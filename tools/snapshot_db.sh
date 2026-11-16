#!/usr/bin/env bash
# Maintainer-time script: snapshot today's OSV database zips and pin them in
# private/db_snapshots.bzl, for upload as assets of a rules_osv release.
#
#   tools/snapshot_db.sh [--out DIR] [--date YYYY-MM-DD] [ecosystem ...]
#
# Downloads https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip
# for each ecosystem (default: DEFAULT_ECOSYSTEMS below) into
# DIR/db-<date>/<eco>-all.zip (DIR defaults to ../osv-db-snapshot, next to
# this checkout), checks each is a complete zip of OSV JSON records, and
# writes the date, sha256 and size of every zip into private/db_snapshots.bzl
# (older snapshots there are kept) and makes it the default. It then prints
# the `gh release create` command that publishes the zips as release assets
# under the tag db-<date>; nothing is uploaded by this script.
#
# The upstream URLs are mutable (rebuilt daily), so the pins only hold for
# the copies uploaded to the release. --date only names the snapshot; the
# content is always what upstream serves now.
set -euo pipefail

cd "$(dirname "$0")/.."
for tool in curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "snapshot_db: needs $tool" >&2; exit 1; }
done

DEFAULT_ECOSYSTEMS=(crates.io Go Maven npm NuGet Packagist PyPI RubyGems)
REPO="collider-bazel-extensions/rules_osv"
UPSTREAM="https://osv-vulnerabilities.storage.googleapis.com"

out="$(cd .. && pwd)/osv-db-snapshot"
date="$(date -u +%F)"
ecos=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) out="$2"; shift 2 ;;
        --date) date="$2"; shift 2 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        -*) echo "snapshot_db: unknown flag $1" >&2; exit 1 ;;
        *) ecos+=("$1"); shift ;;
    esac
done
[[ ${#ecos[@]} -gt 0 ]] || ecos=("${DEFAULT_ECOSYSTEMS[@]}")
[[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "snapshot_db: --date must be YYYY-MM-DD" >&2; exit 1; }
for eco in "${ecos[@]}"; do
    [[ "$eco" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
        echo "snapshot_db: unsupported ecosystem name '$eco' (letters, digits, . _ - only)" >&2; exit 1; }
done

tag="db-$date"
dir="$out/$tag"
mkdir -p "$dir"
pins="$(mktemp)"
trap 'rm -f -- "$pins"' EXIT

for eco in "${ecos[@]}"; do
    asset="$eco-all.zip"
    echo "snapshot_db: $eco <- $UPSTREAM/$eco/all.zip" >&2
    curl -fsSL --retry 3 -o "$dir/$asset.part" "$UPSTREAM/$eco/all.zip"
    mv "$dir/$asset.part" "$dir/$asset"
    # A complete zip whose members are OSV records (CRCs checked), hashed.
    python3 -I - "$dir/$asset" "$eco" >> "$pins" <<'PY'
import hashlib, json, os, sys, zipfile
path, eco = sys.argv[1:]
with zipfile.ZipFile(path) as z:
    bad = z.testzip()
    if bad:
        sys.exit(f"snapshot_db: {path}: corrupt member {bad}")
    names = [n for n in z.namelist() if n.endswith(".json")]
    if not names:
        sys.exit(f"snapshot_db: {path}: no .json records")
    rec = json.loads(z.read(names[0]))
    if "id" not in rec or "affected" not in rec and "withdrawn" not in rec:
        sys.exit(f"snapshot_db: {path}: {names[0]} is not an OSV record")
h = hashlib.sha256()
with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(eco, h.hexdigest(), os.path.getsize(path), len(names))
PY
done

python3 -I - private/db_snapshots.bzl "$date" "$pins" <<'PY'
import ast, re, sys
path, date, pins = sys.argv[1:]
text = open(path).read()
m = re.search(r"^DB_SNAPSHOTS = (\{.*?^\})$", text, re.M | re.S)
snaps = ast.literal_eval(m.group(1)) if m else {}
snaps[date] = {}
for line in open(pins):
    eco, sha, size, records = line.split()
    snaps[date][eco] = {"sha256": sha, "size": int(size)}
body = "DB_SNAPSHOTS = {\n"
for d in sorted(snaps, reverse=True):
    body += f'    "{d}": {{\n'
    for eco in sorted(snaps[d], key=str.lower):
        p = snaps[d][eco]
        body += f'        "{eco}": {{"sha256": "{p["sha256"]}", "size": {p["size"]}}},\n'
    body += "    },\n"
body += "}"
if m:
    text = text[:m.start()] + body + text[m.end():]
else:
    sys.exit(f"{path}: no DB_SNAPSHOTS dict")
text = re.sub(r'^DEFAULT_DB_DATE = ".*"$', f'DEFAULT_DB_DATE = "{date}"', text, flags=re.M)
open(path, "w").write(text)
PY

total=0
echo
echo "Snapshot $tag in $dir:"
while read -r eco sha size records; do
    printf '  %-12s %11s bytes  %6s records  sha256 %s\n' "$eco" "$size" "$records" "$sha"
    total=$((total + size))
done < "$pins"
echo "  total $total bytes"
echo
echo "Pinned in private/db_snapshots.bzl (DEFAULT_DB_DATE = \"$date\")."
echo "Publish the zips as release assets (needs gh auth with write access to $REPO):"
echo
files=""
for eco in "${ecos[@]}"; do files+=" \\
    $dir/$eco-all.zip"; done
cat <<CMD
gh release create $tag --repo $REPO \\
    --title "OSV database snapshot $date" \\
    --notes "OSV database zips from $UPSTREAM/<ecosystem>/all.zip, downloaded $date, pinned by rules_osv (private/db_snapshots.bzl). Not a code release." \\
    --latest=false$files
CMD
