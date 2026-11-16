#!/usr/bin/env bash
# Consumer checks against the commit's release archive (git archive honours
# .gitattributes export-ignore, as GitHub's tag tarballs do):
#   1. tests/ and tools/ are not shipped, @rules_osv//... loads, and a root
#      without osv.version()/osv.db() gets the pinned osv-scanner and snapshot
#   2. an unsupported osv-scanner version, and an unpinned snapshot date,
#      fail naming the tag to pin them with
#   3. a snapshot pinned in osv.db() itself, from a mirror (here a file://
#      zip of real OSV records): a vulnerable go.mod fails naming the finding
#      and the snapshot date, a fixed one passes, an ignore file covers the
#      finding; an ecosystem the tests don't use is never fetched (its
#      "mirror" doesn't exist)
#   4. an osv-scanner version not in private/versions.bzl, pinned in
#      osv.version() itself: the test runs that version
# None of it needs the db-<date> release assets.
# Usage: .github/consumer/check.sh <scratch dir>
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="$1"
src="$work/rules_osv"
rm -rf "$work"; mkdir -p "$src"
git -C "$repo" archive HEAD | tar -x -C "$src"
for d in tests tools; do
    if [[ -e "$src/$d" ]]; then echo "FAIL: archive contains $d/" >&2; exit 1; fi
done
version="$(sed -n 's/^DEFAULT_VERSION = "\(.*\)"/\1/p' "$src/private/versions.bzl")"
date="$(sed -n 's/^DEFAULT_DB_DATE = "\(.*\)"/\1/p' "$src/private/db_snapshots.bzl")"

consumer() { # <name> <extra MODULE.bazel lines>
    local c="$work/$1"
    mkdir -p "$c"
    if [[ -f "$repo/.bazelversion" ]]; then cp "$repo/.bazelversion" "$c/"; fi
    cat > "$c/MODULE.bazel" <<MOD
module(name = "consumer")
bazel_dep(name = "rules_osv")
local_path_override(module_name = "rules_osv", path = "$src")
$2
MOD
    touch "$c/BUILD.bazel"
    echo "$c"
}

# 1. No tags: resolves to the pinned binary and snapshot; //... loads.
c="$(consumer untagged "")"
(cd "$c" && bazel query @rules_osv//... >/dev/null)
echo "PASS: @rules_osv//... loads from the archive ($(cd "$c" && bazel query @rules_osv//... 2>/dev/null | wc -l) targets)"
(cd "$c" && bazel mod show_extension @rules_osv//:extensions.bzl%osv) > "$work/untagged.out"
grep -q "osv_db" "$work/untagged.out" && grep -q "osv_scanner_linux_amd64" "$work/untagged.out" || {
    cat "$work/untagged.out" >&2; echo "FAIL: untagged consumer: osv_db / osv_scanner_* not generated" >&2; exit 1; }
echo "PASS: untagged root resolves (osv-scanner $version, snapshot $date)"

# 2. Unsupported pins fail clearly.
expect_mod_fail() { # <name> <MODULE lines> <message>
    local c
    c="$(consumer "$1" "$2")"
    if (cd "$c" && bazel build @osv_db//... @osv_scanner_linux_amd64//...) > "$work/$1.out" 2>&1; then
        echo "FAIL: $1 resolved" >&2; exit 1
    fi
    grep -qF "$3" "$work/$1.out" || { cat "$work/$1.out" >&2; echo "FAIL: $1: wrong error" >&2; exit 1; }
    echo "PASS: $1 fails clearly"
}
expect_mod_fail bad_version 'osv = use_extension("@rules_osv//:extensions.bzl", "osv")
osv.version(version = "0.0.1")
use_repo(osv, "osv_db", "osv_scanner_linux_amd64")' 'osv.version(version = "0.0.1") is not supported'
expect_mod_fail bad_date 'osv = use_extension("@rules_osv//:extensions.bzl", "osv")
osv.db(date = "2000-01-01")
use_repo(osv, "osv_db", "osv_scanner_linux_amd64")' 'osv.db(name = "osv_db", date = "2000-01-01") is not a pinned snapshot'

# 3. A self-pinned snapshot from a mirror.
mirror="$work/mirror_zips"
mkdir -p "$mirror"
python3 -I - "$mirror/Go-all.zip" "$repo"/tests/testdata/db/Go/*.json <<'PY'
import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    for p in sys.argv[2:]:
        z.write(p, os.path.basename(p))
PY
go_sha="$(sha256sum "$mirror/Go-all.zip" | cut -d' ' -f1)"
c="$(consumer mirror "osv = use_extension(\"@rules_osv//:extensions.bzl\", \"osv\")
osv.db(
    date = \"2026-01-02\",
    url = \"file://$mirror/{ecosystem}-all.zip\",
    sha256 = {
        \"Go\": \"$go_sha\",
        \"npm\": \"$(printf '0%.0s' {1..64})\",  # no such zip: must never be fetched
    },
)
use_repo(osv, \"osv_db\")")"
mkdir -p "$c/vulnerable" "$c/clean"
printf 'module example.com/c\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.5.0\n' > "$c/vulnerable/go.mod"
printf 'module example.com/c\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.1\n' > "$c/clean/go.mod"
cat > "$c/osv-scanner.toml" <<'TOML'
[[IgnoredVulns]]
id = "CVE-2020-36567"   # an alias of GO-2020-0001
effectiveUntil = 2099-01-01
reason = "Consumer check: accepted."
TOML
cat > "$c/BUILD.bazel" <<'BUILD'
load("@rules_osv//:defs.bzl", "osv_scan_test")

osv_scan_test(name = "clean_test", db = ["@osv_db//:Go"], lockfiles = ["clean/go.mod"])

osv_scan_test(name = "vulnerable_test", db = ["@osv_db//:Go"], lockfiles = ["vulnerable/go.mod"])

osv_scan_test(
    name = "ignored_test",
    db = ["@osv_db//:Go"],
    ignore = "osv-scanner.toml",
    lockfiles = ["vulnerable/go.mod"],
)
BUILD
(cd "$c" && bazel test //:clean_test //:ignored_test --test_output=errors)
if (cd "$c" && bazel test //:vulnerable_test --test_output=all) > "$work/vulnerable.out" 2>&1; then
    echo "FAIL: vulnerable_test passed" >&2; exit 1
fi
for s in "OSV database snapshot 2026-01-02: Go (sha256 ${go_sha:0:12})" \
         "vulnerable/go.mod  Go github.com/gin-gonic/gin@1.5.0  GO-2020-0001"; do
    grep -qF "$s" "$work/vulnerable.out" || { cat "$work/vulnerable.out" >&2; echo "FAIL: not in the output: $s" >&2; exit 1; }
done
ext="$(cd "$c" && bazel info output_base)/external"
[[ -f "$ext/rules_osv++osv+osv_db_Go/all.zip" ]] || { ls "$ext" >&2; echo "FAIL: no Go database repo at $ext/rules_osv++osv+osv_db_Go" >&2; exit 1; }
for r in osv_db_npm osv_scanner_darwin_amd64 osv_scanner_darwin_arm64 osv_scanner_linux_arm64; do
    if [[ -e "$ext/rules_osv++osv+$r" ]]; then echo "FAIL: $r was fetched, but nothing uses it" >&2; exit 1; fi
done
echo "PASS: mirrored snapshot: vulnerable fails (GO-2020-0001, snapshot 2026-01-02), clean and ignored pass; npm and other platforms' binaries never fetched"

# 4. A self-pinned osv-scanner (2.7.0 is not in private/versions.bzl).
c="$(consumer pinned_version "osv = use_extension(\"@rules_osv//:extensions.bzl\", \"osv\")
osv.version(
    version = \"2.7.0\",
    sha256 = {\"linux_amd64\": \"160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b\"},
)
osv.db(date = \"2026-01-02\", url = \"file://$mirror/{ecosystem}-all.zip\", sha256 = {\"Go\": \"$go_sha\"})
use_repo(osv, \"osv_db\")")"
mkdir -p "$c/clean"
printf 'module example.com/c\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.1\n' > "$c/clean/go.mod"
cat > "$c/BUILD.bazel" <<'BUILD'
load("@rules_osv//:defs.bzl", "osv_scan_test")

osv_scan_test(name = "clean_test", db = ["@osv_db//:Go"], lockfiles = ["clean/go.mod"])
BUILD
(cd "$c" && bazel test //:clean_test --test_output=all) > "$work/pinned_version.out" 2>&1 || {
    cat "$work/pinned_version.out" >&2; echo "FAIL: pinned_version" >&2; exit 1; }
grep -qF "osv-scanner 2.7.0, offline" "$work/pinned_version.out" || {
    cat "$work/pinned_version.out" >&2; echo "FAIL: not osv-scanner 2.7.0" >&2; exit 1; }
echo "PASS: self-pinned osv-scanner 2.7.0 runs"
