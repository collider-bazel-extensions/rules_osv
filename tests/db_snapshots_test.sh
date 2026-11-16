#!/usr/bin/env bash
# private/db_snapshots.bzl: every pin is a 64-hex sha256 and a positive
# size, DEFAULT_DB_DATE is pinned, and it covers at least Go, npm, PyPI,
# crates.io and Maven. No network.
set -euo pipefail
python3 -I - "${TEST_SRCDIR}/_main/private/db_snapshots.bzl" <<'PY'
import ast, re, sys
text = open(sys.argv[1]).read()
default = re.search(r'^DEFAULT_DB_DATE = "([^"]*)"$', text, re.M).group(1)
snaps = ast.literal_eval(re.search(r"^DB_SNAPSHOTS = (\{.*?^\})$", text, re.M | re.S).group(1))
errs = []
for date, ecos in snaps.items():
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        errs.append("bad date %r" % date)
    for eco, pin in ecos.items():
        if not re.fullmatch(r"[0-9a-f]{64}", pin.get("sha256", "")):
            errs.append("%s %s: sha256 %r" % (date, eco, pin.get("sha256")))
        if not isinstance(pin.get("size"), int) or pin["size"] <= 0:
            errs.append("%s %s: size %r" % (date, eco, pin.get("size")))
if default not in snaps:
    errs.append("DEFAULT_DB_DATE %s is not in DB_SNAPSHOTS" % default)
else:
    missing = {"Go", "npm", "PyPI", "crates.io", "Maven"} - set(snaps[default])
    if missing:
        errs.append("snapshot %s lacks %s" % (default, ", ".join(sorted(missing))))
    for eco in sorted(snaps[default], key=str.lower):
        print("%s %-10s %11d bytes  %s" % (default, eco, snaps[default][eco]["size"], snaps[default][eco]["sha256"]))
if errs:
    sys.exit("FAIL: " + "; ".join(errs) + " (tools/snapshot_db.sh)")
print("PASS: %d snapshot(s), default %s" % (len(snaps), default))
PY
