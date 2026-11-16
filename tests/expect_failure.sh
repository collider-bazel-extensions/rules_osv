#!/usr/bin/env bash
# Runs a test target that must fail, and checks its exit code and output.
# Argv: <test executable (rootpath)> <exit code> <fixed string>...
set -uo pipefail
target="$1" want_rc="$2"; shift 2
# The inner test must not write the outer test's reports.
out=$(env -u XML_OUTPUT_FILE -u TEST_UNDECLARED_OUTPUTS_DIR "$TEST_SRCDIR/_main/$target" 2>&1)
rc=$?
echo "$out"
echo "---- exit $rc"
status=0
if [[ "$rc" != "$want_rc" ]]; then echo "FAIL: exit $rc, want $want_rc" >&2; status=1; fi
for s in "$@"; do
    if grep -qF -- "$s" <<<"$out"; then echo "ok: $s"; else echo "FAIL: not in the output: $s" >&2; status=1; fi
done
[[ $status == 0 ]] && echo PASS
exit $status
