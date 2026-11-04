#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for the Kudu code the fuzz targets cover. Runs the dynamically
# linked, unsanitized /mayhem/kat_probe (built by mayhem/build.sh) and compares each line of its stdout
# with the answers below (taken from Kudu's own numbers/escaping/url-coding/coding/rle unit tests).
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


PROBE="$SRC/kat_probe"
[ -x "$PROBE" ] || { echo "missing $PROBE (mayhem/build.sh should have built it)" >&2; emit_ctrf kat-probe 0 1; exit 1; }

EXPECTED='strto32 1 -12345
strtou64 1 18446744073709551615
strto64_overflow 0
itoa_commas 1,234,567
itoa -9007199254740993
cescape a\n\t\"b\\\001
cunescape 610a4141
urlencode hello%20world%26a%3Db%2Fc
urldecode 1 hello world&a=b c
urldecode_hive 1 a+b+
base64 aGVsbG8sIGt1ZHU=
base64dec 1 hello, kudu
html &lt;a href="x"&gt;&amp;&lt;/a&gt;
varint ac02808080808020
varint_dec 1 300 1 1099511627776 0
memcmpable f3f8
groupvarint 1b01000100000100000001
version 1 3.1.2-SNAPSHOT
version_bad 0
json 1 1 42 kudu
json_bad 0
rle 10010388c6fa
rle_dec 1111111101234567'

ACTUAL="$("$PROBE" 2>/dev/null)" || true
passed=0 failed=0
while IFS= read -r want; do
  if printf '%s\n' "$ACTUAL" | grep -qxF -- "$want"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1)); echo "FAIL: expected line: $want" >&2
  fi
done <<< "$EXPECTED"
[ "$passed" -gt 0 ] || { echo "kat_probe produced no matching output" >&2; }

emit_ctrf kat-probe "$passed" "$failed" 0
