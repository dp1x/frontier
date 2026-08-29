#!/usr/bin/env bash
# ALIAS-DIFF execution matrix for msn-2026-0004 (strict-aliasing / effective type).
#
# For every generated program: compile under seven configs
#   gcc-O0  gcc-O2  gcc-O3  gcc-O2-nostrict  clang-O2  clang-O3  clang-O2-nostrict
# run each binary with timeout 10s, sha256 its stdout, and classify against the
# gcc -O0 baseline for the same program:
#   BASELINE   first config (gcc -O0), defines expected exit|sha
#   OK         identical exit code and stdout hash to baseline
#   DIVERGENT  exit or stdout hash differs from baseline
#   CFERR      configuration failed to compile (infrastructure defect)
#
# Report rows: family|variant|config|exit|sha256|verdict
# Usage: run_matrix.sh [REPORT_TSV]   (default: <script dir>/alias_report.tsv)
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT="${1:-$SCRIPT_DIR/alias_report.tsv}"
GEN_DIR="$SCRIPT_DIR/generated"

if ! command -v gcc >/dev/null 2>&1; then sudo apt-get update -qq && sudo apt-get install -y -qq gcc; fi
if ! command -v clang >/dev/null 2>&1; then sudo apt-get update -qq && sudo apt-get install -y -qq clang; fi
command -v gcc >/dev/null 2>&1 || { echo "FATAL|gcc unavailable"; exit 1; }
command -v clang >/dev/null 2>&1 || { echo "FATAL|clang unavailable"; exit 1; }

python "$SCRIPT_DIR/gen_programs.py" "$GEN_DIR" || exit 1

CFG_IDS=(gcc-O0 gcc-O2 gcc-O3 gcc-O2-nostrict clang-O2 clang-O3 clang-O2-nostrict)
CCS=(gcc gcc gcc gcc clang clang clang)
# -ffp-contract=off everywhere so FMA contraction cannot fake divergences.
FLAGS=("-std=c11 -O0 -ffp-contract=off"
       "-std=c11 -O2 -ffp-contract=off"
       "-std=c11 -O3 -ffp-contract=off"
       "-std=c11 -O2 -fno-strict-aliasing -ffp-contract=off"
       "-std=c11 -O2 -ffp-contract=off"
       "-std=c11 -O3 -ffp-contract=off"
       "-std=c11 -O2 -fno-strict-aliasing -ffp-contract=off")

TMPBIN="$(mktemp -d)"
trap 'rm -rf "$TMPBIN"' EXIT

: > "$REPORT"
{
  echo "META|tool=gcc|version=$(gcc --version | head -1)"
  echo "META|tool=clang|version=$(clang --version | head -1)"
  echo "META|host=$(uname -sr)|run=${GITHUB_RUN_ID:-local}"
} >> "$REPORT"

total_rows=0
cferr=0

for SRC in "$GEN_DIR"/*.c; do
  NAME="$(basename "$SRC" .c)"
  FAM="${NAME%%-*}"
  VAR="${NAME##*-}"
  base_sha=""
  base_exit=""
  for ci in 0 1 2 3 4 5 6; do
    cfg="${CFG_IDS[$ci]}"
    BIN="$TMPBIN/${NAME}_${cfg}"
    if ! ${CCS[$ci]} ${FLAGS[$ci]} -o "$BIN" "$SRC" >"$TMPBIN/cc.log" 2>&1; then
      echo "$FAM|$VAR|$cfg|CFERR|-|CFERR" >> "$REPORT"
      { echo "--- compile failure $NAME/$cfg ---"; head -15 "$TMPBIN/cc.log"; } >&2
      cferr=$((cferr + 1))
      continue
    fi
    timeout 10s "$BIN" > "$TMPBIN/out.txt" 2>/dev/null
    ec=$?
    sha="$(sha256sum "$TMPBIN/out.txt" | cut -d' ' -f1)"
    if [ -z "$base_sha" ]; then
      verdict="BASELINE"
      base_sha="$sha"
      base_exit="$ec"
    elif [ "$sha" = "$base_sha" ] && [ "$ec" = "$base_exit" ]; then
      verdict="OK"
    else
      verdict="DIVERGENT"
    fi
    echo "$FAM|$VAR|$cfg|$ec|$sha|$verdict" >> "$REPORT"
    total_rows=$((total_rows + 1))
  done
done

SUMF="$TMPBIN/summary.txt"
{
  echo "SUMMARY|rows=$total_rows|cferr=$cferr"
  awk -F'|' '$6 == "BASELINE" || $6 == "OK" || $6 == "DIVERGENT" {
        r[$1]++
        if ($6 == "DIVERGENT") d[$1]++
      }
      END {
        for (f in r) printf "BYFAMILY|family=%s|rows=%d|divergent=%d\n", f, r[f], d[f] + 0
      }' "$REPORT" | sort
} > "$SUMF"
cat "$SUMF" >> "$REPORT"

echo "--- report tail ---"
tail -8 "$REPORT"
echo "--- divergent rows ---"
grep '|DIVERGENT$' "$REPORT" || echo "(none)"

if [ "$cferr" -ne 0 ]; then
  echo "FATAL|$cferr compile failure(s); matrix incomplete" >&2
  exit 1
fi
exit 0
