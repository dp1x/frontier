#!/usr/bin/env bash
# ALIAS-DIFF round-2 matrix for msn-2026-0004 (opaque-TU barrier).
#
# For every program (round-1 asm + round-2 opaque-tu variants), compile
# under six configs (gcc-O0/O2/O3, clang-O0/O2/O3) and sha256 the stdout.
# The gcc -O0 baseline defines the expected sha; any non-equal sha
# (or non-equal exit code) is DIVERGENT.
#
# The opaque-tu programs are linked with opaque_tu.c, which provides
# opaque_ext() and touch_ext() in a separately-compiled translation unit.
# Without LTO, the caller's optimizer cannot see through these calls,
# forcing it to assume the function may modify any pointer-aliased
# storage.  This is the round-2 design per exp-2026-0015.
#
# Report rows: family|variant|barrier|config|exit|sha256|verdict
# Usage: run_matrix_r2.sh [REPORT_TSV]   (default: <script dir>/alias_report_r2.tsv)
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT="${1:-$SCRIPT_DIR/alias_report_r2.tsv}"
GEN_DIR="$SCRIPT_DIR/generated"
OPAQUE_TU_SRC="$SCRIPT_DIR/opaque_tu.c"

if ! command -v gcc >/dev/null 2>&1; then echo "FATAL|gcc unavailable"; exit 1; fi
# clang is optional: if missing, skip the clang configs and continue.
HAS_CLANG=0
if command -v clang >/dev/null 2>&1; then HAS_CLANG=1; fi

# Generate round-1 programs (asm barrier) and round-2 programs (opaque-tu).
python "$SCRIPT_DIR/gen_programs.py" "$GEN_DIR" || exit 1
python "$SCRIPT_DIR/gen_programs_r2.py" "$GEN_DIR" || exit 1

# Build the opaque_tu.c helper once.
OPAQUE_TU_OBJ="$(mktemp -d)/opaque_tu.o"
gcc -O2 -c -o "$OPAQUE_TU_OBJ" "$OPAQUE_TU_SRC"

if [ "$HAS_CLANG" -eq 1 ]; then
  CFG_IDS=(gcc-O0 gcc-O2 gcc-O3 clang-O0 clang-O2 clang-O3)
  CCS=(gcc gcc gcc clang clang clang)
  # -ffp-contract=off everywhere so FMA contraction cannot fake divergences.
  FLAGS=("-std=c11 -O0 -ffp-contract=off"
         "-std=c11 -O2 -ffp-contract=off"
         "-std=c11 -O3 -ffp-contract=off"
         "-std=c11 -O0 -ffp-contract=off"
         "-std=c11 -O2 -ffp-contract=off"
         "-std=c11 -O3 -ffp-contract=off")
else
  CFG_IDS=(gcc-O0 gcc-O2 gcc-O3)
  CCS=(gcc gcc gcc)
  FLAGS=("-std=c11 -O0 -ffp-contract=off"
         "-std=c11 -O2 -ffp-contract=off"
         "-std=c11 -O3 -ffp-contract=off")
fi

TMPBIN="$(mktemp -d)"
trap 'rm -rf "$TMPBIN"' EXIT

: > "$REPORT"
{
  echo "META|tool=gcc|version=$(gcc --version | head -1)"
  if [ "$HAS_CLANG" -eq 1 ]; then
    echo "META|tool=clang|version=$(clang --version | head -1)"
  else
    echo "META|tool=clang|version=unavailable"
  fi
  echo "META|host=$(uname -sr)|run=${GITHUB_RUN_ID:-local}"
  echo "META|round=2|barriers=asm,opaque-tu|families=d,ctl"
} >> "$REPORT"

total_rows=0
cferr=0

# Iterate over (barrier, source-dir) pairs.
# asm barrier:    all 5 families, src is GEN_DIR/<fam>-<var>.c
# opaque-tu barrier: only d and ctl, src is GEN_DIR/opaque-tu/<fam>-<var>.c
run_matrix() {
  local barrier="$1"
  local src_dir="$2"
  local families="$3"
  for FAM in $families; do
    for SRC in "$src_dir"/${FAM}-*.c; do
      [ -e "$SRC" ] || continue
      NAME="$(basename "$SRC" .c)"
      VAR="${NAME##*-}"
      base_sha=""
      base_exit=""
      ncfg="${#CFG_IDS[@]}"
      for ((ci=0; ci<ncfg; ci++)); do
        cfg="${CFG_IDS[$ci]}"
        BIN="$TMPBIN/${NAME}_${barrier}_${cfg}"
        if [ "$barrier" = "opaque-tu" ]; then
          if ! ${CCS[$ci]} ${FLAGS[$ci]} -I "$SCRIPT_DIR" -o "$BIN" "$SRC" "$OPAQUE_TU_OBJ" >"$TMPBIN/cc.log" 2>&1; then
            echo "$FAM|$VAR|$barrier|$cfg|CFERR|-|CFERR" >> "$REPORT"
            { echo "--- compile failure $NAME/$barrier/$cfg ---"; head -15 "$TMPBIN/cc.log"; } >&2
            cferr=$((cferr + 1))
            continue
          fi
        else
          if ! ${CCS[$ci]} ${FLAGS[$ci]} -o "$BIN" "$SRC" >"$TMPBIN/cc.log" 2>&1; then
            echo "$FAM|$VAR|$barrier|$cfg|CFERR|-|CFERR" >> "$REPORT"
            { echo "--- compile failure $NAME/$barrier/$cfg ---"; head -15 "$TMPBIN/cc.log"; } >&2
            cferr=$((cferr + 1))
            continue
          fi
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
        echo "$FAM|$VAR|$barrier|$cfg|$ec|$sha|$verdict" >> "$REPORT"
        total_rows=$((total_rows + 1))
      done
    done
  done
}

# asm barrier: all 5 families (same as round-1)
run_matrix "asm" "$GEN_DIR" "a b c d ctl"
# opaque-tu barrier: d + ctl only
run_matrix "opaque-tu" "$GEN_DIR/opaque-tu" "d ctl"

SUMF="$TMPBIN/summary.txt"
{
  echo "SUMMARY|rows=$total_rows|cferr=$cferr"
  awk -F'|' 'BEGIN{OFS="|"} NF == 7 && $7 == "DIVERGENT" {d[$3]++} NF == 7 {r[$3]++}
      END {
        for (b in r) printf "BYBARRIER|barrier=%s|rows=%d|divergent=%d\n", b, r[b], d[b] + 0
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
