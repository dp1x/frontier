#!/bin/bash
# Clang C23 #embed crash characterization matrix
# Run as: bash run_embed_matrix.sh <clang-binary> <output-dir>
#
# Returns: exit 0 if all stimuli complete (some may crash, that is the verdict)
# Writes: <output-dir>/embed_crash_matrix.tsv with per-stimulus verdict

set -u

CLANG="${1:?clang binary required}"
OUTDIR="${2:?output dir required}"

mkdir -p "$OUTDIR"
TSV="$OUTDIR/embed_crash_matrix.tsv"
LOG="$OUTDIR/embed_crash_console.log"
: > "$TSV"
: > "$LOG"

echo -e "stimulus_id\texit_code\telapsed_ms\tstderr_first_120\ttype\tverdict" | tee -a "$TSV"

run_stimulus() {
    local id="$1"
    local file="$2"
    local type="$3"
    local start_ms=$(date +%s%3N)
    local stderr_file="$OUTDIR/${id}_stderr.log"
    local exit_file="$OUTDIR/${id}_exit.txt"

    if [ ! -f "$file" ]; then
        echo "MISSING_INPUT: $file" >&2
        echo -e "$id\t-1\t0\tMISSING INPUT\t$type\tinput_missing" | tee -a "$TSV"
        return
    fi

    # Memory limit to 2 GB to bound the OOM reproducer
    ulimit -v 2097152 2>/dev/null || true

    timeout 30 "$CLANG" -std=c23 -c "$file" -o /tmp/${id}.o 2> "$stderr_file" > /dev/null
    local rc=$?
    local end_ms=$(date +%s%3N)
    local elapsed=$((end_ms - start_ms))
    echo "$rc" > "$exit_file"

    local first_120
    first_120=$(head -c 200 "$stderr_file" | tr '\n' ' ' | tr '\t' ' ')
    local verdict="unknown"
    if [ "$rc" -eq 0 ]; then
        verdict="compiles_cleanly"
    elif [ "$rc" -eq 124 ]; then
        verdict="hangs_timeout"
    elif [ "$rc" -eq 139 ]; then
        verdict="crashes_segv"
    elif [ "$rc" -eq 134 ]; then
        if grep -q "Assertion" "$stderr_file"; then
            verdict="crashes_assertion"
        elif grep -q "out of memory" "$stderr_file"; then
            verdict="crashes_oom"
        elif grep -q "fatal error" "$stderr_file"; then
            verdict="crashes_fatal"
        else
            verdict="crashes_abort_other"
        fi
    else
        if grep -q "error:" "$stderr_file"; then
            verdict="rejects_with_error"
        else
            verdict="exits_other"
        fi
    fi

    echo -e "$id\t$rc\t$elapsed\t$first_120\t$type\t$verdict" | tee -a "$TSV"
    echo "[$id] rc=$rc elapsed=${elapsed}ms verdict=$verdict" >> "$LOG"
}

echo "Running matrix with $(basename $CLANG)..." | tee -a "$LOG"

# Control
cat > /tmp/ctrl_canary.c <<'EOF'
const unsigned char data[] = {
#include "/etc/hostname"
};
int main(void) { return sizeof(data); }
EOF
# Use the legacy #include as a control since basic #embed requires an actual file
# The real ctrl is a basic #embed of /etc/hostname
cat > /tmp/ctrl_canary_embed.c <<'EOF'
const unsigned char data[] = {
#embed "/etc/hostname"
};
int main(void) { return sizeof(data); }
EOF
run_stimulus "ctrl_canary" "/tmp/ctrl_canary_embed.c" "control"

# Issue #212075 reproducer
cat > /tmp/iss212075_min.c <<'EOF'
#embed <foo> limit(defined(bar)),
EOF
run_stimulus "iss212075_min" "/tmp/iss212075_min.c" "known_bug_repro"

# Issue #219332 reproducer
cat > /tmp/iss219332_min.c <<'EOF'
char a[] = {
#embed
};

char b[] = {
#embed __FILE__ prefix([sizeof(a) - 1])
};
EOF
run_stimulus "iss219332_min" "/tmp/iss219332_min.c" "known_bug_repro"

# Characterization matrix
cat > /tmp/char_limit_0.c <<'EOF'
const unsigned char data[] = {
#embed "/etc/hostname" limit(0)
};
EOF
run_stimulus "char_limit_0" "/tmp/char_limit_0.c" "char_variant"

cat > /tmp/char_limit_1.c <<'EOF'
const unsigned char data[] = {
#embed "/etc/hostname" limit(1)
};
EOF
run_stimulus "char_limit_1" "/tmp/char_limit_1.c" "char_variant"

cat > /tmp/char_limit_1000.c <<'EOF'
const unsigned char data[] = {
#embed "/etc/hostname" limit(1000)
};
EOF
run_stimulus "char_limit_1000" "/tmp/char_limit_1000.c" "char_variant"

cat > /tmp/char_limit_defined.c <<'EOF'
#embed "/etc/hostname" limit(defined(X))
EOF
run_stimulus "char_limit_defined" "/tmp/char_limit_defined.c" "char_variant"

cat > /tmp/char_limit_defined_trailing_comma.c <<'EOF'
#embed "/etc/hostname" limit(defined(X)),
EOF
run_stimulus "char_limit_defined_trailing_comma" "/tmp/char_limit_defined_trailing_comma.c" "char_variant"

cat > /tmp/char_prefix_zero.c <<'EOF'
const unsigned char data[] = {
#embed "/etc/hostname" prefix([0])
};
EOF
run_stimulus "char_prefix_zero" "/tmp/char_prefix_zero.c" "char_variant"

cat > /tmp/char_suffix_zero.c <<'EOF'
const unsigned char data[] = {
#embed "/etc/hostname" suffix([0])
};
EOF
run_stimulus "char_suffix_zero" "/tmp/char_suffix_zero.c" "char_variant"

cat > /tmp/char_if_empty.c <<'EOF'
const unsigned char data[] = {
#embed "/nonexistent/path/should/not/exist" if_empty(0xFF)
};
EOF
run_stimulus "char_if_empty" "/tmp/char_if_empty.c" "char_variant"

cat > /tmp/char_self_file.c <<'EOF'
const unsigned char data[] = {
#embed __FILE__
};
EOF
run_stimulus "char_self_file" "/tmp/char_self_file.c" "char_variant"

cat > /tmp/char_concat_bugs.c <<'EOF'
char a[] = {
#embed "/etc/hostname" limit(defined(X))
};
char b[] = {
#embed __FILE__ prefix([sizeof(a) - 1])
};
EOF
run_stimulus "char_concat_bugs" "/tmp/char_concat_bugs.c" "char_variant"

echo "Matrix complete. Results in $TSV"