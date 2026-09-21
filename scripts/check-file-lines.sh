#!/usr/bin/env bash
# Enforce the repository-wide source file size limit.
#
# Every tracked Rust and Python source file must stay at or below MAX_LINES
# (default 1000). Oversized files are split by module, never truncated.
set -euo pipefail

MAX_LINES="${MAX_LINES:-1000}"
status=0

while IFS= read -r file; do
    lines=$(wc -l <"$file")
    if [ "$lines" -gt "$MAX_LINES" ]; then
        echo "ERROR: $file has $lines lines (limit $MAX_LINES)"
        status=1
    fi
done < <(git ls-files '*.rs' '*.py')

if [ "$status" -eq 0 ]; then
    echo "file-size check passed (limit $MAX_LINES lines)"
fi
exit "$status"
