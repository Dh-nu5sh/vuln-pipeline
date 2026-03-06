#!/usr/bin/env bash
# run_all.sh — run scanner/run_scan.py for every non-empty line in targets.txt
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGETS_FILE="$ROOT_DIR/targets.txt"
LOG_DIR="$ROOT_DIR/logs"
mkdir -p "$LOG_DIR"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "Error: $TARGETS_FILE not found. Create targets.txt in the repo root with one URL per line."
  exit 1
fi

echo "Starting run_all.sh — reading targets from $TARGETS_FILE"

while IFS= read -r target || [ -n "$target" ]; do
  # skip blank lines and lines starting with #
  trimmed="$(echo "$target" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  if [ -z "$trimmed" ] || [[ "$trimmed" =~ ^# ]]; then
    continue
  fi

  echo "=== Scanning: $trimmed ==="
  timestamp="$(date +%Y%m%d-%H%M%S)"
  # log per-target
  logfile="$LOG_DIR/scan-$(echo "$trimmed" | sed 's/[^a-zA-Z0-9]/_/g')-$timestamp.log"

  # Run the Python orchestrator (adjust path if you put run_scan.py elsewhere)
  # Redirect stdout+stderr to the log file so you can inspect later.
  python3 "$ROOT_DIR/scanner/run_scan.py" "$trimmed" >> "$logfile" 2>&1 || {
    echo "Scan for $trimmed failed — check $logfile"
    continue
  }

  echo "Finished: $trimmed (log: $logfile)"
done < "$TARGETS_FILE"

echo "All targets processed."
