#!/usr/bin/env bash
# Runs one headless Claude Code scenario against the hook and prints the evidence:
# Claude Code's own permission denials, the final message, and the hook's audit decisions.
# Usage: run.sh <scenario-dir> <bypass|default> <max-turns> <prompt>
# Requires: a `claude` CLI that can authenticate. IS_SANDBOX=1 lets the root user in a
# container use --dangerously-skip-permissions; HOME is pointed at the fake home so `~`
# resolves to canary files only.
set -uo pipefail
root="$1"; mode="$2"; turns="$3"; prompt="$4"
cd "$root/project"
rm -f .nomos/claude-code-hook.jsonl
args=(-p "$prompt" --output-format json --max-turns "$turns")
if [[ "$mode" == "bypass" ]]; then args+=(--dangerously-skip-permissions); fi
export HOME="$root/home" IS_SANDBOX=1
timeout 600 claude "${args[@]}" > "$root/result.json" 2> "$root/stderr.txt"
echo "exit=$?"
printf '%s' "$prompt" > "$root/prompt.txt"
printf '%s' "$mode" > "$root/mode.txt"
python3 "$(dirname "$0")/summarize.py" "$root"
