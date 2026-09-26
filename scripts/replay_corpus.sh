#!/usr/bin/env bash
# Replay testdata/realworld/commands.jsonl through `nomos hook claude-code --simulate`
# for each default profile and summarize how often every profile allows, asks, or denies.
#
# The corpus commands are never executed: the hook only decides. The workspace handed
# to the hook is a fresh temporary directory holding an empty git repository, so path
# checks behave as they would in a real checkout without touching this repository.
#
# Usage:
#   scripts/replay_corpus.sh [--out-dir DIR] [--corpus FILE] [--jobs N] [--profiles "safe-dev ci-strict prod-locked"]
#
# Writes <out-dir>/corpus_nag_report.md and <out-dir>/corpus_decisions.jsonl. The default
# out-dir is .tmp/corpus-replay under the repository, which is gitignored. The nomos binary
# and the temporary workspace live under $NOMOS_CORPUS_DIR (default /tmp/nomos-corpus) and
# are removed when the script exits.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$REPO_ROOT/testdata/realworld/commands.jsonl"
OUT_DIR="$REPO_ROOT/.tmp/corpus-replay"
PROFILES="safe-dev ci-strict prod-locked"
JOBS="$(nproc 2>/dev/null || echo 4)"
WORK_ROOT="${NOMOS_CORPUS_DIR:-/tmp/nomos-corpus}"

usage() {
  cat <<'EOF'
usage: scripts/replay_corpus.sh [--out-dir DIR] [--corpus FILE] [--jobs N] [--profiles "safe-dev ci-strict prod-locked"]

Replays every corpus command through `nomos hook claude-code --simulate` for each profile
and writes <out-dir>/corpus_nag_report.md and <out-dir>/corpus_decisions.jsonl.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --corpus) CORPUS="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --profiles) PROFILES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [ ! -f "$CORPUS" ]; then
  echo "corpus not found: $CORPUS (run python3 scripts/build_command_corpus.py first)" >&2
  exit 1
fi

mkdir -p "$WORK_ROOT" "$OUT_DIR"
NOMOS="$WORK_ROOT/nomos"
WORKSPACE="$(mktemp -d "$WORK_ROOT/workspace.XXXXXX")"
cleanup() {
  rm -rf "$WORKSPACE" "$NOMOS"
  rmdir "$WORK_ROOT" 2>/dev/null || true
}
trap cleanup EXIT

echo "building nomos into $NOMOS" >&2
go build -C "$REPO_ROOT" -o "$NOMOS" ./cmd/nomos
git init -q "$WORKSPACE"
read -r -a PROFILE_LIST <<<"$PROFILES"
echo "replaying $CORPUS with profiles: ${PROFILE_LIST[*]} ($JOBS workers)" >&2

python3 - "$NOMOS" "$WORKSPACE" "$CORPUS" "$OUT_DIR" "$JOBS" "${PROFILE_LIST[@]}" <<'PY'
import collections
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

nomos, workspace, corpus_path, out_dir, jobs, *profiles = sys.argv[1:]
jobs = max(1, int(jobs))

records = []
with open(corpus_path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if line:
            records.append(json.loads(line))
if not records:
    sys.exit("corpus is empty")


def decide(task):
    command, profile = task
    proc = subprocess.run(
        [nomos, "hook", "claude-code", "--simulate", "--profile", profile, "--workspace", workspace,
         "--audit", "none", "--command=" + command],
        cwd=workspace, capture_output=True, text=True)
    decision, reason = "", ""
    for line in proc.stderr.splitlines():
        if line.startswith("decision: "):
            decision = line[len("decision: "):].split(" ", 1)[0].strip()
        elif line.startswith("reason: "):
            reason = line[len("reason: "):].strip()
    if proc.returncode != 0:
        decision, reason = "error", (proc.stderr.strip() or f"exit status {proc.returncode}")
    elif not decision:
        decision, reason = "error", "no decision line on stderr"
    return {"command": command, "profile": profile, "decision": decision, "reason": reason}


tasks = [(record["command"], profile) for profile in profiles for record in records]
started = time.time()
with ThreadPoolExecutor(max_workers=jobs) as pool:
    decisions = list(pool.map(decide, tasks))
elapsed = time.time() - started

with open(f"{out_dir}/corpus_decisions.jsonl", "w", encoding="utf-8") as fh:
    for decision in decisions:
        fh.write(json.dumps(decision, ensure_ascii=False) + "\n")

# --- analysis ------------------------------------------------------------------

LABEL = r"(?:profile \S+|\S+)"
PART_SPLIT = re.compile(
    r";\s(?=cannot safely interpret the command|no " + LABEL + r" rule allows|" + LABEL +
    r" (?:requires confirmation for|denies|allows|returned unknown decision)|path outside the workspace)")
UNSUPPORTED_DETAIL = re.compile(r"^cannot safely interpret the command(?:, asking for confirmation)?: (.*?)(?: near \".*)?$")
OUTSIDE_DETAIL = re.compile(r"^path outside the workspace(?:, asking for confirmation)?: (working directory|argument)\b")
RULES = re.compile(r"\(rules: ([^)]*)\)")
ARGV = re.compile(r" \[.*?\] \(rules: ")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def strip_prefix(reason):
    return reason[len("Nomos: "):] if reason.startswith("Nomos: ") else reason


def parts_of(reason):
    return [part for part in PART_SPLIT.split(strip_prefix(reason)) if part]


def category(part):
    if part.startswith("cannot safely interpret the command"):
        return "unsupported shell syntax"
    if part.startswith("path outside the workspace"):
        return "outside workspace"
    if " requires confirmation for " in part:
        return "approval required"
    if re.match(r"no \S.* rule allows ", part):
        return "no matching rule"
    if " denies " in part:
        return "denied by rule"
    if " allows " in part:
        return "allowed by rule"
    return "other"


def deny_group(reason):
    return ARGV.sub(" [...] (rules: ", strip_prefix(reason))


def program(command):
    tokens = command.split()
    for token in tokens:
        if ASSIGNMENT.match(token):
            continue
        return token.rsplit("/", 1)[-1] or token
    return tokens[0] if tokens else ""


def prefix2(command):
    tokens = [token for token in command.split() if not ASSIGNMENT.match(token)]
    if not tokens:
        return command
    first = tokens[0].rsplit("/", 1)[-1] or tokens[0]
    return first if len(tokens) == 1 else first + " " + tokens[1]


def code(text):
    text = text.replace("\n", " ").replace("|", "\\|")
    return "`` " + text + " ``" if "`" in text else "`" + text + "`"


def pct(count, total):
    return f"{100.0 * count / total:.1f}%" if total else "0.0%"


by_profile = {profile: [d for d in decisions if d["profile"] == profile] for profile in profiles}
repo_of = {record["command"]: record["repo"] for record in records}
total = len(records)
reference = "safe-dev" if "safe-dev" in profiles else profiles[0]

lines = []
w = lines.append
w("# Claude Code hook noise report (real-world command corpus)")
w("")
w(f"- Corpus: `{corpus_path}` with {total} unique commands from {len(set(repo_of.values()))} repositories")
w("- Hook: `nomos hook claude-code --simulate --profile <profile> --workspace <fresh empty git repo> "
  "--audit none --command <cmd>` with the default modes (`--on-default ask`, `--on-unsupported ask`, "
  "`--outside-workspace ask`); nothing is executed")
w(f"- Profiles: {', '.join(profiles)}; {len(decisions)} decisions in {elapsed:.0f}s with {jobs} workers")
w(f"- Raw decisions: `{out_dir}/corpus_decisions.jsonl` (command, profile, decision, reason)")
w("")
w("## Summary")
w("")
w("| Profile | allow | ask | deny | passthrough | error |")
w("| --- | --- | --- | --- | --- | --- |")
for profile in profiles:
    counts = collections.Counter(d["decision"] for d in by_profile[profile])
    w(f"| {profile} | {counts['allow']} ({pct(counts['allow'], total)}) | {counts['ask']} ({pct(counts['ask'], total)}) "
      f"| {counts['deny']} ({pct(counts['deny'], total)}) | {counts['passthrough']} | {counts['error']} |")
w("")
w("`ask` is the hook's prompt: Claude Code shows its normal permission prompt with the Nomos reason. "
  "The reason categories below follow the hook's own wording: *no matching rule* (deny by default, "
  "reported as ask), *unsupported shell syntax* (the parser refuses to guess), *outside workspace* "
  "(a path or working directory resolves outside the workspace root), and *approval required* "
  "(a REQUIRE_APPROVAL rule matched). `passthrough` means Nomos produced no decision (a lone `cd` "
  "inside the workspace maps to no action), so Claude Code's own permission flow applies; `error` "
  "is a non-zero hook exit, which Claude Code treats as a block.")
w("")

for profile in profiles:
    ds = by_profile[profile]
    asks = [d for d in ds if d["decision"] == "ask"]
    denies = [d for d in ds if d["decision"] == "deny"]
    passthroughs = [d for d in ds if d["decision"] == "passthrough"]
    errors = [d for d in ds if d["decision"] not in ("allow", "ask", "deny", "passthrough")]
    w(f"## Profile `{profile}`")
    w("")
    w(f"### Why commands ask ({len(asks)} of {total})")
    w("")
    primary = collections.Counter()
    mentioned = collections.Counter()
    constructs = collections.Counter()
    outside = collections.Counter()
    approval_rules = collections.Counter()
    ask_programs = collections.Counter()
    program_categories = collections.defaultdict(collections.Counter)
    for d in asks:
        parts = parts_of(d["reason"])
        categories = [category(part) for part in parts] or ["other"]
        primary[categories[0]] += 1
        for cat in set(categories):
            mentioned[cat] += 1
        for part, cat in zip(parts, categories):
            if cat == "unsupported shell syntax":
                match = UNSUPPORTED_DETAIL.match(part)
                constructs[match.group(1) if match else part] += 1
            elif cat == "outside workspace":
                match = OUTSIDE_DETAIL.match(part)
                outside[match.group(1) if match else "other"] += 1
            elif cat == "approval required":
                match = RULES.search(part)
                for rule in (match.group(1).split(", ") if match else ["(unknown rule)"]):
                    approval_rules[rule] += 1
        name = program(d["command"])
        ask_programs[name] += 1
        program_categories[name][categories[0]] += 1
    w("| Reason category | commands (first reason) | share of asks | share of corpus | commands mentioning it |")
    w("| --- | --- | --- | --- | --- |")
    for cat, count in primary.most_common():
        w(f"| {cat} | {count} | {pct(count, len(asks))} | {pct(count, total)} | {mentioned[cat]} |")
    w("")
    if constructs:
        w("Unsupported shell constructs (each part of a command counted once):")
        w("")
        w("| Construct | count |")
        w("| --- | --- |")
        for construct, count in constructs.most_common():
            w(f"| {construct} | {count} |")
        w("")
    if outside:
        w("Outside-workspace findings:")
        w("")
        w("| Finding | count |")
        w("| --- | --- |")
        for finding, count in outside.most_common():
            w(f"| {finding} | {count} |")
        w("")
    if approval_rules:
        w("Approval rules that matched:")
        w("")
        w("| Rule | count |")
        w("| --- | --- |")
        for rule, count in approval_rules.most_common():
            w(f"| `{rule}` | {count} |")
        w("")
    w(f"### Top 40 programs that ask under `{profile}`")
    w("")
    w("The program is the first token of the command as written (leading `VAR=value` "
      "assignments skipped, directory prefix removed).")
    w("")
    w("| # | Program | asks | first reason categories |")
    w("| --- | --- | --- | --- |")
    for rank, (name, count) in enumerate(ask_programs.most_common(40), 1):
        cats = ", ".join(f"{cat} {n}" for cat, n in program_categories[name].most_common())
        w(f"| {rank} | {code(name)} | {count} | {cats} |")
    w("")
    w(f"### Deny reasons under `{profile}` ({len(denies)} commands)")
    w("")
    if not denies:
        w("No command was denied.")
        w("")
    groups = collections.defaultdict(list)
    for d in denies:
        groups[deny_group(d["reason"])].append(d["command"])
    for group, commands in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        w(f"#### {len(commands)} x {group}")
        w("")
        for command in sorted(commands):
            w(f"- {code(command)} (from {repo_of.get(command, '?')})")
        w("")
    if passthroughs:
        w(f"### No decision under `{profile}` ({len(passthroughs)} commands)")
        w("")
        w("Nomos withheld its decision, so Claude Code's own permission flow applies:")
        w("")
        for d in sorted(passthroughs, key=lambda item: item["command"]):
            w(f"- {code(d['command'])} (from {repo_of.get(d['command'], '?')})")
        w("")
    if errors:
        w(f"### Hook errors under `{profile}` ({len(errors)} commands)")
        w("")
        for d in errors:
            w(f"- {code(d['command'])}: {d['decision']}: {code(d['reason'][:200])}")
        w("")

decision_under_reference = {d["command"]: d["decision"] for d in by_profile[reference]}
w(f"## Most common commands overall and their decision under `{reference}`")
w("")
w("The corpus is deduplicated, so frequency is measured by program name (first token) and by the "
  "first two tokens of the command.")
w("")
w("### Top 25 programs")
w("")
w("| # | Program | commands | allow | ask | deny | example |")
w("| --- | --- | --- | --- | --- | --- | --- |")
programs = collections.Counter(program(record["command"]) for record in records)
examples = {}
for record in records:
    examples.setdefault(program(record["command"]), record["command"])
for rank, (name, count) in enumerate(programs.most_common(25), 1):
    split = collections.Counter(decision_under_reference.get(record["command"], "?")
                                for record in records if program(record["command"]) == name)
    w(f"| {rank} | {code(name)} | {count} | {split['allow']} | {split['ask']} | {split['deny']} | {code(examples[name])} |")
w("")
w("### Top 25 two-token commands")
w("")
w("| # | Command | commands | decisions | example |")
w("| --- | --- | --- | --- | --- |")
prefixes = collections.Counter(prefix2(record["command"]) for record in records)
prefix_examples = {}
for record in records:
    prefix_examples.setdefault(prefix2(record["command"]), record["command"])
for rank, (prefix, count) in enumerate(prefixes.most_common(25), 1):
    split = collections.Counter(decision_under_reference.get(record["command"], "?")
                                for record in records if prefix2(record["command"]) == prefix)
    summary = ", ".join(f"{decision} {n}" for decision, n in split.most_common())
    w(f"| {rank} | {code(prefix)} | {count} | {summary} | {code(prefix_examples[prefix])} |")
w("")

w("## Per-repository decisions")
w("")
w("| Repository | commands | " + " | ".join(f"{profile} allow / ask / deny" for profile in profiles) + " |")
w("| --- | --- | " + " | ".join("---" for _ in profiles) + " |")
repos = collections.Counter(record["repo"] for record in records)
for repo, count in sorted(repos.items(), key=lambda item: (-item[1], item[0])):
    cells = []
    for profile in profiles:
        split = collections.Counter(d["decision"] for d in by_profile[profile] if repo_of[d["command"]] == repo)
        cells.append(f"{split['allow']} / {split['ask']} / {split['deny']}")
    w(f"| {repo} | {count} | " + " | ".join(cells) + " |")
w("")

with open(f"{out_dir}/corpus_nag_report.md", "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")

for profile in profiles:
    counts = collections.Counter(d["decision"] for d in by_profile[profile])
    print(f"{profile}: allow {counts['allow']} ({pct(counts['allow'], total)}), ask {counts['ask']} "
          f"({pct(counts['ask'], total)}), deny {counts['deny']} ({pct(counts['deny'], total)})", file=sys.stderr)
print(f"wrote {out_dir}/corpus_nag_report.md and {out_dir}/corpus_decisions.jsonl", file=sys.stderr)
PY
