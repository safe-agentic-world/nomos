#!/usr/bin/env python3
"""Build a reproducible corpus of real-world single-line shell commands.

The corpus (testdata/realworld/commands.jsonl) measures how often the Claude
Code hook (`nomos hook claude-code`) prompts or blocks on commands that
developers actually run. It is built from a fixed list of permissively
licensed open-source repositories, each pinned to one commit:

- every repository is cloned shallowly and sparsely (`git clone --depth 1
  --filter=blob:none --sparse` followed by `git sparse-checkout set .github
  Makefile package.json`; cone mode also keeps the top-level files, which is
  where the LICENSE file lives) and checked out at the pinned commit;
- the LICENSE file is verified to be MIT, Apache-2.0, or BSD before anything
  is extracted, and a repository with any other license is skipped;
- commands come from `run:` steps in `.github/workflows/*.yml|*.yaml`
  (multi-line scripts are split into lines; steps whose `shell:` is not a
  POSIX shell are skipped), Makefile recipe lines (leading tab and `@`/`-`/`+`
  prefixes stripped, simple `$(VAR)` references expanded from the Makefile and
  the top-level files it `include`s, lines that still carry make-only syntax
  dropped), and the values of `"scripts"` in package.json;
- comment lines, YAML/GitHub-expression noise (`${{ ... }}`), shell
  control-flow fragments (`fi`, `done`, `case` arms, an `if ... then` without
  its `fi`), heredoc bodies, quoted strings and array literals that span lines,
  and lines shorter than 3 or longer than 200 characters are dropped;
- the result is deduplicated globally (first occurrence wins), capped per
  repository with a seeded sample, and shuffled with the same fixed seed, so
  the output is byte-for-byte reproducible.

Only the Python standard library and the `git` binary are used. The clone
directory (default /tmp/nomos-corpus/repos) is deleted when the run finishes
unless --keep-clones is given.

Usage:
    python3 scripts/build_command_corpus.py              # rebuild testdata/realworld
    python3 scripts/build_command_corpus.py --unpinned   # discovery: clone branch tips, print pins
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
from pathlib import Path

SEED = 20260926
PER_REPO_CAP = 400
MIN_LEN = 3
MAX_LEN = 200
DEFAULT_CLONE_DIR = Path("/tmp/nomos-corpus/repos")
SPARSE_PATHS = (".github", "Makefile", "package.json")
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"}

# (owner/name, pinned commit). Pins are the default-branch tips seen on
# 2026-09-26 when the corpus was first built; a rebuild fetches exactly these
# commits. `--unpinned` prints the current tips when the list needs refreshing.
#
# Candidates that verified as permissive but were left out because the sparse
# checkout yields (almost) nothing: kubernetes/kubernetes (no workflows; the
# root Makefile is a symlink into build/), golang/tools (no workflows or
# Makefile), pallets/flask (6 lines), expressjs/express (16), psf/requests (25).
REPOSITORIES: tuple[tuple[str, str], ...] = (
    ("cli/cli", "9b031151a825bda919203c5202876a725d637368"),
    ("django/django", "4fab678a0739d54401ccee7eb587553657c9f76e"),
    ("tokio-rs/tokio", "38cdde2bf70057b316c0c8554c5110ecfebd1cd4"),
    ("prettier/prettier", "88d8e96365bf9885dfe795ac9a15cd69ad8356f0"),
    ("fastapi/fastapi", "192b12197eb04c2b4a691cce7d87261b21716714"),
    ("vercel/next.js", "abac2089cd97ba3a102747e82434c5c5e6181716"),
    ("prometheus/prometheus", "270db29150547af8dc2f7695382068525c95361c"),
    ("pandas-dev/pandas", "eeae81b6da3c2c2b19906815bcb84bd2b19aef9f"),
    ("rust-lang/cargo", "07b80494920f3824e2515e536b76ff282e23993e"),
    ("denoland/deno", "b157cd27e153f0a3e2ef10a6a31edfd105fcbf93"),
)


class CorpusError(Exception):
    """A failure that must stop the build: the corpus would not be reproducible."""


# --- git -------------------------------------------------------------------


def run_git(args: list[str], cwd: Path | None = None) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    proc = subprocess.run(["git", *args], cwd=cwd, env=env, check=False,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise CorpusError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout.strip()


def clone_repository(repo: str, commit: str, dest: Path, reuse: bool = False) -> str:
    """Sparse-clone repo into dest at the pinned commit and return the checked-out SHA."""
    url = f"https://github.com/{repo}.git"
    if dest.exists():
        if reuse and (dest / ".git").exists():
            head = run_git(["rev-parse", "HEAD"], cwd=dest)
            if not commit or head == commit:
                return head
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    run_git(["clone", "--quiet", "--depth", "1", "--filter=blob:none", "--sparse", url, str(dest)])
    # --skip-checks: cone mode refuses plain file names (Makefile, package.json) otherwise;
    # top-level files are always part of a cone-mode checkout, so the names are only
    # there to state the intent.
    run_git(["sparse-checkout", "set", "--skip-checks", *SPARSE_PATHS], cwd=dest)
    head = run_git(["rev-parse", "HEAD"], cwd=dest)
    if commit and head != commit:
        # The branch tip moved on since the pin was taken: fetch exactly the pinned commit.
        run_git(["fetch", "--quiet", "--depth", "1", "origin", commit], cwd=dest)
        run_git(["checkout", "--quiet", commit], cwd=dest)
        head = run_git(["rev-parse", "HEAD"], cwd=dest)
        if head != commit:
            raise CorpusError(f"{repo}: checked out {head}, expected pinned commit {commit}")
    return head


# --- license verification ----------------------------------------------------


def classify_license_text(text: str) -> str | None:
    folded = " ".join(text.split()).lower()
    if "apache license" in folded and "version 2.0" in folded:
        return "Apache-2.0"
    if "permission is hereby granted, free of charge, to any person obtaining a copy" in folded:
        return "MIT"
    if "redistribution and use in source and binary forms, with or without modification, are permitted" in folded:
        return "BSD-3-Clause" if "neither the name" in folded else "BSD-2-Clause"
    return None


def detect_license(root: Path) -> tuple[str, str] | None:
    """Return (SPDX id, file name) when the repository's license file is permissive."""
    files = {p.name.upper(): p for p in root.iterdir() if p.is_file()}
    for key in ("LICENSE", "LICENSE.MD", "LICENSE.TXT", "LICENSE.RST", "LICENCE", "LICENCE.MD",
                "LICENCE.TXT", "COPYING", "COPYING.MD", "COPYING.TXT"):
        if key in files:
            spdx = classify_license_text(files[key].read_text(encoding="utf-8", errors="replace"))
            if spdx in PERMISSIVE:
                return spdx, files[key].name
            return None
    # Dual-licensed layouts such as LICENSE-MIT + LICENSE-APACHE: every file must verify.
    # Third-party notice files describe vendored code, not the repository's license.
    ids, names = [], []
    for key in sorted(files):
        if "THIRD" in key or "NOTICE" in key:
            continue
        if key.startswith("LICENSE-") or key.startswith("LICENSE.") or key.startswith("LICENCE-"):
            spdx = classify_license_text(files[key].read_text(encoding="utf-8", errors="replace"))
            if spdx not in PERMISSIVE:
                return None
            if spdx not in ids:
                ids.append(spdx)
            names.append(files[key].name)
    if ids:
        return " OR ".join(ids), ", ".join(names)
    return None


# --- shell script lines --------------------------------------------------------

HEREDOC_TERMINATOR = re.compile(r"-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
GH_EXPRESSION = re.compile(r"\$\{\{.*?\}\}")
FUNCTION_DEF = re.compile(r"^(function\s+)?[A-Za-z_][\w-]*\s*\(\)\s*\{?$")
TRAILING_OPERATOR = re.compile(r"\s*(&&|\|\||\||;)$")
OPENERS = {"if": "fi", "for": "done", "while": "done", "until": "done", "case": "esac", "select": "done"}
FRAGMENTS = {"then", "else", "elif", "fi", "do", "done", "esac", "in", "function", "end", "{", "}", ";;"}
CASE_ARM = re.compile(r"^[^\s()'\"]+\s*\)(\s|$)")
QUOTE_LOOKAHEAD = 120  # lines searched for the close of a multi-line string or array literal

# When --dump-drops is given, every dropped line is recorded here as (category, line).
DROP_LOG: list[tuple[str, str]] | None = None


def drop(dropped: dict[str, int], category: str, line: str) -> None:
    dropped[category] = dropped.get(category, 0) + 1
    if DROP_LOG is not None:
        DROP_LOG.append((category, line))


CLOSED = (None, 0)


def scan_state(state: tuple[str | None, int], line: str) -> tuple[str | None, int]:
    """Track the open quote and unbalanced parentheses across a line."""
    quote, depth = state
    i = 0
    while i < len(line):
        char = line[i]
        if quote == "'":
            if char == "'":
                quote = None
        elif quote == '"':
            if char == "\\":
                i += 1
            elif char == '"':
                quote = None
        elif char == "\\":
            i += 1
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "#" and (i == 0 or line[i - 1].isspace()):
            break  # a comment runs to the end of the line
        i += 1
    return quote, depth


def heredoc_terminator(line: str) -> str | None:
    """The terminator word of a `<<` heredoc operator outside quotes, if the line has one."""
    quote = None
    i = 0
    while i < len(line):
        char = line[i]
        if quote == "'":
            if char == "'":
                quote = None
        elif quote == '"':
            if char == "\\":
                i += 1
            elif char == '"':
                quote = None
        elif char == "\\":
            i += 1
        elif char in "'\"":
            quote = char
        elif char == "#" and (i == 0 or line[i - 1].isspace()):
            return None
        elif line.startswith("<<", i):
            if line.startswith("<<<", i):  # here-string
                i += 3
                continue
            match = HEREDOC_TERMINATOR.match(line, i + 2)
            return match.group(2) if match else None
        i += 1
    return None


def multiline_construct_end(lines: list[str], start: int) -> int | None:
    """Index of the line that closes a quote or parenthesis opened on lines[start], if one is near."""
    state = scan_state(CLOSED, lines[start].strip())
    if state == CLOSED:
        return None
    for j in range(start + 1, min(len(lines), start + 1 + QUOTE_LOOKAHEAD)):
        state = scan_state(state, lines[j].strip())
        if state == CLOSED:
            return j
    return None


def is_noise(line: str) -> bool:
    """Lines that are not a command anyone would run on their own."""
    if not re.search(r"[A-Za-z0-9]", line):
        return True
    if re.fullmatch(r"[A-Z_]{2,}", line):  # a stray heredoc terminator such as EOF
        return True
    if FUNCTION_DEF.match(line) or CASE_ARM.match(line):
        return True
    words = line.replace(";", " ; ").split()
    first = words[0]
    if first in FRAGMENTS:
        return True
    closer = OPENERS.get(first)
    if closer is not None and closer not in words:
        return True  # `if ...; then` or `for ...; do` without the rest of the compound command
    return False


def script_to_commands(script: str) -> tuple[list[str], dict[str, int]]:
    """Split a shell script into candidate single-line commands, with drop counts."""
    logical: list[str] = []
    pending: str | None = None
    for raw in script.splitlines():
        line = raw.rstrip()
        if pending is not None:
            line = pending + " " + line.strip()
            pending = None
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending = line[:-1].rstrip()
            continue
        logical.append(line)
    if pending is not None:
        logical.append(pending)

    out: list[str] = []
    dropped = {"comment": 0, "expression": 0, "noise": 0, "length": 0, "heredoc_body": 0,
               "multiline_construct": 0}
    terminator: str | None = None
    construct_end = -1  # index of the line closing a multi-line quoted string or array
    for index, line in enumerate(logical):
        stripped = line.strip()
        if index <= construct_end:
            drop(dropped, "multiline_construct", stripped)
            continue
        if terminator is not None:
            if stripped == terminator:
                terminator = None
            else:
                drop(dropped, "heredoc_body", stripped)
            continue
        if not stripped:
            continue
        if stripped.startswith("#"):
            drop(dropped, "comment", stripped)
            continue
        end = multiline_construct_end(logical, index)
        if end is not None:
            # A quoted argument or array literal that spans lines (a jq program, a
            # multi-line echo, `args=(` ... `)`) is not a single-line command; skip
            # it up to the line that closes it.
            construct_end = end
            drop(dropped, "multiline_construct", stripped)
            continue
        candidate = heredoc_terminator(stripped)
        if candidate and any(later.strip() == candidate for later in logical[index + 1:]):
            terminator = candidate  # the command line is kept; its heredoc body is skipped
        if GH_EXPRESSION.search(stripped):
            drop(dropped, "expression", stripped)
            continue
        stripped = TRAILING_OPERATOR.sub("", stripped).strip()
        if not stripped or is_noise(stripped):
            drop(dropped, "noise", stripped)
            continue
        if not MIN_LEN <= len(stripped) <= MAX_LEN:
            drop(dropped, "length", stripped)
            continue
        out.append(stripped)
    return out, dropped


# --- GitHub workflows ---------------------------------------------------------------

RUN_KEY = re.compile(r"^(?P<indent>[ \t]*)(?P<dash>-[ \t]+)?run:(?:[ \t]+(?P<value>.*))?$")
BLOCK_INDICATOR = re.compile(r"^[|>][-+0-9]*(?:[ \t]+#.*)?$")
DEFAULTS_KEY = re.compile(r"^(?P<indent>[ \t]*)defaults:\s*(?:#.*)?$")
SHELL_KEY = re.compile(r"^(?P<indent>[ \t]*)shell:[ \t]*(?P<value>\S.*)$")
POSIX_SHELLS = {"bash", "sh", "dash", "zsh", "msys2"}


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def is_blank_or_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def read_block(lines: list[str], start: int, key_indent: int) -> tuple[list[str], int]:
    """Collect the lines of a block scalar whose key sits at key_indent."""
    block: list[str] = []
    i = start
    while i < len(lines):
        line = lines[i]
        if line.strip() == "":
            block.append("")
        elif indent_of(line) > key_indent:
            block.append(line)
        else:
            break
        i += 1
    while block and block[-1] == "":
        block.pop()
    return block, i


def fold(block: list[str]) -> str:
    """Approximate YAML folding: lines join with spaces, blank lines separate commands."""
    paragraphs: list[str] = []
    current: list[str] = []
    for line in block:
        if line.strip() == "":
            if current:
                paragraphs.append(" ".join(current))
                current = []
        else:
            current.append(line.strip())
    if current:
        paragraphs.append(" ".join(current))
    return "\n".join(paragraphs)


def unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        return (inner.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t")
                .replace("\\\\", "\\"))
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("''", "'")
    return re.sub(r"\s+#.*$", "", value)


def read_scalar(lines: list[str], index: int, value: str, key_indent: int) -> tuple[str, int]:
    """Read a plain or quoted scalar that starts on the run: line itself."""
    quote = value[0] if value[0] in "\"'" else ""
    parts = [value]
    i = index + 1
    closed = not quote or (len(value) >= 2 and value.endswith(quote) and not value.endswith("\\" + quote))
    # A plain scalar continues on more-indented lines; a quoted one until its closing quote.
    while i < len(lines) and (not quote or not closed):
        line = lines[i]
        if not line.strip() or indent_of(line) <= key_indent:
            break
        i += 1
        if not quote and line.strip().startswith("#"):
            continue
        parts.append(line.strip())
        if quote and line.rstrip().endswith(quote):
            closed = True
    return unquote(" ".join(parts)), i


def step_shell(lines: list[str], run_index: int, key_indent: int, has_dash: bool) -> str | None:
    """The `shell:` value of the step that owns the run: key at run_index, if any."""
    start = run_index
    if not has_dash:
        j = run_index - 1
        while j >= 0:
            if not is_blank_or_comment(lines[j]) and indent_of(lines[j]) < key_indent:
                start = j
                break
            j -= 1
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if not is_blank_or_comment(line):
            indent = indent_of(line)
            if indent < key_indent:
                break
            if indent == key_indent:
                match = SHELL_KEY.match(line)
                if match:
                    return match.group("value")
        i += 1
    return None


def default_shell(lines: list[str], defaults_index: int, indent: int) -> str | None:
    i = defaults_index + 1
    while i < len(lines):
        line = lines[i]
        if not is_blank_or_comment(line):
            if indent_of(line) <= indent:
                break
            match = SHELL_KEY.match(line)
            if match:
                return match.group("value")
        i += 1
    return None


def shell_is_posix(shell: str | None) -> bool:
    if shell is None:
        return True  # unset: bash on Linux and macOS runners
    value = re.sub(r"\s+#.*$", "", shell).strip().strip("'\"")
    if value.startswith("${{"):
        return True
    words = value.split()
    if not words:
        return True
    return words[0].rsplit("/", 1)[-1] in POSIX_SHELLS


def workflow_scripts(text: str) -> list[tuple[str | None, str]]:
    """Return (shell, script) for every `run:` step in a workflow file."""
    lines = text.splitlines()
    results: list[tuple[str | None, str]] = []
    defaults: list[tuple[int, str]] = []  # (indent of the defaults: key, shell)
    i = 0
    while i < len(lines):
        line = lines[i]
        if is_blank_or_comment(line):
            i += 1
            continue
        indent = indent_of(line)
        while defaults and indent < defaults[-1][0]:
            defaults.pop()
        match = DEFAULTS_KEY.match(line)
        if match:
            shell = default_shell(lines, i, indent)
            if shell is not None:
                defaults.append((indent, shell))
            i += 1
            continue
        match = RUN_KEY.match(line)
        if not match:
            i += 1
            continue
        dash = match.group("dash") or ""
        key_indent = indent + len(dash)
        value = (match.group("value") or "").strip()
        if not value:  # a `run:` mapping such as defaults.run, not a step
            i += 1
            continue
        if value[0] in "[{":
            i += 1
            continue
        shell = step_shell(lines, i, key_indent, bool(dash))
        if shell is None and defaults:
            shell = defaults[-1][1]
        if BLOCK_INDICATOR.match(value):
            block, next_i = read_block(lines, i + 1, key_indent)
            script = "\n".join(block) if value[0] == "|" else fold(block)
        else:
            script, next_i = read_scalar(lines, i, value, key_indent)
        results.append((shell, script))
        i = max(next_i, i + 1)
    return results


def workflow_commands(text: str) -> tuple[list[str], dict[str, int]]:
    out: list[str] = []
    dropped: dict[str, int] = {"non_posix_shell": 0}
    for shell, script in workflow_scripts(text):
        if not shell_is_posix(shell):
            drop(dropped, "non_posix_shell", f"[shell: {shell}] " + script.replace("\n", " | "))
            continue
        commands, counts = script_to_commands(script)
        out.extend(commands)
        for key, value in counts.items():
            dropped[key] = dropped.get(key, 0) + value
    return out, dropped


# --- Makefiles ---------------------------------------------------------------------

MAKE_ASSIGNMENT = re.compile(
    r"^(?:export\s+|override\s+)*([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:=|::=|\+=|=)\s*(.*?)\s*$")
MAKE_REFERENCE = re.compile(r"\$[({]([A-Za-z_][A-Za-z0-9_.-]*)[)}]")
MAKE_AUTOMATIC = re.compile(r"\$[@<^*?%+|]|\$\([@<^*?%+|][DF]?\)")
MAKE_BUILTINS = {"MAKE": "make", "RM": "rm -f", "CC": "cc", "CXX": "c++", "AR": "ar", "CURDIR": "."}
MAKE_ENVIRONMENT = {"HOME", "PWD", "PATH", "GOPATH", "GOROOT", "USER", "TMPDIR", "SHELL"}
PLACEHOLDER = "\x00"


def join_continuations(text: str) -> list[str]:
    lines: list[str] = []
    pending: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if pending is not None:
            line = pending + " " + line.strip()
            pending = None
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending = line[:-1].rstrip()
            continue
        lines.append(line)
    if pending is not None:
        lines.append(pending)
    return lines


def parse_make_variables(lines: list[str]) -> dict[str, str]:
    variables = dict(MAKE_BUILTINS)
    in_define = False
    for line in lines:
        if line.startswith("\t"):
            continue
        stripped = line.strip()
        if in_define:
            if stripped.startswith("endef"):
                in_define = False
            continue
        if stripped.startswith("define "):
            in_define = True
            continue
        match = MAKE_ASSIGNMENT.match(stripped)
        if not match:
            continue
        name, operator, value = match.groups()
        value = re.sub(r"\s*#.*$", "", value)
        if operator == "?=" and name in variables:
            continue
        if operator == "+=":
            variables[name] = (variables.get(name, "") + " " + value).strip()
        else:
            variables[name] = value
    return variables


def expand_make(line: str, variables: dict[str, str]) -> str | None:
    """Expand simple `$(VAR)` references; None when make-only syntax remains."""
    line = line.replace("$$", PLACEHOLDER)
    for _ in range(8):
        if MAKE_AUTOMATIC.search(line):
            return None
        unresolved = False

        def replace(match: re.Match[str]) -> str:
            nonlocal unresolved
            name = match.group(1)
            if name in variables:
                return variables[name].replace("$$", PLACEHOLDER)
            if name in MAKE_ENVIRONMENT:
                return "$" + name
            unresolved = True
            return match.group(0)

        expanded = MAKE_REFERENCE.sub(replace, line)
        if unresolved:
            return None
        if expanded == line:
            break
        line = expanded
    if "$(" in line or "${" in line or MAKE_AUTOMATIC.search(line):
        return None
    return line.replace(PLACEHOLDER, "$")


MAKE_RULE = re.compile(r"^[^\t#=]*?:(?!=)")
MAKE_CONDITIONALS = ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")
MAKE_INCLUDE = re.compile(r"^-?include\s+(.+)$")


def included_lines(lines: list[str], directory: Path | None) -> list[str]:
    """Lines of the files named by `include` directives, for their variable definitions."""
    extra: list[str] = []
    if directory is None:
        return extra
    for line in lines:
        match = MAKE_INCLUDE.match(line.strip())
        if not match:
            continue
        for name in match.group(1).split():
            path = directory / name
            if "$" not in name and "/" not in name and path.is_file():
                extra.extend(join_continuations(path.read_text(encoding="utf-8", errors="replace")))
    return extra


def makefile_commands(text: str, directory: Path | None = None) -> tuple[list[str], dict[str, int]]:
    lines = join_continuations(text)
    variables = parse_make_variables(included_lines(lines, directory) + lines)
    out: list[str] = []
    dropped: dict[str, int] = {"make_syntax": 0}
    in_define = False
    in_recipe = False  # tab-indented lines are recipe lines only after a rule
    for line in lines:
        stripped = line.strip()
        if in_define:
            if stripped.startswith("endef"):
                in_define = False
            continue
        if not line.startswith("\t"):
            if stripped.startswith("define "):
                in_define = True
                in_recipe = False
            elif stripped and not stripped.startswith("#") and stripped.split()[0] not in MAKE_CONDITIONALS:
                in_recipe = bool(MAKE_RULE.match(line))
            continue
        if not in_recipe:
            continue
        recipe = re.sub(r"^[@+-]+\s*", "", line.lstrip("\t "))
        expanded = expand_make(recipe, variables)
        if expanded is None:
            drop(dropped, "make_syntax", recipe)
            continue
        commands, counts = script_to_commands(expanded)
        out.extend(commands)
        for key, value in counts.items():
            dropped[key] = dropped.get(key, 0) + value
    return out, dropped


# --- package.json ------------------------------------------------------------------


def package_json_commands(text: str) -> tuple[list[str], dict[str, int]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorpusError(f"package.json is not valid JSON: {exc}") from exc
    scripts = data.get("scripts") if isinstance(data, dict) else None
    out: list[str] = []
    dropped: dict[str, int] = {}
    if isinstance(scripts, dict):
        for value in scripts.values():
            if isinstance(value, str):
                commands, counts = script_to_commands(value)
                out.extend(commands)
                for key, count in counts.items():
                    dropped[key] = dropped.get(key, 0) + count
    return out, dropped


# --- corpus assembly -----------------------------------------------------------------


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        files.extend(sorted(p for p in workflows.iterdir()
                            if p.is_file() and p.suffix in (".yml", ".yaml")))
    for name in ("Makefile", "GNUmakefile", "makefile"):
        path = root / name
        if path.is_file():  # a symlink to a path outside the sparse checkout is skipped
            files.append(path)
            break
    package = root / "package.json"
    if package.is_file():
        files.append(package)
    return files


def extract(path: Path) -> tuple[list[str], dict[str, int]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name == "package.json":
        return package_json_commands(text)
    if path.suffix in (".yml", ".yaml"):
        return workflow_commands(text)
    return makefile_commands(text, path.parent)


def build(args: argparse.Namespace) -> int:
    global DROP_LOG
    clone_dir = Path(args.clone_dir)
    out_dir = Path(args.out_dir)
    dump = open(args.dump_drops, "w", encoding="utf-8") if args.dump_drops else None
    seen: set[str] = set()
    per_repo: dict[str, list[dict[str, str]]] = {}
    sources: list[dict[str, object]] = []
    pins: list[tuple[str, str]] = []
    for repo, pin in REPOSITORIES:
        if not pin and not args.unpinned:
            raise CorpusError(f"{repo} has no pinned commit; run with --unpinned to discover one")
        dest = clone_dir / repo.replace("/", "__")
        print(f"cloning {repo} ...", file=sys.stderr)
        head = clone_repository(repo, "" if args.unpinned else pin, dest, reuse=args.reuse_clones)
        pins.append((repo, head))
        license_info = detect_license(dest)
        if license_info is None:
            print(f"  skipped: license of {repo} is not MIT, Apache-2.0, or BSD", file=sys.stderr)
            sources.append({"repo": repo, "commit": head, "license": "(not permissive; skipped)",
                            "extracted": 0, "taken": 0})
            continue
        spdx, license_file = license_info
        records: list[dict[str, str]] = []
        extracted = 0
        dropped_total: dict[str, int] = {}
        duplicates = 0
        for path in source_files(dest):
            relative = path.relative_to(dest).as_posix()
            if dump is not None:
                DROP_LOG = []
            commands, dropped = extract(path)
            if dump is not None:
                for category, line in DROP_LOG or []:
                    dump.write(json.dumps({"repo": repo, "path": relative, "category": category,
                                           "line": line}, ensure_ascii=False) + "\n")
            extracted += len(commands)
            for key, value in dropped.items():
                dropped_total[key] = dropped_total.get(key, 0) + value
            for command in commands:
                if command in seen:
                    duplicates += 1
                    continue
                seen.add(command)
                records.append({"command": command, "repo": repo, "path": relative,
                                "commit": head, "license": spdx})
        per_repo[repo] = records
        sources.append({"repo": repo, "commit": head, "license": spdx, "license_file": license_file,
                        "extracted": extracted, "unique": len(records), "taken": 0})
        print(f"  {spdx} ({license_file}) at {head[:12]}: {extracted} lines, "
              f"{len(records)} new unique, {duplicates} duplicates, dropped {dropped_total}",
              file=sys.stderr)

    rng = random.Random(args.seed)
    corpus: list[dict[str, str]] = []
    for repo, _ in REPOSITORIES:
        records = per_repo.get(repo, [])
        if len(records) > args.cap:
            records = rng.sample(records, args.cap)
        for source in sources:
            if source["repo"] == repo:
                source["taken"] = len(records)
        corpus.extend(records)
    rng.shuffle(corpus)

    out_dir.mkdir(parents=True, exist_ok=True)
    corpus_path = out_dir / "commands.jsonl"
    with corpus_path.open("w", encoding="utf-8") as fh:
        for record in corpus:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    (out_dir / "SOURCES.md").write_text(render_sources(sources, len(corpus), args), encoding="utf-8")
    print(f"wrote {len(corpus)} commands to {corpus_path}", file=sys.stderr)

    if dump is not None:
        dump.close()
        print(f"dropped lines written to {args.dump_drops}", file=sys.stderr)
    if args.unpinned:
        print("\nbranch tips seen (paste into REPOSITORIES to pin):")
        for repo, head in pins:
            print(f'    ("{repo}", "{head}"),')
    if not (args.keep_clones or args.reuse_clones) and clone_dir.exists():
        shutil.rmtree(clone_dir)
        parent = clone_dir.parent
        if clone_dir == DEFAULT_CLONE_DIR and parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()  # leave no empty /tmp/nomos-corpus behind
    return 0


def render_sources(sources: list[dict[str, object]], total: int, args: argparse.Namespace) -> str:
    lines = [
        "# Real-world command corpus sources",
        "",
        f"`commands.jsonl` holds {total} single-line shell commands collected by",
        "`scripts/build_command_corpus.py` from the public repositories listed below.",
        "Each line is a JSON object with the keys `command`, `repo`, `path` (the file",
        "the command was taken from), `commit` (the pinned commit), and `license`.",
        "",
        "The commands are short, factual build and test invocations (one line each)",
        "taken from public CI workflows, Makefiles, and package.json scripts; they are",
        "used here purely as test fixtures for measuring how often the Claude Code hook",
        "prompts or blocks, and every source repository is permissively licensed (MIT,",
        "Apache-2.0, or BSD) as verified from its license file at the pinned commit.",
        "",
        "| Repository | License | Pinned commit | Extracted lines | Commands taken |",
        "| --- | --- | --- | --- | --- |",
    ]
    for source in sources:
        lines.append(f"| [{source['repo']}](https://github.com/{source['repo']}) | {source['license']} "
                     f"| `{source['commit']}` | {source['extracted']} | {source['taken']} |")
    lines += [
        "",
        "## How the corpus is built",
        "",
        "- Repositories are cloned with `git clone --depth 1 --filter=blob:none --sparse`",
        "  and `git sparse-checkout set .github Makefile package.json`, then checked out",
        "  at the pinned commit.",
        "- Commands come from `run:` steps in `.github/workflows/*.yml` and `*.yaml`",
        "  (multi-line scripts split into lines, steps whose `shell:` is not a POSIX",
        "  shell skipped), Makefile recipe lines (leading tab and `@`/`-`/`+` stripped,",
        "  simple `$(VAR)` references expanded from the Makefile and the top-level files",
        "  it includes, lines that still contain make-only syntax dropped), and the",
        "  values of `scripts` in package.json.",
        "- Comment lines, lines carrying GitHub expressions (`${{ ... }}`), shell",
        "  control-flow fragments (including `case` arms), heredoc bodies, quoted",
        "  strings and array literals that span lines, and lines outside 3 to 200",
        "  characters are dropped.",
        f"- Commands are deduplicated globally, capped at {args.cap} per repository with a",
        f"  seeded sample, and shuffled with seed {args.seed}, so a rebuild reproduces the",
        "  file byte for byte.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", default=str(root / "testdata" / "realworld"),
                        help="directory for commands.jsonl and SOURCES.md (default: testdata/realworld)")
    parser.add_argument("--clone-dir", default=str(DEFAULT_CLONE_DIR),
                        help=f"where repositories are cloned (default: {DEFAULT_CLONE_DIR})")
    parser.add_argument("--keep-clones", action="store_true", help="do not delete the clone directory")
    parser.add_argument("--reuse-clones", action="store_true",
                        help="reuse an existing clone that is already at the pinned commit (implies --keep-clones)")
    parser.add_argument("--unpinned", action="store_true",
                        help="clone branch tips instead of the pinned commits and print the tips")
    parser.add_argument("--dump-drops", metavar="FILE",
                        help="also write every dropped line as JSONL (repo, path, category, line) to FILE")
    parser.add_argument("--cap", type=int, default=PER_REPO_CAP, help=f"commands per repository (default {PER_REPO_CAP})")
    parser.add_argument("--seed", type=int, default=SEED, help=f"shuffle seed (default {SEED})")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 10):
        print("python 3.10 or newer is required", file=sys.stderr)
        return 2
    try:
        return build(args)
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
