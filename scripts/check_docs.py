"""Check relative inline Markdown links in contributor-facing documentation.

No network requests; anchors and external URLs are not validated. Files under
ignored local environments, build output, and historical changelogs are excluded.
"""
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


def main():
    root = Path(__file__).resolve().parents[1]
    paths = [root / name for name in ("README.md", "CONTRIBUTING.md", "TESTING.md", "SECURITY.md")]
    for directory in ("docs", "examples", "sdk", ".github"):
        paths.extend(path for path in (root / directory).rglob("*.md")
                     if not any(part in {"build", "dist", "node_modules", ".venv"}
                                or part.endswith(".egg-info") for part in path.parts))
    failures = []
    for path in sorted(paths):
        content = path.read_text(encoding="utf-8")
        content = re.sub(r"(?ms)^```.*?^```[^\n]*", "", content)
        for match in re.finditer(r"!?\[[^\]\n]*\]\(([^)\n]+)\)", content):
            target = match.group(1).strip().split(' "', 1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            resolved = (root if parsed.path.startswith("/") else path.parent) / unquote(parsed.path.lstrip("/"))
            if not resolved.exists():
                failures.append(f"{path.relative_to(root)}: missing link {target}")
    for failure in failures:
        print(failure)
    print(f"Checked {len(paths)} Markdown files; {len(failures)} broken local links")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
