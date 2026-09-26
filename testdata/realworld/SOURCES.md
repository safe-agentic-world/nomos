# Real-world command corpus sources

`commands.jsonl` holds 1526 single-line shell commands collected by
`scripts/build_command_corpus.py` from the public repositories listed below.
Each line is a JSON object with the keys `command`, `repo`, `path` (the file
the command was taken from), `commit` (the pinned commit), and `license`.

The commands are short, factual build and test invocations (one line each)
taken from public CI workflows, Makefiles, and package.json scripts; they are
used here purely as test fixtures for measuring how often the Claude Code hook
prompts or blocks, and every source repository is permissively licensed (MIT,
Apache-2.0, or BSD) as verified from its license file at the pinned commit.

| Repository | License | Pinned commit | Extracted lines | Commands taken |
| --- | --- | --- | --- | --- |
| [cli/cli](https://github.com/cli/cli) | MIT | `9b031151a825bda919203c5202876a725d637368` | 453 | 277 |
| [django/django](https://github.com/django/django) | BSD-3-Clause | `4fab678a0739d54401ccee7eb587553657c9f76e` | 154 | 87 |
| [tokio-rs/tokio](https://github.com/tokio-rs/tokio) | MIT | `38cdde2bf70057b316c0c8554c5110ecfebd1cd4` | 166 | 126 |
| [prettier/prettier](https://github.com/prettier/prettier) | MIT | `88d8e96365bf9885dfe795ac9a15cd69ad8356f0` | 108 | 81 |
| [fastapi/fastapi](https://github.com/fastapi/fastapi) | MIT | `192b12197eb04c2b4a691cce7d87261b21716714` | 143 | 91 |
| [vercel/next.js](https://github.com/vercel/next.js) | MIT | `abac2089cd97ba3a102747e82434c5c5e6181716` | 386 | 280 |
| [prometheus/prometheus](https://github.com/prometheus/prometheus) | Apache-2.0 | `270db29150547af8dc2f7695382068525c95361c` | 125 | 107 |
| [pandas-dev/pandas](https://github.com/pandas-dev/pandas) | BSD-3-Clause | `eeae81b6da3c2c2b19906815bcb84bd2b19aef9f` | 115 | 92 |
| [rust-lang/cargo](https://github.com/rust-lang/cargo) | Apache-2.0 OR MIT | `07b80494920f3824e2515e536b76ff282e23993e` | 79 | 64 |
| [denoland/deno](https://github.com/denoland/deno) | MIT | `b157cd27e153f0a3e2ef10a6a31edfd105fcbf93` | 1369 | 321 |

## How the corpus is built

- Repositories are cloned with `git clone --depth 1 --filter=blob:none --sparse`
  and `git sparse-checkout set .github Makefile package.json`, then checked out
  at the pinned commit.
- Commands come from `run:` steps in `.github/workflows/*.yml` and `*.yaml`
  (multi-line scripts split into lines, steps whose `shell:` is not a POSIX
  shell skipped), Makefile recipe lines (leading tab and `@`/`-`/`+` stripped,
  simple `$(VAR)` references expanded from the Makefile and the top-level files
  it includes, lines that still contain make-only syntax dropped), and the
  values of `scripts` in package.json.
- Comment lines, lines carrying GitHub expressions (`${{ ... }}`), shell
  control-flow fragments (including `case` arms), heredoc bodies, quoted
  strings and array literals that span lines, and lines outside 3 to 200
  characters are dropped.
- Commands are deduplicated globally, capped at 400 per repository with a
  seeded sample, and shuffled with seed 20260926, so a rebuild reproduces the
  file byte for byte.
