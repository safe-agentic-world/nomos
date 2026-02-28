# Repository Guidelines

## Project Structure & Module Organization
This repository is currently documentation-only. The top-level files are:
- `README.md`: project summary.
- `TASKS.md`: task tracking and notes.
- `LICENSE`: licensing information.

If you introduce source code or tests, propose a clear layout in your PR (for example, `src/` for implementation and `tests/` for automated tests), and update this guide to reflect the new structure.

## Build, Test, and Development Commands
No build, test, or run scripts are defined yet. If you add tooling, document it here with exact commands. Examples to add when applicable:
- `npm run build`: compile or bundle the project.
- `npm test`: run the test suite.
- `make lint`: run linters/formatters.

## Coding Style & Naming Conventions
There is no established language-specific style yet. Follow these baseline rules:
- Match the existing file’s indentation and formatting.
- Use clear, descriptive names (e.g., `policyEngine`, `agentConfig`).
- Keep Markdown headings short and in Title Case.

If you introduce a formatter or linter, include the exact command and config file path (for example, `pyproject.toml`, `.editorconfig`, `.prettierrc`).

## Testing Guidelines
No testing framework is currently configured. If you add tests:
- Place them in a dedicated `tests/` directory (or language-standard equivalent).
- Use descriptive names like `test_policy_validation.py` or `policy_validation.test.ts`.
- Ensure new functionality is covered and note how to run the tests in this guide.

## Commit & Pull Request Guidelines
Git history only contains “Initial commit,” so there is no established convention. Use short, imperative subject lines (e.g., “Add policy validation notes”).

Pull requests should include:
- A concise summary of changes.
- Links to relevant issues or tasks.
- Notes on tests run (or why tests are not applicable).
- Documentation updates when behavior or structure changes.

## Security & Configuration Notes
Do not add secrets to the repository. If configuration is required in the future, provide sample files (e.g., `config.example.json`) and document required fields in `README.md`.
