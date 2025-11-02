# Repository Guidelines

## Project Structure & Module Organization

## Build, Test, and Development Commands

## Coding Style & Naming Conventions
- Stick to 2-space indentation in Scheme files and 2-space indentation with aligned braces in C (match the existing files).
- Use `snake_case` for C variables/functions and `Upper_Snake` for enum entries (`OP_FX_ADD`).
- Keep comments concise; add explanatory comments only for non-obvious control flow or GC interactions.
- When adding generators, keep Scheme data structures declarative—one opcode definition should feed both VM and tracer.

## Testing Guidelines
- No automated test harness exists yet. Manually run representative programs through the `hawk` binary after each change.
- For generator tweaks, compare `gosh vmgen.scm` output against the committed C switch cases.
- If you introduce tests, place scripts in `tests/` (create it) and document how to run them here.

## Commit & Pull Request Guidelines
