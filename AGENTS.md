# Repository Guidelines

## Project Structure & Module Organization
Project uses c23, including 'auto'.  no need to include stdbool.h, c23 includes bool by default.
This is a tracing jit compiler.
An explicit goal is minimum lines of code, while keeping readability (i.e. don't make super long lines).

## Build, Test, and Development Commands

## Coding Style & Naming Conventions
- Stick to 2-space indentation in Scheme files and 2-space indentation with aligned braces in C (match the existing files).
- Use `snake_case` for C variables/functions and `Upper_Snake` for enum entries (`OP_FX_ADD`).
- Keep comments concise; add explanatory comments only for non-obvious control flow or GC interactions.

## Testing Guidelines
build with `cmake --build build`.  You can build aarch64 with `cmake --build build_aarch64`

## Commit & Pull Request Guidelines
