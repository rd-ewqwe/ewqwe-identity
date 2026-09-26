---
name: rust
description: Use when writing, reviewing, or modifying Rust code in this repository.
applyTo: "**/*.rs"
---

# Rust Development

- Formatting: Adhere to standard `cargo fmt` formatting.
- Linting: Resolve all `cargo clippy` warnings before completing a task.
- Crate Versions: Always treat `Cargo.toml` and `Cargo.lock` as the canonical source for crate versions.
- API Usage: Before suggesting or generating Rust API usage, check the workspace manifest versions first.
- Comments: Use `///` doc comments for public items and `//` comments for private implementation details. Follow the rules in the [code-comments skill](../code-comments/SKILL.md).
- Logging: Use the `ewqwe_logging` crate. Call `tracing_init` in a binary, and `log_init` in tests.
- Testing: Write unit tests in a `#[cfg(test)] mod tests` module. Write integration tests for endpoints and critical workflows in the crate's `tests` module, for example `crates/ewqwe-credential-verifier-server/src/tests/`. Run them with `cargo test`.
- Testing: Spawn the server inside the tests, and clean up after each test. Use `#[tokio::test]` or `#[actix_web::test]` as appropriate.
- Error Handling: Return `Result` and `Option`. Do not panic in code, or in tests. Use the project error system: the `AttError` and `AttResult` types, the `AttResultHelper::context` method, and the `auth_error!`, `auth_bail!`, and `auth_ensure!` macros. Define error enums with `thiserror`. Do not use `anyhow` or `eyre`.
- Function naming: Name a function after the action it performs, using the vocabulary of the standards. For example, `verify_mdoc_presentation` and `decode_sd_jwt_presentation`.

# Workspace handling

- Always treat `Cargo.toml` and `Cargo.lock` as the canonical source for crate versions.
- Before suggesting or generating Rust API usage, check the workspace manifest versions first.
- Declare a shared dependency once in the root `Cargo.toml` under `[workspace.dependencies]`, and reference it from a member with `workspace = true`.
- The workspace uses edition 2024. Do not lower the edition of a member below the workspace setting.

# Behavior Expectations

- Keep changes version-aware and minimal.
- Avoid introducing API calls that require dependency upgrades unless explicitly requested.
- If a request conflicts with manifest-pinned versions, call out the conflict before producing code.
