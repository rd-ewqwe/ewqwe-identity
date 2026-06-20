# AGENTS.md — ewQwe Identity

## Project

EU Age Verification using W3C Digital Credentials. Rust actix-web credential verifier + TypeScript/Node.js SPA frontends in a pnpm workspace.

## Repo layout

```
typescript/          pnpm workspace
  ewqwe-digital-identity/  shared JS library (@ewqwe/digital-identity)
  demo-webapp/             Relying Party demo (@ewqwe/demo-webapp)
crates/
  ewqwe-credential-verifier-ui/  admin dashboard (Rust + SPA in ui/)
  ewqwe-digital-credential/      credential crypto (SD-JWT, mDoc)
  ewqwe-openid4vp/               OpenID4VP protocol, DCQL, stores
  other crates...                logging, client lib, server
```

## Rules

### Rust code
- Generated Rust **must not produce any clippy warnings**. Run `cargo clippy --workspace` before finishing.
- Use the project's error pattern (`AttError`, `AttResult`, `AttResultHelper`), not `anyhow`/`eyre`.
- Use `ewqwe_logging` (`TracingConfig`, `tracing_init`), not `env_logger` or manual `tracing-subscriber` setup.
- Dependencies go in root `Cargo.toml` `[workspace.dependencies]`, then referenced with `workspace = true` in member crates.

### TypeScript code
- pnpm workspaces, no npm. Use `workspace:*` protocol for inter-package deps.
- Vanilla TypeScript, no React/Vue.
- Vite for building, Vitest for testing.

### Markdown
- **No ASCII art diagrams.** Use mermaid.js for all diagrams (flowcharts, sequence diagrams, etc.).
- No inline HTML in mermaid blocks — mermaid renderer does not support it.
- Mermaid diagrams are auto-themed; do not use `%%{init}%%` or `classDef` styles.

### Errors & diagnostics
- Fix root causes, not symptoms. Don't silence diagnostics with casts or `as any` if the real issue is a type or logic error.
- Pre-existing issues are not your problem to fix (mention them and move on).
- If you can't fix a diagnostic after 1–2 attempts, explain what's blocking you to the user.

### General
- Read files before editing them. Prefer targeted reads for large files.
- Do not commit changes or create branches unless asked.
- Keep changes minimal and consistent with existing code style.
- Write tests for new code. These tests should cover the new functionality and edge cases and create a non-regression harness.
- Update documentation and READMEs after making changes.
