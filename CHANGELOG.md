# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.3] — 2026-07-05

### Fixed

- Better error handling in `ewqwe-openid4vp` and `ewqwe-digital-credential` crates

## [1.1.2] — 2026-06-30

### Security

- Various fixes to address static code analysis: hard-coded values, complex regexes.
- Handling of Isser CAs and added Frande Identité IACA

## [1.1.1] — 2026-06-27

### Security

- **Rust**: Upgraded `quinn-proto` from 0.11.14 to 0.11.15 to fix [RUSTSEC-2026-0185](https://rustsec.org/advisories/RUSTSEC-2026-0185) — remote memory exhaustion from unbounded out-of-order stream reassembly (HIGH severity, CVSS 7.5).
- **Rust**: Suppressed [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (`rsa` Marvin Attack) with a justified ignore in `.cargo/audit.toml`. The `rsa` crate is a transitive dependency of `sqlx-mysql` used only for client-side password encryption during MySQL authentication — there is no decryption oracle, so the attack is not exploitable.
- **TypeScript**: Upgraded `vitest` from ^1.0.0 to ^3.2.6 to fix [GHSA-5xrq-8626-4rwp](https://github.com/advisories/GHSA-5xrq-8626-4rwp) — arbitrary file read and execution via the Vitest UI server (CRITICAL severity).
- **TypeScript**: Upgraded `vite` from ^5.0.0 to ^6.4.3 to fix three vulnerabilities:
  - [GHSA-fx2h-pf6j-xcff](https://github.com/advisories/GHSA-fx2h-pf6j-xcff) — `server.fs.deny` bypass on Windows alternate paths (HIGH severity).
  - [GHSA-4w7w-66w2-5vf9](https://github.com/advisories/GHSA-4w7w-66w2-5vf9) — path traversal in optimized deps `.map` handling (MODERATE).
  - [GHSA-v6wh-96g9-6wx3](https://github.com/advisories/GHSA-v6wh-96g9-6wx3) — NTLMv2 hash disclosure via UNC path handling on Windows (MODERATE).
- **TypeScript**: Resolved `esbuild` to >=0.24.3 via pnpm workspace overrides to fix [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99) — dev server cross-origin request leak (MODERATE).

### Added

- `.cargo/audit.toml` — security advisory configuration with justified ignore for `rsa` (RUSTSEC-2023-0071).
- `typescript/pnpm-workspace.yaml` — added `overrides` for `vite` and `esbuild` to force patched versions across all dependency trees.

### Changed

- `Cargo.lock` — updated `quinn-proto` 0.11.14 → 0.11.15.
- `typescript/ewqwe-digital-identity/package.json` — devDependencies: `vite` ^5.0.0 → ^6.4.3, `vitest` ^1.0.0 → ^3.2.6.
- `typescript/package.json` — added `overrides` field for `vite` and `esbuild`.

### Fixed

- All known Dependabot security advisories resolved. `cargo audit` and `pnpm audit` report zero vulnerabilities.

---

## [1.1.0] — 2026-06-24

Initial open-core release.

[1.1.1]: https://github.com/rd-ewqwe/ewqwe-identity/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/rd-ewqwe/ewqwe-identity/releases/tag/v1.1.0
