---
name: git-commits
description: Use when creating git commits. Covers atomic commit splitting and conventional commit format.
---

# Git commits

## Goal

A clean, linear history. Each commit that lands on main is one deliberate step.
A reader must never have to follow a commit that patches or undoes an earlier
one from the same branch.

## Atomicity

One fix per commit. Never bundle unrelated fixes.

- A fix may span several files. Commit them together when the fix is incomplete without them.
- One file may contain several unrelated fixes. Split them into separate commits, staging only the relevant hunks.
- Every commit must leave the tree in a working state.

## Rewrite until it reaches main

Anything not yet on main is a draft.

- Correcting an earlier commit on the branch: `git commit --fixup=<sha>`.
- Never leave a plain commit that fixes another commit from the same branch. Use `--fixup`.
- Two commits belong together when they address the same issue, or when one repairs a fault the other introduced.
- The change, the test it broke, and the formatting of that test are one commit, not three.

Once a commit is on main the history is fixed. Corrections become new commits.

## Format

```
type(scope): subject

body
```

- `type`: `chore`, `fix`, `feat`, `doc`, `agent`.
- `scope`: a path. Need not be a valid path, but must be precise enough to match the target in a fuzzy finder.
  - single file: full path — `fix(credential_verifier/src/server/verify_endpoint/mod.rs):`
  - several files: common parent — `fix(credential_verifier/src/server):`
- `subject`: imperative, lowercase, no trailing period.

## Body

- State why. Give the failure or constraint that motivated the change.
- Paste the error when it identifies the bug.
- Do not restate the diff.
- Do not name a specific machine, distro, or personal environment. Describe the condition instead.

Example:

```
fix(credential_verifier/src/tests): initialize logging with log_init

`tracing_init` builds the OTLP gRPC exporter, which cannot start on the
current-thread runtime that `#[tokio::test]` creates, so every integration
test aborted before its first request:

  panicked: failed to export to OTLP endpoint http://localhost:4317

Call `log_init` in the tests, and keep `tracing_init` for the binary.
```
