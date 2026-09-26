---
name: code-comments
description: Use when writing, reviewing, or modifying source code comments and doc comments. Covers module docs, item docs, inline comments, and test comments.
applyTo: "**/*.rs"
---

# Code comments

This skill governs comments in source code: module docs (`//!`), item docs (`///`), inline
comments (`//`), and test comments.

It refines the comment rule in the [rust skill](../rust/SKILL.md): a doc comment states the
contract of an item, an inline comment explains a step.

## Audience

Write for an experienced programmer who can read the code. The reader has the code in front of
them. Do not describe what the code says. State what the code cannot say by itself: the intent,
the constraints, and the consequences.

## Language

Use simplified technical English.

- Short, direct sentences. One idea per sentence.
- Active voice, present tense.
- A precise and consistent vocabulary. No idioms, metaphors, or buzzwords.
- Sentence case for headings.

## What to comment

- The intent: why the item or the step exists.
- Non-obvious constraints: invariants, lock order, lifetimes, ownership, units, encodings, and
  edge cases.
- Non-obvious consequences: side effects, cost, failure modes, and interference between parts.
- The reason for a choice that looks wrong but is deliberate.

## What not to comment

- Anything the code already states. Never translate a line into prose.
- Names and types that already carry the meaning.
- Obvious control flow.
- A restatement of the signature in words.

## Doc comments

- `//!` for the module and `///` for the item.
- Document every public item. Document a private item when its contract is not clear from the
  name and the signature.
- Keep the first line a single sentence. It appears in lists and in hover text.
- Use `# Errors` on a public function that returns `Result`, and `# Panics` when it can panic.
- Link related items with intra-doc links, for example [`CredentialIssuer::generate`].
- Keep the `rustdoc` build free of warnings.

## Inline comments

- Use `//` for a step whose reason is not visible in the code.
- Put the comment on the line above the code it explains.
- Keep it to one or two lines. When it needs more, extract a helper and document the helper.
- State the why, never the what.

## Test comments

State what the test demonstrates functionally, in one or two sentences. Describe the behaviour,
not the mechanics. Do not list the assertions.

```rust
/// A presentation whose nonce does not match the stored transaction is rejected.
#[test]
fn presentation_with_mismatched_nonce_is_rejected() {
```

## Examples

Restates the code:

```rust
// Add one to the counter.
counter += 1;
```

States the intent:

```rust
// The device signature binds to the SessionTranscript, so it must be rebuilt here.
build_openid4vp_session_transcript(response_uri, nonce)
```

Restates the signature:

```rust
/// Decodes the mDoc presentation.
pub fn decode_mdoc_presentation(encoded: &str) -> Result<DecodedMdoc> {
```

States the contract:

```rust
/// Decodes an mDoc presentation without verifying any signature.
///
/// # Errors
/// Returns [`CredentialError::Cbor`] if the CBOR payload is malformed.
pub fn decode_mdoc_presentation(encoded: &str) -> Result<DecodedMdoc> {
```
