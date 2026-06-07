#!/usr/bin/env bash
# =============================================================================
# ewQwe Identity — Developer Setup
# =============================================================================
#
# Clone both repos side-by-side so you can use [patch.crates-io] to test
# open-core changes in the enterprise workspace without publishing to crates.io.
#
# Usage:
#   ./scripts/dev-setup.sh
#
# After cloning, the directory structure looks like:
#
#   ~/projects/
#   ├── ewqwe-identity/          ← public repo (this one)
#   │   ├── crates/              ← open-core crate sources
#   │   └── ...
#   └── ewqwe-identity-enterprise/ ← private repo
#       ├── Cargo.toml           ← [patch.crates-io] enabled for local dev
#       └── crates/              ← enterprise crate sources
#
# =============================================================================
set -euo pipefail

PUBLIC_REPO="git@github.com:ewqwe-identity/ewqwe-identity.git"
PRIVATE_REPO="git@github.com:ewqwe-identity/ewqwe-identity-enterprise.git"
PARENT_DIR="${EWQWE_DEV_ROOT:-$HOME/projects}"

echo "=== ewQwe Identity Developer Setup ==="
echo "Parent directory: $PARENT_DIR"
echo ""

# ── Clone public repo ────────────────────────────────────────────────────
if [ -d "$PARENT_DIR/ewqwe-identity" ]; then
    echo "[SKIP] Public repo already exists at $PARENT_DIR/ewqwe-identity"
else
    echo "[CLONE] $PUBLIC_REPO"
    git clone "$PUBLIC_REPO" "$PARENT_DIR/ewqwe-identity"
fi

# ── Clone private repo ───────────────────────────────────────────────────
if [ -d "$PARENT_DIR/ewqwe-identity-enterprise" ]; then
    echo "[SKIP] Enterprise repo already exists at $PARENT_DIR/ewqwe-identity-enterprise"
else
    echo "[CLONE] $PRIVATE_REPO"
    git clone "$PRIVATE_REPO" "$PARENT_DIR/ewqwe-identity-enterprise"
fi

# ── Enable local patch overrides in the enterprise workspace ─────────────
ENTERPRISE_CARGO="$PARENT_DIR/ewqwe-identity-enterprise/Cargo.toml"
if grep -q '^\[patch.crates-io\]' "$ENTERPRISE_CARGO" 2>/dev/null; then
    echo "[OK] [patch.crates-io] is already active in enterprise Cargo.toml"
elif grep -q '^# \[patch.crates-io\]' "$ENTERPRISE_CARGO" 2>/dev/null; then
    echo "[PATCH] Enabling [patch.crates-io] for local development..."
    # Uncomment the patch section
    sed -i '' 's/^# \[patch.crates-io\]/[patch.crates-io]/' "$ENTERPRISE_CARGO"
    sed -i '' 's/^# ewqwe_/ewqwe_/g' "$ENTERPRISE_CARGO"
    echo "[OK] Done. Remember to comment it out before committing!"
else
    echo "[WARN] Could not find [patch.crates-io] section in enterprise Cargo.toml"
    echo "       Add it manually following open_core.md guidelines."
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Workflow:"
echo "  1. Edit open-core code in ~/projects/ewqwe-identity/crates/"
echo "  2. Build enterprise to verify:"
echo "       cd ~/projects/ewqwe-identity-enterprise && cargo check"
echo "  3. When ready, publish open-core crates:"
echo "       cd ~/projects/ewqwe-identity && cargo publish -p ewqwe_digital_credential"
echo "  4. Then disable patches and bump version in enterprise Cargo.toml"
