#!/bin/sh
# entrypoint.sh — ewQwe Credential Verifier container entrypoint
#
# Substitutes environment variables into the default config template and
# allows overriding the full config via a mounted file.
#
# Supported environment variables:
#   PUBLIC_ROOT_URL    — sets public_root_url (required in HTTP mode behind a reverse proxy)
#   HOST_PORT          — port to listen on (default: 9888 for HTTP, 4043 for TLS)
#   RUST_LOG           — logging filter, e.g. "info,ewqwe_credential_verifier_server=debug"
#   SESSION_SECRET     — hex-encoded session secret (auto-generated when not set)
#   SIGNER_CERT_PATH   — path to signer certificate PEM (default: built-in dev cert)
#   SIGNER_KEY_PATH    — path to signer private key PEM (default: built-in dev cert)
#   ANSI_COLORS        — set to "yes", "true" or "1" to enable ANSI colors in logs

set -e

CONFIG_SRC="/etc/ewqwe/credential-server.toml"
CONFIG_FINAL="${CONFIG_FINAL:-/tmp/credential-server.toml}"

# Allow full config override via mounted path.
if [ -f "/data/credential-server.toml" ]; then
    echo "Using mounted config from /data/credential-server.toml"
    CONFIG_SRC="/data/credential-server.toml"
elif [ -f "/etc/ewqwe/credential-server.toml" ]; then
    echo "Using default config from /etc/ewqwe/credential-server.toml"
fi

# Copy the source config so we can safely modify it.
cp "$CONFIG_SRC" "$CONFIG_FINAL"

# ── Environment variable substitution ─────────────────────────────────────

# Helper: uncomment a commented-out TOML key and set its value.
# Usage: set_key <key> <value>
# The value is written as a TOML string (quoted).
set_key() {
    _key="$1"
    _val="$2"
    if grep -q "^# ${_key} " "$CONFIG_FINAL"; then
        sed -i "s|^# ${_key} = .*|${_key} = \"${_val}\"|" "$CONFIG_FINAL"
    else
        sed -i "s|^${_key} = .*|${_key} = \"${_val}\"|" "$CONFIG_FINAL"
    fi
}

# Helper: set a TOML key that is NOT a string (integer, etc.)
set_key_raw() {
    _key="$1"
    _val="$2"
    sed -i "s|^${_key} = .*|${_key} = ${_val}|" "$CONFIG_FINAL"
}

if [ -n "${PUBLIC_ROOT_URL}" ]; then
    echo "Setting public_root_url to ${PUBLIC_ROOT_URL}"
    set_key "public_root_url" "${PUBLIC_ROOT_URL}"
fi

if [ -n "${HOST_PORT}" ]; then
    echo "Setting host_port to ${HOST_PORT}"
    set_key_raw "host_port" "${HOST_PORT}"
fi

if [ -n "${RUST_LOG}" ]; then
    echo "Setting rust_log to ${RUST_LOG}"
    set_key "rust_log" "${RUST_LOG}"
fi

if [ -n "${SESSION_SECRET}" ]; then
    echo "Setting session_secret from SESSION_SECRET environment variable"
    set_key "session_secret" "${SESSION_SECRET}"
fi

if [ -n "${SIGNER_CERT_PATH}" ]; then
    echo "Setting attestation_issuer_certificate to ${SIGNER_CERT_PATH}"
    set_key "attestation_issuer_certificate" "${SIGNER_CERT_PATH}"
fi

if [ -n "${SIGNER_KEY_PATH}" ]; then
    echo "Setting attestation_issuer_key to ${SIGNER_KEY_PATH}"
    set_key "attestation_issuer_key" "${SIGNER_KEY_PATH}"
fi

if [ -n "${ANSI_COLORS}" ]; then
    case "${ANSI_COLORS}" in
        [Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|1)
            echo "Enabling ANSI colors in logs"
            sed -i 's|^with_ansi_colors = .*|with_ansi_colors = true|' "$CONFIG_FINAL"
            ;;
        *)
            echo "Disabling ANSI colors in logs"
            sed -i 's|^with_ansi_colors = .*|with_ansi_colors = false|' "$CONFIG_FINAL"
            ;;
    esac
fi

# ── Start the credential verifier server ──────────────────────────────────

exec ewqwe_credential_verifier_server "$CONFIG_FINAL"
