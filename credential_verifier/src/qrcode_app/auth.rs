//! Password hashing and verification helpers for the QR Code APP.
//!
//! Uses Argon2id (RFC 9106 recommended variant) via the `argon2` crate.

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::qrcode_app::error::{QrcodeAppError, QrcodeAppResult};

/// Hash a plaintext password using Argon2id with a random salt.
///
/// Returns the PHC-formatted hash string suitable for storage.
pub fn hash_password(password: &str) -> QrcodeAppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default(); // Argon2id, recommended parameters
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| QrcodeAppError::Config(format!("Password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored Argon2 PHC hash string.
///
/// Returns `true` if the password matches, `false` otherwise.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}
