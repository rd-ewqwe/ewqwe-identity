//! Attestation signing module for EU Age Verification.
//!
//! This module provides functionality to sign age verification attestations
//! in both JWT and CBOR formats, supporting RS256 (RSA) and ES256 (ECDSA P-256) algorithms.
//!
//! # Attestation Format
//!
//! The attestation confirms that the credential verifier has successfully verified
//! a Proof of Age from a wallet, and the subject meets the age requirement.
//!
//! # Supported Algorithms
//!
//! - **RS256**: RSA PKCS#1 signatures with SHA-256
//! - **ES256**: ECDSA signatures with P-256 curve and SHA-256
//!
//! # Example
//!
//! ```rust,ignore
//! use credential_verifier::attestation::{
//!     Attestation, JwtSigner, SigningAlgorithm, AttestationSigner
//! };
//!
//! let attestation = Attestation::new(
//!     "verifier.example.com",
//!     "rp.example.com",
//!     "session-123",
//!     true, // age requirement met
//! );
//!
//! let signer = JwtSigner::from_pem(SigningAlgorithm::ES256, &private_key_pem)?
//! let token = signer.sign(&attestation)?;
//! ```

mod attestation_struct;
mod cose_signer;
mod jwt_signer;
#[cfg(test)]
mod tests;

pub use attestation_struct::Attestation;
pub use cose_signer::{CoseSigner, CoseSigningAlgorithm, verify_cose_attestation};
pub use jwt_signer::{JwtSigner, SigningAlgorithm};

/// Common trait for attestation signers (JWT, CBOR, etc.)
pub trait AttestationSigner {
    /// Signs the attestation claims and returns the encoded attestation.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign(&self, claims: &Attestation) -> crate::AttResult<Vec<u8>>;

    /// Returns the algorithm identifier used by this signer.
    fn algorithm(&self) -> &str;
}

/// Converts a JPEG2000 portrait image to JPEG in the claims map, if present.
///
/// The France Identité wallet sends the portrait claim in JPEG2000 format,
/// which browsers cannot natively render. This function:
///
/// 1. Checks if the `portrait` key exists in the claims and is a non-empty string
/// 2. Decodes the base64url-encoded value
/// 3. Detects JPEG2000 via magic bytes (`\x00\x00\x00\x0c\x6a\x50\x20\x20`
///    or `\xff\x4f\xff\x51`)
/// 4. Decodes and re-encodes as JPEG using the `image` crate
/// 5. Replaces the original value with the JPEG-encoded base64
///
/// If the conversion fails (e.g. corrupt image data), a warning is logged
/// but the original portrait value is preserved — the request is not failed.
///
/// Returns the portrait claims map with JPEG2000 images converted to JPEG.
/// If the portrait is already a browser-compatible format (JPEG, PNG, GIF, WebP)
/// it is passed through unchanged. Unknown formats are also passed through.
pub fn convert_portrait_to_jpeg(
    mut claims: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    use base64::Engine as _;
    let portrait_value = match claims.get("portrait") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return claims,
    };

    let portrait_bytes =
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&portrait_value) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to decode portrait base64, leaving as-is"
                );
                return claims;
            }
        };

    // Check if the image is already browser-compatible (JPEG, PNG, GIF, WebP)
    // Pass through without conversion
    if is_browser_compatible_image(&portrait_bytes) {
        return claims;
    }

    // Not a standard browser format — check if it's JPEG2000 and try to convert
    if is_jpeg2000(&portrait_bytes) {
        match convert_jpeg2000_to_jpeg_bytes(&portrait_bytes) {
            Ok(jpeg_bytes) => {
                let jpeg_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&jpeg_bytes);
                claims.insert("portrait".to_string(), serde_json::Value::String(jpeg_b64));
                tracing::info!(
                    original_len = portrait_bytes.len(),
                    jpeg_len = jpeg_bytes.len(),
                    "converted JPEG2000 portrait to JPEG"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to convert JPEG2000 portrait to JPEG, leaving original"
                );
            }
        }
    } else {
        // Unknown format — log diagnostic info and leave as-is
        let preview_len = portrait_bytes.len().min(32);
        let hex_prefix: String = portrait_bytes[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        tracing::warn!(
            len = portrait_bytes.len(),
            hex_prefix = %hex_prefix,
            "portrait is not a browser-compatible or JPEG2000 format; leaving original value"
        );
    }

    claims
}

/// Decode JPEG2000 (JP2/J2K) bytes and re-encode as standard JPEG bytes.
///
/// Handles grayscale, RGB, CMYK, and ICC-based color spaces (always
/// producing a JPEG that browsers can render). Alpha channels are
/// stripped during conversion.
fn convert_jpeg2000_to_jpeg_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    use hayro_jpeg2000::ColorSpace;
    use image::codecs::jpeg::JpegEncoder;
    use image::{ExtendedColorType, ImageEncoder};

    let jp2 = hayro_jpeg2000::Image::new(data, &hayro_jpeg2000::DecodeSettings::default())
        .map_err(|e| format!("failed to parse JPEG2000 image: {e}"))?;

    let width = jp2.width();
    let height = jp2.height();
    let has_alpha = jp2.has_alpha();
    let color_channels = jp2.color_space().num_channels() as usize;
    let stride = if has_alpha {
        color_channels + 1
    } else {
        color_channels
    };

    let raw_pixels = jp2
        .decode()
        .map_err(|e| format!("failed to decode JPEG2000 image: {e}"))?;

    // Prepare pixel data and corresponding image color type for JPEG encoding.
    let (pixel_data, color_type): (Vec<u8>, ExtendedColorType) = match jp2.color_space() {
        ColorSpace::Gray => {
            let data = if has_alpha {
                raw_pixels.chunks(stride).map(|pix| pix[0]).collect()
            } else {
                raw_pixels
            };
            (data, ExtendedColorType::L8)
        }
        ColorSpace::RGB => {
            let data = if has_alpha {
                raw_pixels
                    .chunks(stride)
                    .flat_map(|pix| pix[..3].to_vec())
                    .collect()
            } else {
                raw_pixels
            };
            (data, ExtendedColorType::Rgb8)
        }
        ColorSpace::CMYK => {
            let rgb: Vec<u8> = if has_alpha {
                raw_pixels
                    .chunks(stride)
                    .flat_map(|cmyka| convert_cmyk_pixel(&cmyka[..4]))
                    .collect()
            } else {
                raw_pixels.chunks(4).flat_map(convert_cmyk_pixel).collect()
            };
            (rgb, ExtendedColorType::Rgb8)
        }
        _ => {
            // Unknown or ICC-based color space: extract usable RGB or grayscale data
            if color_channels >= 3 {
                let data = if has_alpha {
                    raw_pixels
                        .chunks(stride)
                        .flat_map(|pix| pix[..3].to_vec())
                        .collect()
                } else if color_channels > 3 {
                    raw_pixels
                        .chunks(color_channels)
                        .flat_map(|pix| pix[..3].to_vec())
                        .collect()
                } else {
                    raw_pixels
                };
                (data, ExtendedColorType::Rgb8)
            } else {
                let data = if has_alpha {
                    raw_pixels.chunks(stride).map(|pix| pix[0]).collect()
                } else {
                    raw_pixels
                };
                (data, ExtendedColorType::L8)
            }
        }
    };

    let mut jpeg_bytes = Vec::new();
    let encoder = JpegEncoder::new_with_quality(&mut jpeg_bytes, 85);
    encoder
        .write_image(&pixel_data, width, height, color_type)
        .map_err(|e| format!("failed to encode JPEG: {e}"))?;

    Ok(jpeg_bytes)
}

/// Convert a single CMYK pixel (4 bytes) to RGB (3 bytes).
/// Uses the standard formula: R=255*(1-C)*(1-K), G=255*(1-M)*(1-K), B=255*(1-Y)*(1-K).
fn convert_cmyk_pixel(cmyk: &[u8]) -> [u8; 3] {
    if cmyk.len() < 4 {
        return [0, 0, 0];
    }
    let c = f32::from(cmyk[0]) / 255.0;
    let m = f32::from(cmyk[1]) / 255.0;
    let y = f32::from(cmyk[2]) / 255.0;
    let k = f32::from(cmyk[3]) / 255.0;
    [
        (255.0 * (1.0 - c) * (1.0 - k)).round() as u8,
        (255.0 * (1.0 - m) * (1.0 - k)).round() as u8,
        (255.0 * (1.0 - y) * (1.0 - k)).round() as u8,
    ]
}

/// Check if the image data is JPEG2000 (SOC marker or JP2 signature).
fn is_jpeg2000(data: &[u8]) -> bool {
    // JPEG 2000 codestream (SOC marker): 0xFF 0x4F 0xFF 0x51
    if data.len() >= 4 && data[0..4] == [0xff, 0x4f, 0xff, 0x51] {
        return true;
    }
    // JP2 file format (signature box): 00 00 00 0C 6A 50 20 20
    if data.len() >= 8 && data[0..8] == [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20] {
        return true;
    }
    false
}

/// Check if the image data is already in a browser-compatible format.
fn is_browser_compatible_image(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    // JPEG: starts with \xff\xd8\xff
    if data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
        return true;
    }
    // PNG: \x89PNG\r\n\x1a\n
    if data.len() >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4e && data[3] == 0x47 {
        return true;
    }
    // GIF87a or GIF89a
    if data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x38 {
        return true;
    }
    // WebP: RIFF....WEBP (12 bytes)
    if data.len() >= 12
        && data[0] == 0x52
        && data[1] == 0x49
        && data[2] == 0x46
        && data[3] == 0x46
        && data[8] == 0x57
        && data[9] == 0x45
        && data[10] == 0x42
        && data[11] == 0x50
    {
        return true;
    }
    false
}
