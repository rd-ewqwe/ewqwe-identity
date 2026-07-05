//! X.509 PKI helpers — build self-signed CA and issuer leaf certificates.
//!
//! All certificates use EC P-256 keys and SHA-256 signatures.  Validity is
//! one year from the moment of generation.

use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{
        X509, X509Builder, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
};

use crate::error::CredentialResult;

/// Build a self-signed CA certificate from `ca_key`.
pub fn build_ca_cert(ca_key: &PKey<Private>) -> CredentialResult<X509> {
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let serial_bn = BigNum::from_u32(1)?;
    let serial_num = Asn1Integer::from_bn(&serial_bn)?;
    b.set_serial_number(&serial_num)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "ewQwe Credential CA")?;
    name.append_entry_by_text("O", "ewQwe")?;
    let name = name.build();
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?; // self-signed

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    b.set_pubkey(ca_key)?;

    b.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    b.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    b.sign(ca_key, MessageDigest::sha256())?;
    Ok(b.build())
}

/// Build an issuer leaf certificate signed by `ca_key` / `ca_cert`.
pub fn build_issuer_cert(
    ca_key: &PKey<Private>,
    ca_cert: &X509,
    issuer_key: &PKey<Private>,
) -> CredentialResult<X509> {
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let serial_bn = BigNum::from_u32(2)?;
    let serial_num = Asn1Integer::from_bn(&serial_bn)?;
    b.set_serial_number(&serial_num)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "ewQwe Credential Issuer")?;
    name.append_entry_by_text("O", "ewQwe")?;
    let name = name.build();
    b.set_subject_name(&name)?;
    b.set_issuer_name(ca_cert.subject_name())?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    b.set_pubkey(issuer_key)?;

    b.append_extension(BasicConstraints::new().build()?)?;

    b.sign(ca_key, MessageDigest::sha256())?;
    Ok(b.build())
}
