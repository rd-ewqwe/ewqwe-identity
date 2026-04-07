//! In-process `VerifierCredentialVerifier` implementation for the Verifier App QR flow.
//!
//! `QrCredentialVerifierImpl` adapts the `credential_verifier` verification
//! pipeline to the [`ewqwe_verifier_app::VerifierCredentialVerifier`] trait.
//! It is registered as `web::Data<Arc<dyn VerifierCredentialVerifier>>` on the
//! actix-web app when the Verifier App is enabled, allowing the
//! `qr_status` route handler to run full credential verification in-process
//! without a round-trip to the `/ewqwe_api/verify` HTTP endpoint.

use std::sync::Arc;

use ewqwe_openid4vp::OpenID4VPService;
use ewqwe_verifier_app::{QrVerifyResult, VerifierCredentialVerifier};
use openssl::x509::X509;

use crate::{
    journal::DynJournalStore,
    server::verify_endpoint::verify_vp_token_for_qr,
};

/// Adapts `credential_verifier`'s `verify_vp_token_for_qr` to the
/// [`VerifierCredentialVerifier`] interface expected by `ewqwe_verifier_app`.
pub(crate) struct QrCredentialVerifierImpl {
    pub service: Arc<OpenID4VPService>,
    pub trusted_cas: Arc<Vec<X509>>,
    pub journal: Option<Arc<DynJournalStore>>,
}

#[async_trait::async_trait]
impl VerifierCredentialVerifier for QrCredentialVerifierImpl {
    async fn verify_qr_presentation(
        &self,
        vp_token: &str,
        state: &str,
        username: &str,
    ) -> Result<QrVerifyResult, String> {
        let journal_ref = self.journal.as_deref();
        match verify_vp_token_for_qr(vp_token, state, username, &self.service, &self.trusted_cas, journal_ref).await {
            Ok(outcome) => Ok(QrVerifyResult {
                success: outcome.success,
                doc_type: outcome.doc_type,
                errors: outcome.errors,
            }),
            Err(e) => Err(e.to_string()),
        }
    }
}
