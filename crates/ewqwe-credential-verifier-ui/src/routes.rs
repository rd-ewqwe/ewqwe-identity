//! HTTP route handlers for the Verifier App.

use actix_identity::Identity;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use chrono::{DateTime, Utc};
use ewqwe_openid4vp::{
    InitTransactionRequest, OpenID4VPService, determine_profile, get_credential_type,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::{info, trace};
use uuid::Uuid;

use crate::{
    VerifierCredentialVerifier, VerifierJournalProvider, auth,
    config::VerifierUiConfig,
    db::{DynVerifierUiStore, VerifierAppStore},
    error::VerifierAppError,
    models::{
        AdminJournalQuery, BootstrapRequest, CreateUserRequest, I18nQuery, LoginRequest,
        NewUserRecord, UpdateUserRequest, UserChanges, UserResponse, VerifierAppRole,
    },
    qr_user_map::QrUserMap,
};

// ─── Error helpers ────────────────────────────────────────────────────────────

fn unauthorized() -> HttpResponse {
    HttpResponse::Unauthorized().json(json!({"error": "unauthorized"}))
}

fn not_found() -> HttpResponse {
    HttpResponse::NotFound().json(json!({"error": "not found"}))
}

fn conflict(msg: &str) -> HttpResponse {
    HttpResponse::Conflict().json(json!({"error": msg}))
}

fn bad_request(msg: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"error": msg}))
}

fn internal_error(msg: &str) -> HttpResponse {
    tracing::error!("verifier_ui internal error: {msg}");
    HttpResponse::InternalServerError().json(json!({"error": "internal server error"}))
}

/// Map a `VerifierAppError` to an `HttpResponse`.
fn store_error_response(e: VerifierAppError) -> HttpResponse {
    match e {
        VerifierAppError::NotFound => not_found(),
        VerifierAppError::Conflict(msg) => conflict(&msg),
        VerifierAppError::Storage(msg) => internal_error(&msg),
        VerifierAppError::Config(msg) => internal_error(&msg),
    }
}

// ─── Session helper ───────────────────────────────────────────────────────────

/// Extract the currently authenticated user from the identity cookie and the
/// store.  Returns `None` (→ 401) when the cookie is absent or stale.
async fn current_user(
    identity: Option<Identity>,
    store: &DynVerifierUiStore,
) -> Option<UserResponse> {
    trace!("Verifier App: session user lookup {}", identity.is_some());
    let id = identity?.id().ok()?;
    trace!(user_id = %id, "Verifier App: session user lookup");
    match store.get_user_by_id(&id).await {
        Ok(Some(user)) if user.is_active => Some(UserResponse::from(user)),
        _ => None,
    }
}

// ─── Setup ────────────────────────────────────────────────────────────────────

/// `POST /verifier_ui/api/setup/bootstrap`
///
/// One-time first-admin creation.  Fails with `409 Conflict` after the first
/// successful call.
pub async fn bootstrap(
    req: HttpRequest,
    store: web::Data<Arc<DynVerifierUiStore>>,
    body: web::Json<BootstrapRequest>,
) -> HttpResponse {
    // Guard: only allowed before any admin user exists.
    match store.user_count().await {
        Ok(0) => {}
        Ok(_) => return conflict("bootstrap already completed"),
        Err(e) => return store_error_response(e),
    }

    // Basic input validation.
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return bad_request("valid email required");
    }
    if body.password.len() < 12 {
        return bad_request("password must be at least 12 characters");
    }

    let password = body.password.clone();
    let hash = match web::block(move || auth::hash_password(&password)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return internal_error(&e.to_string()),
        Err(_) => return internal_error("password hashing failed"),
    };

    let record = NewUserRecord {
        id: Uuid::new_v4().to_string(),
        email: email.clone(),
        password_hash: Some(hash),
        first_name: body.first_name.clone(),
        last_name: body.last_name.clone(),
        role: VerifierAppRole::Admin,
        is_superadmin: true,
        allowed_credential_types: Vec::new(),
    };

    let user = match store.create_user(&record).await {
        Ok(u) => u,
        Err(e) => return store_error_response(e),
    };

    // Automatically log in the newly created superadmin.
    if let Err(e) = Identity::login(&req.extensions(), user.id.clone()) {
        tracing::warn!("Failed to create identity session after bootstrap: {e}");
    }

    tracing::info!(email = %email, "Verifier App: superadmin created via bootstrap");
    HttpResponse::Created().json(UserResponse::from(user))
}

// ─── Authentication ───────────────────────────────────────────────────────────

/// `POST /verifier_ui/api/auth/login`
pub async fn login(
    req: HttpRequest,
    store: web::Data<Arc<DynVerifierUiStore>>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    let email = body.email.trim().to_lowercase();

    let user = match store.get_user_by_email(&email).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            // Constant-time-ish: still hash a dummy value to avoid timing oracle.
            let _ = web::block(|| auth::hash_password("dummy_constant_time")).await;
            return unauthorized();
        }
        Err(e) => return store_error_response(e),
    };

    if !user.is_active {
        let _ = web::block(|| auth::hash_password("dummy_constant_time")).await;
        return unauthorized();
    }

    let hash = match &user.password_hash {
        Some(h) => h.clone(),
        None => return unauthorized(), // OIDC-only account
    };

    let password = body.password.clone();
    let valid = match web::block(move || auth::verify_password(&password, &hash)).await {
        Ok(v) => v,
        Err(_) => return internal_error("password verification failed"),
    };

    if !valid {
        return unauthorized();
    }

    if let Err(e) = Identity::login(&req.extensions(), user.id.clone()) {
        tracing::error!("Failed to create identity session for {email}: {e}");
        return internal_error("session creation failed");
    }

    tracing::info!(email = %email, "Verifier App: user logged in");
    HttpResponse::Ok().json(UserResponse::from(user))
}

/// `POST /verifier_ui/api/auth/logout`
pub async fn logout(identity: Option<Identity>) -> HttpResponse {
    if let Some(id) = identity {
        id.logout();
    }
    HttpResponse::Ok().json(json!({"status": "logged out"}))
}

/// `GET /verifier_ui/api/auth/me`
pub async fn me(
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
) -> HttpResponse {
    match current_user(identity, &store).await {
        Some(user) => HttpResponse::Ok().json(user),
        None => unauthorized(),
    }
}

// ─── QR Code generation & status ─────────────────────────────────────────────

/// `POST /verifier_ui/api/qr/generate`
///
/// Initiates an OpenID4VP credential verification transaction and returns the
/// QR code data URL together with the transaction ID for status polling.
///
/// Accepts an optional `credential_type` in the JSON body: `"proof-of-age"`
/// (default), `"mdl"`, or `"national-id"`.  The profile (AnnexA / HAIP) is
/// determined automatically from the credential type.
pub async fn generate_qr(
    req: HttpRequest,
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
    service: web::Data<Arc<OpenID4VPService>>,
    qr_map: web::Data<Arc<QrUserMap>>,
    config: web::Data<Arc<VerifierUiConfig>>,
    body: web::Json<crate::models::GenerateQrRequest>,
) -> HttpResponse {
    trace!("Verifier App: QR generation requested");

    let user = match current_user(identity, &store).await {
        Some(u) => u,
        None => return unauthorized(),
    };

    // Resolve credential type (default: proof-of-age).
    let credential_type = body.credential_type.as_deref().unwrap_or("proof-of-age");

    // Validate the credential type is known.
    if get_credential_type(credential_type).is_none() {
        return bad_request(&format!("unknown credential type: {credential_type}"));
    }

    // ── Permission check ───────────────────────────────────────────────
    // First check the server-level allowed types, then the user-level list.
    if !config.allowed_credential_types.is_empty()
        && !config
            .allowed_credential_types
            .iter()
            .any(|t| t == credential_type)
    {
        return bad_request(&format!(
            "credential type '{credential_type}' is not enabled on this server"
        ));
    }
    if !user.allowed_credential_types.is_empty()
        && !user
            .allowed_credential_types
            .iter()
            .any(|t| t == credential_type)
    {
        return HttpResponse::Forbidden().json(json!({
            "error": format!("you are not allowed to request '{credential_type}' credentials")
        }));
    }

    info!(user_id = %user.id, credential_type = %credential_type,
          "Verifier App: generating QR transaction");

    // Build the public URL the wallet will use for `response_uri`.
    let public_url = config.qr_code_callback_url.clone().unwrap_or_else(|| {
        let conn = req.connection_info();
        format!("{}://{}", conn.scheme(), conn.host())
    });

    // Determine profile from credential type.
    let profile = determine_profile(Some(credential_type), None);

    // Build DCQL query: use specified claims if provided, otherwise use defaults.
    let dcql_query = if body.claims.is_empty() {
        None // let init_transaction use the default DCQL for the credential type
    } else {
        Some(ewqwe_openid4vp::build_dcql_for_credential_type_with_claims(
            credential_type,
            &body.claims,
        ))
    };

    let init_req = InitTransactionRequest {
        profile: Some(profile),
        dcql_query, // use custom DCQL with selected claims, or None for defaults
        nonce: None,
        state: None,
        client_metadata: None,
        credential_type: Some(credential_type.to_string()),
        transaction_data: None,
    };

    let resp = match service.init_transaction(init_req, &public_url).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Verifier App: init_transaction failed: {e}");
            return internal_error("failed to create verification transaction");
        }
    };

    // Record which user started this transaction so we can attribute the
    // journal entry later and enforce polling ownership.
    let expires_at = Utc::now() + chrono::Duration::seconds(resp.expires_in.max(0));
    qr_map.insert(
        resp.transaction_id.clone(),
        user.id.clone(),
        user.email.clone(),
        expires_at,
    );

    tracing::info!(
        user_id = %user.id,
        transaction_id = %resp.transaction_id,
        credential_type = %credential_type,
        "Verifier App: QR transaction created"
    );

    HttpResponse::Ok().json(json!({
        "transaction_id": resp.transaction_id,
        "qr_code_data_url": resp.qr_code_data_url,
        "authorization_request_uri": resp.authorization_request_uri,
        "expires_in": resp.expires_in,
    }))
}

/// `GET /verifier_ui/api/qr/{id}/status`
///
/// Polls the verification status for a transaction created by this user.
/// Returns `403 Forbidden` if the transaction belongs to a different user.
pub async fn qr_status(
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
    service: web::Data<Arc<OpenID4VPService>>,
    qr_map: web::Data<Arc<QrUserMap>>,
    verifier: Option<web::Data<Arc<dyn VerifierCredentialVerifier>>>,
    path: web::Path<String>,
) -> HttpResponse {
    let user = match current_user(identity, &store).await {
        Some(u) => u,
        None => return unauthorized(),
    };

    let transaction_id = path.into_inner();

    // Verify ownership: only admin or the initiating user may poll.
    let owner_entry = qr_map.get(&transaction_id);
    let is_owner = owner_entry
        .as_ref()
        .map(|e| e.user_id == user.id)
        .unwrap_or(false);
    let is_admin = user.role == VerifierAppRole::Admin;

    // Allow if the user owns the transaction, or if they are an admin.
    // Also allow if ownership is unknown (entry expired from map) — the
    // OpenID4VP service will return "expired" which is safe to expose.
    if !is_owner && !is_admin && owner_entry.is_some() {
        return HttpResponse::Forbidden().json(json!({"error": "not your transaction"}));
    }

    match service.get_transaction_status(&transaction_id).await {
        Ok(status) => {
            use ewqwe_openid4vp::TransactionStatus;

            // When the wallet has posted a VP token, verify the credential inline
            // (if a verifier is wired in) so the frontend receives a final result.
            if status.status == TransactionStatus::Received {
                if let Some(auth_resp) = status.authorization_response.as_ref() {
                    if let Some(verifier) = verifier.as_ref() {
                        let owner_email = owner_entry
                            .as_ref()
                            .map(|e| e.user_email.as_str())
                            .unwrap_or("system");
                        match verifier
                            .verify_qr_presentation(
                                &auth_resp.vp_token,
                                &auth_resp.state,
                                owner_email,
                            )
                            .await
                        {
                            Ok(result) if result.success => {
                                tracing::info!(
                                    transaction_id = %transaction_id,
                                    doc_type = %result.doc_type,
                                    "QR verification succeeded"
                                );
                                // Transition state to Verified so subsequent polls
                                // return "verified" without re-running verification.
                                if let Err(e) =
                                    service.mark_transaction_verified(&transaction_id).await
                                {
                                    tracing::warn!(
                                        transaction_id = %transaction_id,
                                        error = %e,
                                        "failed to mark transaction verified; subsequent polls will re-verify"
                                    );
                                }
                                HttpResponse::Ok().json(json!({
                                    "status": "verified",
                                    "age_over_18": result.age_over_18,
                                    "verified_claims": result.verified_claims,
                                }))
                            }
                            Ok(result) => {
                                tracing::warn!(
                                    transaction_id = %transaction_id,
                                    errors = ?result.errors,
                                    "QR verification failed"
                                );
                                HttpResponse::Ok().json(json!({
                                    "status": "failed",
                                    "errors": result.errors,
                                }))
                            }
                            Err(e) => {
                                tracing::error!(
                                    transaction_id = %transaction_id,
                                    error = %e,
                                    "QR verification error"
                                );
                                HttpResponse::Ok().json(json!({
                                    "status": "failed",
                                    "errors": [e],
                                }))
                            }
                        }
                    } else {
                        // No verifier plugged in — return "received" so the RP can
                        // verify externally via POST /ewqwe_api/verify.
                        HttpResponse::Ok().json(json!({
                            "status": status.status,
                            "expires_in": status.expires_in,
                        }))
                    }
                } else {
                    HttpResponse::Ok().json(json!({
                        "status": status.status,
                        "expires_in": status.expires_in,
                    }))
                }
            } else {
                HttpResponse::Ok().json(json!({
                    "status": status.status,
                    "expires_in": status.expires_in,
                }))
            }
        }
        Err(e) => {
            tracing::warn!(transaction_id = %transaction_id, "QR status error: {e}");
            HttpResponse::NotFound().json(json!({"error": "transaction not found"}))
        }
    }
}

// ─── Admin: user management ───────────────────────────────────────────────────

/// Require the calling user to be an active admin, or return `403 Forbidden`.
async fn require_admin(
    identity: Option<Identity>,
    store: &DynVerifierUiStore,
) -> Result<UserResponse, HttpResponse> {
    match current_user(identity, store).await {
        Some(user) if user.role == VerifierAppRole::Admin => Ok(user),
        Some(_) => Err(HttpResponse::Forbidden().json(json!({"error": "admin role required"}))),
        None => Err(unauthorized()),
    }
}

/// `GET /verifier_ui/api/admin/users`
pub async fn list_users(
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
) -> HttpResponse {
    if let Err(resp) = require_admin(identity, &store).await {
        return resp;
    }
    match store.list_users(false).await {
        Ok(users) => {
            let dtos: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();
            HttpResponse::Ok().json(dtos)
        }
        Err(e) => store_error_response(e),
    }
}

/// `POST /verifier_ui/api/admin/users`
pub async fn create_user(
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
    body: web::Json<CreateUserRequest>,
) -> HttpResponse {
    if let Err(resp) = require_admin(identity, &store).await {
        return resp;
    }

    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return bad_request("valid email required");
    }
    if body.password.len() < 12 {
        return bad_request("password must be at least 12 characters");
    }

    let password = body.password.clone();
    let hash = match web::block(move || auth::hash_password(&password)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return internal_error(&e.to_string()),
        Err(_) => return internal_error("password hashing failed"),
    };

    let record = NewUserRecord {
        id: Uuid::new_v4().to_string(),
        email,
        password_hash: Some(hash),
        first_name: body.first_name.clone(),
        last_name: body.last_name.clone(),
        role: body.role.clone().unwrap_or_default(),
        is_superadmin: false,
        allowed_credential_types: body.allowed_credential_types.clone().unwrap_or_default(),
    };

    match store.create_user(&record).await {
        Ok(user) => HttpResponse::Created().json(UserResponse::from(user)),
        Err(e) => store_error_response(e),
    }
}

/// `PUT /verifier_ui/api/admin/users/{id}`
pub async fn update_user(
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
    path: web::Path<String>,
    body: web::Json<UpdateUserRequest>,
) -> HttpResponse {
    if let Err(resp) = require_admin(identity, &store).await {
        return resp;
    }

    let user_id = path.into_inner();

    // If a new password is provided, hash it before storing.
    let password_hash = if let Some(ref pwd) = body.new_password {
        if pwd.len() < 12 {
            return bad_request("password must be at least 12 characters");
        }
        let pwd = pwd.clone();
        match web::block(move || auth::hash_password(&pwd)).await {
            Ok(Ok(h)) => Some(h),
            Ok(Err(e)) => return internal_error(&e.to_string()),
            Err(_) => return internal_error("password hashing failed"),
        }
    } else {
        None
    };

    let changes = UserChanges {
        first_name: body.first_name.clone(),
        last_name: body.last_name.clone(),
        role: body.role.clone(),
        is_active: body.is_active,
        password_hash,
        allowed_credential_types: body.allowed_credential_types.clone(),
    };

    match store.update_user(&user_id, &changes).await {
        Ok(user) => HttpResponse::Ok().json(UserResponse::from(user)),
        Err(e) => store_error_response(e),
    }
}

/// `DELETE /verifier_ui/api/admin/users/{id}`
pub async fn delete_user(
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
    path: web::Path<String>,
) -> HttpResponse {
    if let Err(resp) = require_admin(identity, &store).await {
        return resp;
    }
    let user_id = path.into_inner();
    match store.delete_user(&user_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => store_error_response(e),
    }
}

// ─── Admin: journal ───────────────────────────────────────────────────────────

/// `GET /verifier_ui/api/admin/journal`
pub async fn admin_journal(
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
    journal: Option<web::Data<Arc<dyn VerifierJournalProvider>>>,
    query: web::Query<AdminJournalQuery>,
) -> HttpResponse {
    if let Err(resp) = require_admin(identity, &store).await {
        return resp;
    }
    let journal = match journal {
        Some(j) => j,
        None => {
            return HttpResponse::ServiceUnavailable()
                .json(json!({"error": "journal not enabled"}));
        }
    };
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);
    // Parse optional ISO 8601 date strings into DateTime<Utc> for the store query.
    let date_from: Option<DateTime<Utc>> = query
        .date_from
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let date_to: Option<DateTime<Utc>> = query
        .date_to
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    match journal
        .list_verifier_entries(query.user_id.as_deref(), date_from, date_to, limit, offset)
        .await
    {
        Ok(entries) => HttpResponse::Ok().json(entries),
        Err(e) => internal_error(&e),
    }
}

// ─── Internationalisation ─────────────────────────────────────────────────────

static I18N_EN: &[u8] = include_bytes!("static/i18n/en.json");
static I18N_DE: &[u8] = include_bytes!("static/i18n/de.json");
static I18N_FR: &[u8] = include_bytes!("static/i18n/fr.json");
static I18N_IT: &[u8] = include_bytes!("static/i18n/it.json");
static I18N_ES: &[u8] = include_bytes!("static/i18n/es.json");
static I18N_SV: &[u8] = include_bytes!("static/i18n/sv.json");
static I18N_PL: &[u8] = include_bytes!("static/i18n/pl.json");
static I18N_CS: &[u8] = include_bytes!("static/i18n/cs.json");
static I18N_HR: &[u8] = include_bytes!("static/i18n/hr.json");

/// `GET /api/v1/i18n?lang=<code>`
pub async fn get_i18n(query: web::Query<I18nQuery>) -> HttpResponse {
    let (bytes, lang) = match query.lang.as_deref().unwrap_or("en") {
        "de" => (I18N_DE, "de"),
        "fr" => (I18N_FR, "fr"),
        "it" => (I18N_IT, "it"),
        "es" => (I18N_ES, "es"),
        "sv" => (I18N_SV, "sv"),
        "pl" => (I18N_PL, "pl"),
        "cs" => (I18N_CS, "cs"),
        "hr" => (I18N_HR, "hr"),
        _ => (I18N_EN, "en"),
    };
    HttpResponse::Ok()
        .content_type("application/json; charset=utf-8")
        .insert_header(("Content-Language", lang))
        .body(bytes)
}

// ─── Setup status ─────────────────────────────────────────────────────────────

/// `GET /verifier_ui/api/setup/status`
///
/// Public endpoint. Returns `{"bootstrapped": true}` once the first admin
/// account exists, `{"bootstrapped": false}` before bootstrap.
pub async fn setup_status(store: web::Data<Arc<DynVerifierUiStore>>) -> HttpResponse {
    match store.user_count().await {
        Ok(count) => HttpResponse::Ok().json(json!({ "bootstrapped": count > 0 })),
        Err(e) => internal_error(&e.to_string()),
    }
}

// ─── App settings ─────────────────────────────────────────────────────────────

/// `GET /verifier_ui/api/settings`
///
/// Public endpoint. Returns the current app display settings.
pub async fn get_settings(
    store: web::Data<Arc<DynVerifierUiStore>>,
    config: web::Data<Arc<VerifierUiConfig>>,
) -> HttpResponse {
    // DB overrides config defaults.
    let app_name = match store.get_setting("app_name").await {
        Ok(Some(v)) => v,
        _ => config
            .app_name
            .clone()
            .unwrap_or_else(|| "Verifier App".to_string()),
    };
    let logo_url = match store.get_setting("logo_url").await {
        Ok(v) => v.or_else(|| config.logo_url.clone()),
        Err(_) => config.logo_url.clone(),
    };
    HttpResponse::Ok().json(json!({
        "app_name": app_name,
        "logo_url": logo_url,
        "allowed_credential_types": config.allowed_credential_types,
    }))
}

/// Body for `PUT /verifier_ui/api/admin/settings`.
#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub app_name: Option<String>,
    pub logo_url: Option<String>,
}

/// `PUT /verifier_ui/api/admin/settings`
///
/// Admin-only. Persists app display settings to the database.
pub async fn update_settings(
    identity: Option<Identity>,
    store: web::Data<Arc<DynVerifierUiStore>>,
    body: web::Json<UpdateSettingsRequest>,
) -> HttpResponse {
    if let Err(resp) = require_admin(identity, &store).await {
        return resp;
    }
    if let Some(ref name) = body.app_name {
        let name = name.trim().to_string();
        if let Err(e) = store.set_setting("app_name", &name).await {
            return internal_error(&e.to_string());
        }
    }
    if let Some(ref url) = body.logo_url
        && let Err(e) = store.set_setting("logo_url", url).await
    {
        return internal_error(&e.to_string());
    }
    HttpResponse::Ok().json(json!({"status": "settings updated"}))
}
