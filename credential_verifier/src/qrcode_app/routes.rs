//! HTTP route handlers for the QR Code APP.

use std::sync::Arc;

use actix_identity::Identity;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use chrono::Utc;
use ewqwe_openid4vp::{InitTransactionRequest, OpenID4VPService, ProfileId};
use serde_json::json;
use uuid::Uuid;

use crate::{
    journal::{DynJournalStore, JournalStore},
    qrcode_app::{
        auth,
        db::{DynQrcodeAppStore, QrcodeAppStore},
        error::QrcodeAppError,
        models::{
            AdminJournalQuery, BootstrapRequest, CreateUserRequest, LoginRequest, NewUserRecord,
            QrcodeAppRole, UpdateUserRequest, UserChanges, UserResponse,
        },
        qr_user_map::QrUserMap,
    },
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
    tracing::error!("qrcode_app internal error: {msg}");
    HttpResponse::InternalServerError().json(json!({"error": "internal server error"}))
}

fn not_implemented() -> HttpResponse {
    HttpResponse::NotImplemented().json(json!({
        "error": "not implemented",
        "message": "This endpoint is not yet available."
    }))
}

/// Map a `QrcodeAppError` to an `HttpResponse`.
fn store_error_response(e: QrcodeAppError) -> HttpResponse {
    match e {
        QrcodeAppError::NotFound => not_found(),
        QrcodeAppError::Conflict(msg) => conflict(&msg),
        QrcodeAppError::Storage(msg) => internal_error(&msg),
        QrcodeAppError::Config(msg) => internal_error(&msg),
    }
}

// ─── Session helper ───────────────────────────────────────────────────────────

/// Extract the currently authenticated user from the identity cookie and the
/// store.  Returns `None` (→ 401) when the cookie is absent or stale.
async fn current_user(
    identity: Option<Identity>,
    store: &DynQrcodeAppStore,
) -> Option<UserResponse> {
    let id = identity?.id().ok()?;
    match store.get_user_by_id(&id).await {
        Ok(Some(user)) if user.is_active => Some(UserResponse::from(user)),
        _ => None,
    }
}

// ─── Setup ────────────────────────────────────────────────────────────────────

/// `POST /qrcode_app/api/setup/bootstrap`
///
/// One-time first-admin creation.  Fails with `409 Conflict` after the first
/// successful call.
pub async fn bootstrap(
    req: HttpRequest,
    store: web::Data<Arc<DynQrcodeAppStore>>,
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
        role: QrcodeAppRole::Admin,
        is_superadmin: true,
    };

    let user = match store.create_user(&record).await {
        Ok(u) => u,
        Err(e) => return store_error_response(e),
    };

    // Automatically log in the newly created superadmin.
    if let Err(e) = Identity::login(&req.extensions(), user.id.clone()) {
        tracing::warn!("Failed to create identity session after bootstrap: {e}");
    }

    tracing::info!(email = %email, "QR Code APP: superadmin created via bootstrap");
    HttpResponse::Created().json(UserResponse::from(user))
}

// ─── Authentication ───────────────────────────────────────────────────────────

/// `POST /qrcode_app/api/auth/login`
pub async fn login(
    req: HttpRequest,
    store: web::Data<Arc<DynQrcodeAppStore>>,
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

    tracing::info!(email = %email, "QR Code APP: user logged in");
    HttpResponse::Ok().json(UserResponse::from(user))
}

/// `POST /qrcode_app/api/auth/logout`
pub async fn logout(identity: Option<Identity>) -> HttpResponse {
    if let Some(id) = identity {
        id.logout();
    }
    HttpResponse::Ok().json(json!({"status": "logged out"}))
}

/// `GET /qrcode_app/api/auth/me`
pub async fn me(
    identity: Option<Identity>,
    store: web::Data<Arc<DynQrcodeAppStore>>,
) -> HttpResponse {
    match current_user(identity, &store).await {
        Some(user) => HttpResponse::Ok().json(user),
        None => unauthorized(),
    }
}

// ─── QR Code generation & status ─────────────────────────────────────────────

/// `POST /qrcode_app/api/qr/generate`
///
/// Initiates an Annex-A OpenID4VP age-verification transaction and returns the
/// QR code data URL together with the transaction ID for status polling.
pub async fn generate_qr(
    req: HttpRequest,
    identity: Option<Identity>,
    store: web::Data<Arc<DynQrcodeAppStore>>,
    service: web::Data<Arc<OpenID4VPService>>,
    qr_map: web::Data<Arc<QrUserMap>>,
) -> HttpResponse {
    let user = match current_user(identity, &store).await {
        Some(u) => u,
        None => return unauthorized(),
    };

    // Build the public URL the wallet will use for `response_uri`.
    // We derive it from the incoming request so no extra config is required.
    let public_url = {
        let conn = req.connection_info();
        format!("{}://{}", conn.scheme(), conn.host())
    };

    let init_req = InitTransactionRequest {
        public_url,
        profile: Some(ProfileId::AnnexA),
        dcql_query: None, // use default age-verification DCQL
        nonce: None,
        state: None,
        client_metadata: None,
        credential_type: None,
        transaction_data: None,
    };

    let resp = match service.init_transaction(init_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("QR Code APP: init_transaction failed: {e}");
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
        "QR Code APP: QR transaction created"
    );

    HttpResponse::Ok().json(json!({
        "transaction_id": resp.transaction_id,
        "qr_code_data_url": resp.qr_code_data_url,
        "authorization_request_uri": resp.authorization_request_uri,
        "expires_in": resp.expires_in,
    }))
}

/// `GET /qrcode_app/api/qr/{id}/status`
///
/// Polls the verification status for a transaction created by this user.
/// Returns `403 Forbidden` if the transaction belongs to a different user.
pub async fn qr_status(
    identity: Option<Identity>,
    store: web::Data<Arc<DynQrcodeAppStore>>,
    service: web::Data<Arc<OpenID4VPService>>,
    qr_map: web::Data<Arc<QrUserMap>>,
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
    let is_admin = user.role == QrcodeAppRole::Admin;

    // Allow if the user owns the transaction, or if they are an admin.
    // Also allow if ownership is unknown (entry expired from map) — the
    // OpenID4VP service will return "expired" which is safe to expose.
    if !is_owner && !is_admin && owner_entry.is_some() {
        return HttpResponse::Forbidden().json(json!({"error": "not your transaction"}));
    }

    match service.get_transaction_status(&transaction_id).await {
        Ok(status) => HttpResponse::Ok().json(json!({
            "status": status.status,
            "expires_in": status.expires_in,
        })),
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
    store: &DynQrcodeAppStore,
) -> Result<UserResponse, HttpResponse> {
    match current_user(identity, store).await {
        Some(user) if user.role == QrcodeAppRole::Admin => Ok(user),
        Some(_) => Err(HttpResponse::Forbidden().json(json!({"error": "admin role required"}))),
        None => Err(unauthorized()),
    }
}

/// `GET /qrcode_app/api/admin/users`
pub async fn list_users(
    identity: Option<Identity>,
    store: web::Data<Arc<DynQrcodeAppStore>>,
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

/// `POST /qrcode_app/api/admin/users`
pub async fn create_user(
    identity: Option<Identity>,
    store: web::Data<Arc<DynQrcodeAppStore>>,
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
    };

    match store.create_user(&record).await {
        Ok(user) => HttpResponse::Created().json(UserResponse::from(user)),
        Err(e) => store_error_response(e),
    }
}

/// `PUT /qrcode_app/api/admin/users/{id}`
pub async fn update_user(
    identity: Option<Identity>,
    store: web::Data<Arc<DynQrcodeAppStore>>,
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
    };

    match store.update_user(&user_id, &changes).await {
        Ok(user) => HttpResponse::Ok().json(UserResponse::from(user)),
        Err(e) => store_error_response(e),
    }
}

/// `DELETE /qrcode_app/api/admin/users/{id}`
pub async fn delete_user(
    identity: Option<Identity>,
    store: web::Data<Arc<DynQrcodeAppStore>>,
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

/// `GET /qrcode_app/api/admin/journal`
pub async fn admin_journal(
    identity: Option<Identity>,
    store: web::Data<Arc<DynQrcodeAppStore>>,
    journal: Option<web::Data<Arc<DynJournalStore>>>,
    query: web::Query<AdminJournalQuery>,
) -> HttpResponse {
    if let Err(resp) = require_admin(identity, &store).await {
        return resp;
    }
    let journal = match journal {
        Some(j) => j,
        None => {
            return HttpResponse::ServiceUnavailable().json(json!({"error": "journal not enabled"}));
        }
    };
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);
    match journal
        .list_qrcode_app_entries(query.user_id.as_deref(), limit, offset)
        .await
    {
        Ok(entries) => HttpResponse::Ok().json(entries),
        Err(e) => internal_error(&e.to_string()),
    }
}

// ─── Internationalisation ─────────────────────────────────────────────────────

/// `GET /qrcode_app/api/i18n?lang=<code>`
pub async fn get_i18n() -> HttpResponse {
    not_implemented()
}
