//! SSL/TLS Authentication Middleware
//!
//! This module provides SSL/TLS client certificate-based authentication for the KMS server.
//! It extracts client certificates from TLS connections and validates them to authenticate
//! users based on the certificate's Common Name (CN) field.

use actix_service::{Service, Transform};
use actix_web::dev::Extensions;
use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
};
use futures::{
    Future,
    future::{Ready, ok},
};
use openssl::nid::Nid;
use openssl::x509::X509;
use std::any::Any;
use std::{
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use tracing::{debug, error, trace};

use crate::{AttError, AttResult, AuthenticatedUser};

/// The extension struct holding the peer certificate during the connection.
///
/// This struct stores the peer certificate in the request context.
#[derive(Debug, Clone)]
pub struct PeerCertificate {
    /// The peer certificate.
    pub cert: X509,
}

/// Extract the peer certificate from the TLS stream and pass it to middleware.
///
/// This function extracts the peer certificate from the TLS stream and passes it to the middleware.
/// The middleware can then use the peer certificate to authenticate the client.
pub fn extract_openssl_peer_certificate(cnx: &dyn Any, extensions: &mut Extensions) {
    // Check if the connection is a TLS connection.

    use std::net::TcpStream;
    if let Some(tls_socket) =
        cnx.downcast_ref::<actix_tls::accept::openssl::TlsStream<actix_web::rt::net::TcpStream>>()
    {
        if let Some(cert) = tls_socket.ssl().peer_certificate() {
            // The certificate is already an openssl::X509 object
            debug!(
                "Extracted peer certificate from TLS connection: {:?}",
                cert.subject_name()
            );
            extensions.insert(PeerCertificate { cert });
        } else {
            trace!("No peer certificate presented by client");
        }
    } else if let Some(cnx) = cnx.downcast_ref::<TcpStream>() {
        error!("Not a TLS connection: {:?}", cnx.peer_addr());
    } else {
        error!(
            "Unknown connection type (neither TLS nor clear text): {:#?}",
            cnx
        );
    }
}

/// The middleware that checks the peer certificate and extracts the common name.
///
/// This middleware checks and extracts the peer certificate for a common name.
/// The common name is then added to the request context so that it can be used by other middleware or handlers.
pub struct SslAuth;

impl<S, B> Transform<S, ServiceRequest> for SslAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = SslAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    /// Create a new instance of the `SslAuth` middleware.
    fn new_transform(&self, service: S) -> Self::Future {
        trace!("Ssl Authentication enabled");
        // Create a new instance of the `SslAuthMiddleware`.
        ok(SslAuthMiddleware {
            service: Rc::new(service),
        })
    }
}

pub struct SslAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SslAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    /// Poll the `SslAuthMiddleware` for readiness.
    fn poll_ready(&self, ctx: &mut Context) -> Poll<Result<(), Self::Error>> {
        // Poll the underlying service for readiness.
        self.service.poll_ready(ctx)
    }

    /// Call the `SslAuthMiddleware`.
    ///
    /// This function calls the underlying service and checks the peer certificate for a common name.
    /// If the common name is found, it is added to the request context so that it can be used by other middleware or handlers.
    /// If the common name is not found, an unauthorized response is returned.
    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Log that the middleware is being called.
        trace!("Ssl Authentication...");
        let service = self.service.clone();

        Box::pin(async move {
            if req.extensions().contains::<AuthenticatedUser>() {
                debug!("An authenticated user was already found; skipping SSL authentication",);
            } else {
                match ssl_auth(&req) {
                    Ok(Some(user)) => {
                        debug!(
                            "Client certificate authentication successful for user: {}",
                            user.username
                        );
                        req.extensions_mut().insert(user);
                    }
                    Ok(None) => {
                        debug!("No client certificate presented; continuing without user");
                    }
                    Err(e) => {
                        debug!("Client certificate authentication failed: {e:?}");
                        let response = req.into_response(
                            HttpResponse::Unauthorized()
                                .body(format!("Authentication failed: {}", e)),
                        );
                        return Ok(response.map_into_right_body());
                    }
                }
            }
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

fn ssl_auth(req: &ServiceRequest) -> AttResult<Option<AuthenticatedUser>> {
    let certificate = match req.conn_data::<PeerCertificate>() {
        Some(cert) => cert,
        None => {
            return Ok(None);
        }
    };

    let username = certificate
        .cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .ok_or_else(|| {
            AttError::Authentication("Client certificate has no common name".to_owned())
        })?
        .data()
        .as_utf8()
        .map_err(|e| {
            AttError::Authentication(format!("Client certificate common name is not UTF-8: {e}"))
        })?
        .to_string();

    trace!("Client certificate common name: {}", username);

    if username.ends_with('*') {
        return Err(AttError::Authentication(
            "Wildcard usernames are not permitted".to_owned(),
        ));
    }

    Ok(Some(AuthenticatedUser { username }))
}
