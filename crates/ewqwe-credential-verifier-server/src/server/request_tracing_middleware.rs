//! Request tracing middleware — wraps every HTTP request in a tracing span.
//!
//! Logs every API call with method, path, authenticated user, and response
//! status at INFO level. Error responses (4xx/5xx) are additionally logged at
//! WARN / ERROR levels so they are always captured even when the handler
//! forgets to log them.
//!
//! # Structured fields (OTLP-compatible)
//!
//! All fields follow [OpenTelemetry semantic conventions] where applicable:
//!
//! | Field                | Level | Description                              |
//! |----------------------|-------|------------------------------------------|
//! | `http.method`        | span  | HTTP method (GET, POST, …)               |
//! | `http.target`        | span  | Request path                             |
//! | `http.request_id`    | span  | Unique request identifier (UUID v4)      |
//! | `http.status_code`   | event | Response HTTP status                     |
//! | `enduser.id`         | event | Authenticated username (if available)     |
//! | `error.message`      | event | Error description (only on 5xx)          |
//!
//! [OpenTelemetry semantic conventions]: https://opentelemetry.io/docs/specs/semconv/http/http-spans/

use actix_service::{Service, Transform};
use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, EitherBody},
    dev::{ServiceRequest, ServiceResponse},
};
use futures::{
    Future,
    future::{Ready, ok},
};
use std::{
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Instant,
};
use tracing::{Span, debug, error, info_span, warn};

use crate::authenticated_user::AuthenticatedUser;

/// Middleware that creates a tracing span for every HTTP request.
///
/// Usage in actix-web:
/// ```ignore
/// App::new()
///     .wrap(RequestTracing)
///     // … routes …
/// ```
pub struct RequestTracing;

impl<S, B> Transform<S, ServiceRequest> for RequestTracing
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = RequestTracingMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestTracingMiddleware {
            service: Rc::new(service),
        })
    }
}

pub struct RequestTracingMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestTracingMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().to_string();
        let path = req.path().to_string();
        let request_id = uuid::Uuid::new_v4().to_string();
        let start = Instant::now();

        // Check if user is already available (set by EnsureAuth or SslAuth)
        let user = req
            .extensions()
            .get::<AuthenticatedUser>()
            .map(|u| u.username.clone());

        let span = info_span!(
            "http.request",
            http.method = %method,
            http.target = %path,
            http.request_id = %request_id,
            // User might not be available yet — will be set in the response branch
        );

        let service = self.service.clone();

        Box::pin(async move {
            let _guard = span.enter();

            // Log the incoming request at debug level (includes the request_id
            // for correlating with upstream / downstream spans).
            debug!(
                user = user.as_deref().unwrap_or("pending"),
                "handling request"
            );

            // Forward to the next service / handler
            let result = service.call(req).await;

            let elapsed = start.elapsed();

            match result {
                Ok(res) => {
                    let status = res.response().status().as_u16();

                    // Extract user from the response extensions (may have been
                    // set by downstream middleware like EnsureAuth / SslAuth).
                    let effective_user = res
                        .response()
                        .extensions()
                        .get::<AuthenticatedUser>()
                        .map(|u| u.username.clone())
                        .or_else(|| {
                            // Fallback: try the request extensions.
                            res.request()
                                .extensions()
                                .get::<AuthenticatedUser>()
                                .map(|u| u.username.clone())
                        })
                        .unwrap_or_else(|| "anonymous".to_string());

                    // Record the response status and user on the span so every
                    // child event inherits them.
                    Span::current().record("http.status_code", status);

                    if status >= 500 {
                        // Server error — always logged at ERROR.
                        error!(
                            http.status_code = status,
                            enduser.id = effective_user,
                            duration_ms = elapsed.as_millis() as u64,
                            "request failed with server error"
                        );
                    } else if status >= 400 {
                        // Client error — logged at WARN (client mistake or
                        // expired token, not a server bug).
                        warn!(
                            http.status_code = status,
                            enduser.id = effective_user,
                            duration_ms = elapsed.as_millis() as u64,
                            "request failed with client error"
                        );
                    } else {
                        // Success (2xx) — logged at INFO for dashboard metrics.
                        debug!(
                            http.status_code = status,
                            enduser.id = effective_user,
                            duration_ms = elapsed.as_millis() as u64,
                            "request completed"
                        );
                    }

                    Ok(res.map_into_left_body())
                }
                Err(err) => {
                    // Service-level error (connection dropped, etc.) — rare.
                    error!(
                        error.message = %err,
                        duration_ms = elapsed.as_millis() as u64,
                        "request failed with service error"
                    );
                    Err(err)
                }
            }
        })
    }
}
