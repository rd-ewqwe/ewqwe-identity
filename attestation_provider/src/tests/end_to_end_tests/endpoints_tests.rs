use crate::{
    server::{Version, endpoints::version_endpoint},
    tests::{log_test, mock_authenticate::mock_authenticate_endpoint},
};
use actix_identity::IdentityMiddleware;
use actix_session::{SessionMiddleware, config::PersistentSession, storage::CookieSessionStore};
use actix_web::{
    App,
    cookie::{Key, time::Duration},
    http::StatusCode,
    test, web,
};
use tracing::info;

// #[actix_web::test]
// async fn test_invalid_password() {
//     let store = Arc::new(InMemoryCredentialStore::from_iter([("admin", "secret")]));

//     let app = test::init_service(
//         App::new()
//             .wrap(UsernamePasswordAuth::new(store))
//             .route("/", web::get().to(test_handler)),
//     )
//     .await;

//     // Create request with invalid password
//     let credentials = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
//     let req = test::TestRequest::get()
//         .uri("/")
//         .insert_header(("Authorization", format!("Basic {credentials}")))
//         .to_request();

//     let resp = test::call_service(&app, req).await;
//     assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
// }
#[actix_web::test]
async fn test_version_endpoint() {
    log_test(Some("info"));
    let secret_key: Key = Key::generate();
    let app = test::init_service(
        App::new()
            .scope("/version")
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .session_lifecycle(
                        PersistentSession::default().session_ttl(Duration::hours(24)),
                    )
                    .build(),
            )
            .route("/authenticate", web::get().to(mock_authenticate_endpoint))
            .route("/version", web::get().to(version_endpoint)),
    )
    .await;

    // Create request with invalid password
    let req = test::TestRequest::get().uri("/authenticate").to_request();
    info!("Response to /authenticate {req:#?}");
    let req = test::TestRequest::get().uri("/version").to_request();

    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body = test::read_body(resp).await;
    let version: Version = serde_json::from_slice(&body).unwrap();

    assert_eq!(version.version, env!("CARGO_PKG_VERSION"));
}
