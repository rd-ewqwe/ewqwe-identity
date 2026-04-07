use actix_web::{App, http::StatusCode, test, web};
use base64::Engine;
use std::sync::Arc;

#[actix_web::test]
async fn test_invalid_password() {
    let store = Arc::new(InMemoryCredentialStore::from_iter([("admin", "secret")]));

    let app = test::init_service(
        App::new()
            .wrap(UsernamePasswordAuth::new(store))
            .route("/", web::get().to(test_handler)),
    )
    .await;

    // Create request with invalid password
    let credentials = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("Authorization", format!("Basic {credentials}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
