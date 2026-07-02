use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt; // for `oneshot`

use secureledger::build_test_app;

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).expect("valid json")
}

async fn login(app: &Router, username: &str, password: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

async fn token_for(app: &Router, username: &str, password: &str) -> String {
    let (status, body) = login(app, username, password).await;
    assert_eq!(status, StatusCode::OK, "login should succeed: {body:?}");
    body["token"].as_str().expect("token present").to_string()
}

#[tokio::test]
async fn login_returns_token_and_validates() {
    let (app, _state) = build_test_app();

    // Good credentials.
    let (status, body) = login(&app, "admin", "admin123").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["token"].as_str().is_some());
    assert_eq!(body["role"], "admin");
    assert_eq!(body["token_type"], "Bearer");

    // Bad credentials.
    let (status, _body) = login(&app, "admin", "wrongpass").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Unknown user.
    let (status, _body) = login(&app, "nobody", "whatever").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tasks_require_auth() {
    let (app, _state) = build_test_app();
    let req = Request::builder()
        .method("GET")
        .uri("/api/tasks")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn task_crud_happy_path() {
    let (app, _state) = build_test_app();
    let token = token_for(&app, "user", "user123").await;

    // Create.
    let req = Request::builder()
        .method("POST")
        .uri("/api/tasks")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            json!({ "title": "Write tests", "description": "cover CRUD", "status": "todo" })
                .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["title"], "Write tests");
    assert_eq!(created["owner"], "user");
    assert_eq!(created["status"], "todo");

    // Get by id.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/tasks/{id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List.
    let req = Request::builder()
        .method("GET")
        .uri("/api/tasks?limit=10&offset=0")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Update.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/tasks/{id}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json!({ "status": "done" }).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let updated = body_json(resp).await;
    assert_eq!(updated["status"], "done");

    // Delete.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/tasks/{id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Confirm gone.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/tasks/{id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_task_input_is_rejected() {
    let (app, _state) = build_test_app();
    let token = token_for(&app, "user", "user123").await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/tasks")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(json!({ "title": "   " }).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn user_cannot_mutate_other_users_task() {
    let (app, _state) = build_test_app();
    let admin_token = token_for(&app, "admin", "admin123").await;
    let user_token = token_for(&app, "user", "user123").await;

    // Admin creates a task (owner=admin).
    let req = Request::builder()
        .method("POST")
        .uri("/api/tasks")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {admin_token}"))
        .body(Body::from(json!({ "title": "admin task" }).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let id = created["id"].as_str().unwrap().to_string();

    // Regular user tries to delete admin's task -> 403.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/tasks/{id}"))
        .header("authorization", format!("Bearer {user_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rbac_user_cannot_access_audit() {
    let (app, _state) = build_test_app();
    let user_token = token_for(&app, "user", "user123").await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/audit")
        .header("authorization", format!("Bearer {user_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_read_audit_and_events_are_recorded() {
    let (app, _state) = build_test_app();
    let admin_token = token_for(&app, "admin", "admin123").await;

    // Create a task to generate an audit event.
    let req = Request::builder()
        .method("POST")
        .uri("/api/tasks")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {admin_token}"))
        .body(Body::from(json!({ "title": "audited task" }).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Admin reads the audit log.
    let req = Request::builder()
        .method("GET")
        .uri("/api/audit?action=create")
        .header("authorization", format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let events = body_json(resp).await;
    let arr = events.as_array().unwrap();
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["action"], "create");
    assert_eq!(arr[0]["actor"], "admin");
    assert_eq!(arr[0]["entity_type"], "task");
}

#[tokio::test]
async fn health_and_ready_are_public() {
    let (app, _state) = build_test_app();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn openapi_json_is_served() {
    let (app, _state) = build_test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["info"]["title"], "SecureLedger API");
}
