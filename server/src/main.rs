use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, env, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    // Demonstration bootstrap only. Production credentials must be provisioned
    // per-device and persisted using a dedicated secret-management design.
    token_hashes: Arc<RwLock<HashSet<String>>>,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "ghulakh-server" }))
}

async fn authenticate(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    let valid = state.token_hashes.read().await.contains(&digest);
    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(Json(serde_json::json!({ "authenticated": true })))
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = env::var("GHULAKH_BOOTSTRAP_TOKEN")
        .context("set GHULAKH_BOOTSTRAP_TOKEN to a unique, high-entropy test token")?;
    anyhow::ensure!(token.len() >= 32, "bootstrap token must be at least 32 characters");

    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    let state = AppState {
        token_hashes: Arc::new(RwLock::new(HashSet::from([digest]))),
    };

    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    // Temporary process-local entropy sanity exercise; never log or expose secret.
    drop(secret);

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/auth/check", get(authenticate))
        .with_state(state);

    let addr: SocketAddr = env::var("GHULAK_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .context("invalid GHULAK_BIND address")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Ghulakh control API listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
