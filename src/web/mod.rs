//! Web management API (human-facing). Bound to loopback only by the daemon.
//!
//! This is the ONLY surface that can reveal stored credentials, and only after
//! re-supplying the master password. Vault init/unlock also live here. The
//! static SPA in `static/` is served as a fallback.

use crate::error::{ConnectorError, ErrorCode};
use crate::state::AppState;
use crate::types::HostSpec;
use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    middleware::{self, Next},
    extract::Request,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tower_http::services::ServeDir;

type Shared = Arc<AppState>;

/// Build the axum router: API under `/api`, static SPA fallback.
pub fn router(state: Shared, static_dir: std::path::PathBuf) -> Router {
    let api = Router::new()
        .route("/status", get(status))
        .route("/management/grant", put(management_grant))
        .route("/registry", get(registry_list).put(registry_save))
        .route("/registry/{id}", axum::routing::delete(registry_delete))
        .route("/registry/{id}/credential", get(reveal_service_credential))
        .route("/settings", get(get_settings).put(save_settings))
        .route("/vault/init", post(vault_init))
        .route("/vault/unlock", post(vault_unlock))
        .route("/vault/lock-management", post(vault_lock_management))
        .route("/hosts", get(get_hosts).post(add_host))
        .route("/hosts/{id}", put(update_host).delete(remove_host))
        .route("/hosts/{id}/connect", post(connect_host))
        .route("/hosts/{id}/disconnect", post(disconnect_host))
        .route("/hosts/{id}/reveal", post(reveal_host))

        .route("/sessions", get(get_sessions))
        .route("/sessions/{id}/close", post(close_session))
        .route("/sessions/{id}/attach", get(attach_session))
        .route("/audit", get(get_audit))
        .route_layer(middleware::from_fn_with_state(state.clone(), verify_gateway_identity))
        .with_state(state);

    Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
}

/// Map a ConnectorError to an HTTP status + JSON body the SPA understands.
struct ApiError(ConnectorError);

impl From<ConnectorError> for ApiError {
    fn from(e: ConnectorError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0.code {
            ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::HostNotFound | ErrorCode::SessionNotFound => StatusCode::NOT_FOUND,
            ErrorCode::VaultLocked
            | ErrorCode::VaultBadPassword
            | ErrorCode::AuthFailed
            | ErrorCode::PrivateKeyInvalid
            | ErrorCode::PrivateKeyPassphraseRequired
            | ErrorCode::PrivateKeyPassphraseInvalid
            | ErrorCode::KeyboardInteractiveFailed => StatusCode::UNAUTHORIZED,
            ErrorCode::VaultAlreadyInit | ErrorCode::HostKeyMismatch => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(
            json!({ "code": self.0.code, "message": self.0.message, "context": self.0.context }),
        );
        (status, body).into_response()
    }
}

type ApiResult = std::result::Result<Json<serde_json::Value>, ApiError>;

#[derive(Deserialize)]
struct SettingsRequest { mcp_idle_timeout_minutes: u64 }

async fn get_settings(State(st): State<Shared>) -> ApiResult {
    let saved: crate::config::Config = toml::from_str(
        &std::fs::read_to_string(&st.config.config_path).map_err(|e| ApiError(ConnectorError::new(ErrorCode::BadRequest, e.to_string())))?
    ).map_err(|e| ApiError(ConnectorError::new(ErrorCode::BadRequest, e.to_string())))?;
    let active = st.config.mcp_idle_timeout_minutes;
    Ok(Json(json!({"saved_minutes": saved.mcp_idle_timeout_minutes, "active_minutes": active,
        "restart_required": saved.mcp_idle_timeout_minutes != active,
        "environment_override": std::env::var("SSH_CONNECTOR_MCP_IDLE_TIMEOUT_MINUTES").is_ok()})))
}

async fn save_settings(State(st): State<Shared>, Json(req): Json<SettingsRequest>) -> ApiResult {
    if !st.vault.is_management_unlocked() { return Err(ApiError(ConnectorError::locked())); }
    if !(5..=1440).contains(&req.mcp_idle_timeout_minutes) {
        return Err(ApiError(ConnectorError::new(ErrorCode::BadRequest, "空闲回收时间必须为5至1440分钟")));
    }
    if std::env::var("SSH_CONNECTOR_MCP_IDLE_TIMEOUT_MINUTES").is_ok() {
        return Err(ApiError(ConnectorError::new(ErrorCode::BadRequest, "环境变量正在覆盖设置，请先移除该环境变量再使用网页保存")));
    }
    let file = &st.config.config_path;
    let text = std::fs::read_to_string(file).map_err(|e| ApiError(ConnectorError::new(ErrorCode::BadRequest, e.to_string())))?;
    let mut saved: crate::config::Config = toml::from_str(&text).map_err(|e| ApiError(ConnectorError::new(ErrorCode::BadRequest, e.to_string())))?;
    saved.mcp_idle_timeout_minutes = req.mcp_idle_timeout_minutes;
    let text = toml::to_string_pretty(&saved).map_err(|e| ApiError(ConnectorError::new(ErrorCode::BadRequest, e.to_string())))?;
    let tmp = file.with_extension("toml.tmp");
    std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, file))
        .map_err(|e| ApiError(ConnectorError::new(ErrorCode::BadRequest, e.to_string())))?;
    st.audit.record(crate::audit::AuditLog::entry("mcp_idle_timeout_update").with_detail(json!({"minutes":req.mcp_idle_timeout_minutes})));
    get_settings(State(st)).await
}

async fn verify_gateway_identity(State(st): State<Shared>, req: Request, next: Next) -> Response {
    let file = match std::env::var("CREDENTIAL_VAULT_GATEWAY_AUTH_FILE") {
        Ok(path) => path,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "统一登录认证尚未配置").into_response(),
    };
    let secret = match std::fs::read_to_string(file) { Ok(s) => s, Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let cookie = req.headers().get("cookie").and_then(|v|v.to_str().ok()).unwrap_or("");
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).redirect(reqwest::redirect::Policy::none()).build() {
        Ok(c) => c, Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let identity = client.get("http://container-login-gateway:8080/internal/session/verify")
        .header("X-Internal-Auth", secret.trim()).header("Cookie", cookie).send().await;
    if !identity.is_ok_and(|r|r.status().is_success()) {
        // 未登录只拒绝这一个请求，不改动管理授权状态。
        // 网页会话过期、或其他容器做一次只读探测，都不该把人正开着的管理开关
        // 顺手关掉；收回授权只有两条路：30 分钟自然到期，和显式关闭（两者都留审计）。
        return (StatusCode::UNAUTHORIZED, "请先通过容器统一登录网关登录").into_response();
    }
    if req.method()!=axum::http::Method::GET && req.method()!=axum::http::Method::HEAD {
        let origin = req.headers().get("origin").and_then(|v|v.to_str().ok()).and_then(|s|reqwest::Url::parse(s).ok());
        let host = req.headers().get("host").and_then(|v|v.to_str().ok()).unwrap_or("");
        let authority = origin.as_ref().map(|u| match u.port() {Some(port)=>format!("{}:{port}",u.host_str().unwrap_or("")),None=>u.host_str().unwrap_or("").to_string()});
        if authority.as_deref()!=Some(host) {return StatusCode::FORBIDDEN.into_response();}
    }
    next.run(req).await
}

#[derive(Deserialize)]
struct GrantRequest { enabled: bool }
async fn management_grant(State(st): State<Shared>, Json(req): Json<GrantRequest>) -> ApiResult {
    if req.enabled {st.vault.open_management_grant().map_err(ApiError::from)?;} else {st.vault.lock_management();}
    // 管理授权是"凭据可被写入"的开关，每次开与关都必须查得到。
    st.audit.record(crate::audit::AuditLog::entry(if req.enabled { "management_grant_open" } else { "management_grant_close" })
        .with_detail(json!({ "remaining_seconds": st.vault.management_remaining_seconds() })));
    Ok(Json(json!({"enabled":st.vault.is_management_unlocked(),"remaining_seconds":st.vault.management_remaining_seconds()})))
}
// 服务卡片：列表只返回元数据，凭据只说明配了哪几个字段，绝不返回值。
async fn registry_list(State(st): State<Shared>) -> ApiResult {
    Ok(Json(json!({"services":st.vault.service_cards().map_err(ApiError::from)?})))
}
async fn registry_save(State(st): State<Shared>, Json(card): Json<crate::gateway::ServiceCard>) -> ApiResult {
    // 人已在统一登录态下；30 分钟开关只约束智能体写入，网页编辑不再要求它。
    st.vault.put_service_card_by_human(card).map_err(ApiError::from)?;
    Ok(Json(json!({"ok":true})))
}
async fn registry_delete(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.vault.remove_service_card_by_human(&id).map_err(ApiError::from)?;
    Ok(Json(json!({"ok":true})))
}

// --- Vault / status ---

async fn status(State(st): State<Shared>) -> ApiResult {
    Ok(Json(json!({
        "vault_initialized": st.vault.is_initialized().map_err(ApiError::from)?,
        "vault_unlocked": st.vault.is_unlocked(),
        "management_unlocked": st.vault.is_management_unlocked(),
        "management_remaining_seconds": st.vault.management_remaining_seconds(),
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

#[derive(Deserialize)]
struct MasterPassword {
    master_password: String,
}

async fn vault_init(State(st): State<Shared>, Json(req): Json<MasterPassword>) -> ApiResult {
    st.vault
        .init(&req.master_password)
        .map_err(ApiError::from)?;
    st.audit.record(
        crate::audit::AuditLog::entry("vault_init").with_detail(json!({ "source": "web" })),
    );
    Ok(Json(json!({ "ok": true })))
}

async fn vault_unlock(State(st): State<Shared>, Json(req): Json<MasterPassword>) -> ApiResult {
    st.vault
        .unlock(&req.master_password)
        .map_err(ApiError::from)?;
    st.audit.record(
        crate::audit::AuditLog::entry("vault_unlock").with_detail(json!({ "source": "web" })),
    );
    Ok(Json(json!({ "ok": true })))
}

async fn vault_lock_management(State(st): State<Shared>) -> ApiResult {
    st.vault.lock_management();
    st.audit.record(
        crate::audit::AuditLog::entry("management_lock").with_detail(json!({ "source": "web" })),
    );
    Ok(Json(json!({ "ok": true })))
}

// --- Hosts ---

async fn get_hosts(State(st): State<Shared>) -> ApiResult {
    let hosts = st.list_host_details().await.map_err(ApiError::from)?;
    Ok(Json(json!({ "hosts": hosts })))
}

async fn add_host(State(st): State<Shared>, Json(spec): Json<HostSpec>) -> ApiResult {
    let id = st.add_host(spec).map_err(ApiError::from)?;
    Ok(Json(json!({ "host_id": id })))
}

async fn update_host(
    State(st): State<Shared>,
    Path(id): Path<String>,
    Json(spec): Json<HostSpec>,
) -> ApiResult {
    st.update_host(&id, spec).map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

async fn remove_host(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.remove_host(&id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

async fn connect_host(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.connect_host(&id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "status": "connected" })))
}

async fn disconnect_host(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.disconnect_host(&id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "status": "disconnected" })))
}

async fn reveal_host(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    // Human-only reveal: the gateway-identity middleware already proved that a
    // logged-in browser sent this request, so no second password is required.
    // No MCP tool reaches this route, and the value is never logged.
    let cfg = st.vault.get_host_config(&id).map_err(ApiError::from)?;
    st.audit.record(
        crate::audit::AuditLog::entry("credential_reveal")
            .with_host(&id)
            .with_detail(json!({ "source": "web" })),
    );
    Ok(Json(json!({ "auth": cfg.auth, "jump_hosts": cfg.jump_hosts })))
}

async fn reveal_service_credential(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    let card = st.vault.get_service_card(&id).map_err(ApiError::from)?;
    let credential = card
        .credentials
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");
    st.audit.record(
        crate::audit::AuditLog::entry("card_credential_reveal")
            .with_detail(json!({ "source": "web", "card": id })),
    );
    Ok(Json(json!({ "credential": credential })))
}

async fn get_sessions(State(st): State<Shared>) -> ApiResult {
    let sessions = st.list_sessions().await;
    Ok(Json(json!({ "sessions": sessions })))
}

async fn close_session(State(st): State<Shared>, Path(id): Path<String>) -> ApiResult {
    st.close_pty(&id).await.map_err(ApiError::from)?;
    Ok(Json(json!({ "ok": true })))
}

// --- Audit ---

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default = "default_page")]
    page: usize,
}
fn default_page() -> usize {
    1
}

fn default_limit() -> usize {
    200
}

async fn get_audit(State(st): State<Shared>, Query(q): Query<AuditQuery>) -> ApiResult {
    // 分页：page 从 1 开始，最新的一页是第 1 页。per_page 上限 200，前端默认 10。
    let per_page = q.limit.clamp(1, 200);
    let total = st.audit.total_lines();
    let pages = total.div_ceil(per_page).max(1);
    let page = q.page.clamp(1, pages);
    let entries = st.audit.tail_page((page - 1) * per_page, per_page);
    Ok(Json(json!({
        "entries": entries,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages
    })))
}

// --- WebSocket terminal takeover ---

async fn attach_session(
    State(st): State<Shared>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| attach_socket(socket, st, id))
}

/// Bridge a PTY session to a WebSocket: remote bytes -> client, client text/bytes
/// -> remote stdin. Closes when either side ends or the session dies.
async fn attach_socket(socket: WebSocket, st: Shared, session_id: String) {
    let mut rx = match st.sessions.pty_subscribe(&session_id).await {
        Ok(rx) => rx,
        Err(_) => {
            let mut s = socket;
            let _ = s
                .send(Message::Text(
                    json!({ "error": "session_not_found" }).to_string().into(),
                ))
                .await;
            return;
        }
    };

    let (mut sink, mut stream) = {
        use futures_util::StreamExt;
        socket.split()
    };

    // Remote -> client.
    let to_client = tokio::spawn(async move {
        use futures_util::SinkExt;
        loop {
            match rx.recv().await {
                Ok(bytes) => {
                    if sink.send(Message::Binary(bytes.into())).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });

    // Client -> remote stdin.
    let st2 = st.clone();
    let sid = session_id.clone();
    let to_remote = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(Ok(msg)) = stream.next().await {
            let bytes = match msg {
                Message::Text(t) => t.as_bytes().to_vec(),
                Message::Binary(b) => b.to_vec(),
                Message::Close(_) => break,
                _ => continue,
            };
            if st2.pty_input_ws(&sid, bytes).await.is_err() {
                break;
            }
        }
    });

    // When either direction finishes, abort the other.
    tokio::select! {
        _ = to_client => {},
        _ = to_remote => {},
    }
}
