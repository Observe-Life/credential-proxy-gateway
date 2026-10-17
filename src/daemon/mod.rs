//! Daemon assembly: wire vault + state + transports, then serve.
//!
//! Two run modes share one `AppState`:
//! - default: bind a loopback HTTP server hosting the Web UI/API at `/` plus the
//!   MCP Streamable-HTTP endpoint at `/mcp`.
//! - `stdio_mcp`: speak MCP over stdio for editor integrations (no HTTP).
//!
//! Both binds are forced to 127.0.0.1 — this connector is never exposed off-box.

use crate::audit::AuditLog;
use crate::config::{self, Config};
use crate::state::AppState;
use crate::vault::Vault;
use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

pub struct DaemonOptions {
    pub data_dir: Option<PathBuf>,
    pub master_password_env: Option<String>,
    pub master_password_stdin: bool,
    pub stdio_mcp: bool,
}

pub async fn run(opts: DaemonOptions) -> anyhow::Result<()> {
    let data_dir = config::resolve_data_dir(opts.data_dir.clone())?;
    let cfg = Config::load_or_init(&data_dir)?;

    let vault = Arc::new(Vault::open(&data_dir.join("vault.db"), &data_dir.join("runtime-key"))?);
    let audit = Arc::new(AuditLog::new(data_dir.join("audit")));

    // Optional headless unlock. If the vault is uninitialized, unlock is skipped
    // and the Web UI drives first-run init.
    maybe_unlock(&vault, &opts)?;

    // 一次性迁移：把旧的注册记录搬成服务卡片。
    // 幂等——卡片表非空时不动，所以重启不会重复搬、也不会覆盖新卡片。
    if vault.is_unlocked() {
        match vault.migrate_legacy_services() {
            Ok(0) => {}
            Ok(n) => tracing::info!(count = n, "legacy service records migrated into cards"),
            Err(e) => tracing::warn!("legacy migration skipped: {e}"),
        }
    }

    // One-time migration file is read only inside the service. Never log its contents.
    // Credential records are encrypted immediately with the existing vault DEK.
    if let Ok(file) = std::env::var("CREDENTIAL_VAULT_IMPORT_FILE") {
        if std::path::Path::new(&file).exists() {
            let records: Vec<crate::services::ServiceRecord> = serde_json::from_slice(&std::fs::read(&file)?)?;
            vault.open_management_grant()?;
            for record in records { vault.put_service_record(record)?; }
            vault.lock_management();
            std::fs::remove_file(&file)?;
            tracing::info!("MCP credential migration completed; import file removed");
        }
    }

    let local_token = generate_token();
    let state = AppState::new(vault, audit, cfg.clone(), local_token);

    if opts.stdio_mcp {
        // stdio MCP requires an already-unlocked vault (no interactive prompt).
        if !state.vault.is_unlocked() {
            anyhow::bail!("stdio MCP mode requires runtime credentials; initialize or unlock the vault once")
        }
        return crate::mcp::serve_stdio(state).await;
    }

    serve_http(state, &cfg, &data_dir).await
}

fn maybe_unlock(vault: &Vault, opts: &DaemonOptions) -> anyhow::Result<()> {
    if !vault.is_initialized()? {
        return Ok(());
    }
    let pw = if let Some(var) = &opts.master_password_env {
        std::env::var(var).ok()
    } else if opts.master_password_stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else {
        None
    };
    if let Some(pw) = pw {
        match vault.unlock(&pw) {
            Ok(()) => tracing::info!("vault unlocked at startup"),
            Err(error) => tracing::error!(error = %error, "startup unlock failed; continuing locked for management"),
        }
    }
    Ok(())
}

async fn serve_http(state: Arc<AppState>, cfg: &Config, data_dir: &PathBuf) -> anyhow::Result<()> {
    let static_dir = resolve_static_dir(data_dir);
    let mcp_service = crate::mcp::build_http_service(state.clone());

    let app = crate::web::router(state, static_dir)
        .nest_service("/mcp", mcp_service)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let bind_ip = std::env::var("SSH_CONNECTOR_BIND_ADDRESS")
        .ok()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let addr = SocketAddr::from((bind_ip, cfg.web_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on http://{addr}  (web UI + /mcp)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Static assets ship next to the binary in prod, but during development they
/// live in `./static`. Prefer an explicit `data_dir/static`, then `./static`.
fn resolve_static_dir(data_dir: &PathBuf) -> PathBuf {
    let candidate = data_dir.join("static");
    if candidate.is_dir() {
        return candidate;
    }
    PathBuf::from("static")
}

fn generate_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("system RNG");
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in buf {
        let _ = write!(s, "{b:02x}");
    }
    s
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
