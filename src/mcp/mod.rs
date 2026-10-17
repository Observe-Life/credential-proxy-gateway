//! MCP server: the AI-facing tool surface.
//!
//! Security invariant: tools here NEVER return credential plaintext. Host
//! creation/update accepts secrets (write-only), but every read path returns
//! redacted summaries. Credential reveal is exclusively a Web-UI (human) action
//! gated on the master password and is deliberately absent from this surface.
//!
//! Two transports share one tool router:
//! - `serve_http` mounts a Streamable-HTTP service into the daemon's axum app.
//! - `run_stdio_shim` is a thin stdio<->HTTP forwarder so editors that speak
//!   stdio MCP can reach a already-running daemon.

use crate::audit::AuditLog;
use crate::error::ConnectorError;
use crate::state::AppState;
use crate::types::{ExecPayload, HostSpec, KeyName};
use base64::Engine;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{JsonObject, ServerCapabilities, ServerInfo};
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// 目录列表的上下文体积保护：默认回 200 条，最多 2000 条。
/// 这不是安全边界，多出来的条目会被标记，调用方可以要更多或换更窄的路径。
const SFTP_LIST_DEFAULT: usize = 200;
const SFTP_LIST_MAX: usize = 2000;

/// 服务调用面审计：动作 + 卡片 + 目标/命令摘要（先抹凭据再限长）+ 结果。
/// 失败同样要记，否则越界试探完全不留痕。
fn audit_call(
    state: &AppState,
    action: &str,
    card: &crate::gateway::ServiceCard,
    mut detail: serde_json::Value,
) {
    let values = card.values();
    if let Some(map) = detail.as_object_mut() {
        for key in ["url", "command", "cwd", "message"] {
            if let Some(text) = map.get(key).and_then(Value::as_str).map(str::to_owned) {
                let cut: String = crate::gateway::scrub_all(&text, &values).chars().take(240).collect();
                map.insert(key.to_string(), Value::String(cut));
            }
        }
    }
    state.audit.record(AuditLog::entry(action).with_detail(detail));
}

fn err_to_mcp(e: ConnectorError) -> ErrorData {
    // Surface our structured error code + context as MCP error data so the AI
    // can branch on `code` (e.g. host_key_mismatch vs auth_failed).
    let data = serde_json::to_value(&e).ok();
    ErrorData::internal_error(e.message.clone(), data)
}

// --- Tool request types (AI-facing input schemas) ---

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddHostRequest {
    #[serde(flatten)]
    pub spec: HostSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateHostRequest {
    pub host_id: String,
    #[serde(flatten)]
    pub spec: HostSpec,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HostIdRequest {
    pub host_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecRequest {
    pub host_id: String,
    /// Preferred one-shot command form. Exactly one of argv, script, or raw must be provided.
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    /// Multi-line shell script content. Exactly one of argv, script, or raw must be provided.
    #[serde(default)]
    pub script: Option<String>,
    /// Raw command string. Exactly one of argv, script, or raw must be provided.
    #[serde(default)]
    pub raw: Option<String>,
}

struct NormalizedExecRequest {
    host_id: String,
    payload: ExecPayload,
}

fn exec_payload_from_request(req: ExecRequest) -> Result<NormalizedExecRequest, ErrorData> {
    let selected = [
        req.argv.as_ref().map(|_| "argv"),
        req.script.as_ref().map(|_| "script"),
        req.raw.as_ref().map(|_| "raw"),
    ]
    .into_iter()
    .flatten()
    .count();

    if selected != 1 {
        return Err(ErrorData::invalid_params(
            "exec requires exactly one of argv, script, or raw",
            None,
        ));
    }

    let payload = if let Some(argv) = req.argv {
        ExecPayload::Argv { argv }
    } else if let Some(script) = req.script {
        ExecPayload::Script { script }
    } else if let Some(raw) = req.raw {
        ExecPayload::Raw { raw }
    } else {
        unreachable!("selected count was checked");
    };

    Ok(NormalizedExecRequest {
        host_id: req.host_id,
        payload,
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenPtyRequest {
    pub host_id: String,
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default = "default_cols")]
    pub cols: u16,
}

fn default_rows() -> u16 {
    24
}
fn default_cols() -> u16 {
    80
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionIdRequest {
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendTextRequest {
    pub session_id: String,
    pub text: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendKeyRequest {
    pub session_id: String,
    pub key: KeyName,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResizeRequest {
    pub session_id: String,
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpListRequest {
    pub host_id: String,
    pub path: String,
    /// 想拿回多少条：缺省 200，最多 2000。只是体积控制，不是权限。
    #[serde(default)] pub max_entries: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpGetRequest {
    pub host_id: String,
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpPutRequest {
    pub host_id: String,
    pub path: String,
    /// File content. Text is sent as-is (UTF-8).
    pub content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpPutBase64Request {
    pub host_id: String,
    pub path: String,
    /// Base64-encoded file content for small binary-safe uploads.
    pub content_base64: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpDownloadFileRequest {
    pub host_id: String,
    pub remote_path: String,
    /// Local destination path. Must be under /tmp or the daemon's current project directory.
    pub local_path: String,
    /// Defaults to false. Set true to overwrite an existing local destination.
    #[serde(default)]
    pub overwrite: bool,
    /// Create missing local parent directories. Defaults to true.
    #[serde(default = "default_true")]
    pub create_parent_dirs: bool,
    /// Streaming buffer size, from 64 KiB through 8 MiB. Defaults to 256 KiB.
    #[serde(default = "default_transfer_chunk_size")]
    pub chunk_size_bytes: usize,
    /// Compare the received stream, local temp file, and remote SHA-256. Defaults to true.
    #[serde(default = "default_true")]
    pub verify_sha256: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SftpUploadFileRequest {
    pub host_id: String,
    /// Local source file path. Must be under /tmp or the daemon's current project directory.
    pub local_path: String,
    pub remote_path: String,
    /// Defaults to false. Set true to replace an existing remote file.
    #[serde(default)]
    pub overwrite: bool,
    /// Create missing remote parent directories. Defaults to true.
    #[serde(default = "default_true")]
    pub create_parent_dirs: bool,
    /// Streaming buffer size, from 64 KiB through 8 MiB. Defaults to 256 KiB.
    #[serde(default = "default_transfer_chunk_size")]
    pub chunk_size_bytes: usize,
    /// Compare local and server-side SHA-256 before commit. Defaults to true.
    #[serde(default = "default_true")]
    pub verify_sha256: bool,
}

fn default_true() -> bool {
    true
}

fn default_transfer_chunk_size() -> usize {
    256 * 1024
}

/// The MCP tool server. Clones share one `Arc<AppState>`.
#[derive(Clone)]
pub struct McpServer {
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
}

// --- Tool output types (need object-rooted JSON schemas for MCP) ---

use crate::types::{DirEntry, HostSummary, SessionInfo};

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct HostListResult {
    pub hosts: Vec<HostSummary>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct HostIdResult {
    pub host_id: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct OkResult {
    pub ok: bool,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct ConnectResult {
    pub status: String,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SessionListResult {
    pub sessions: Vec<SessionInfo>,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpListResult {
    pub entries: Vec<DirEntry>,
    /// 目录里实际有多少条
    pub total: usize,
    /// true 表示还有没返回的条目，可以用 max_entries 或更窄路径继续取
    pub truncated: bool,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpGetResult {
    pub content: String,
    pub bytes: usize,
    pub had_invalid_utf8: bool,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpGetBase64Result {
    pub content_base64: String,
    pub bytes: usize,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
pub struct SftpFileTransferResult {
    pub local_path: String,
    pub remote_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub verified: bool,
}

impl McpServer {
    pub fn new(state: Arc<AppState>) -> Self {
        let mut tool_router = Self::tool_router();
        sanitize_tool_schemas_for_ai_clients(&mut tool_router);
        Self { state, tool_router }
    }
}

/// Codex and some OpenAI-compatible clients are stricter than full JSON Schema:
/// they expect OpenAI function-style parameter schemas and may reject a whole
/// MCP server when any tool advertises `oneOf`, `$defs/$ref`, nullable type
/// arrays, or Rust-specific integer formats. Keep the business structs typed,
/// but publish a conservative schema surface.
fn sanitize_tool_schemas_for_ai_clients(router: &mut ToolRouter<McpServer>) {
    for route in router.map.values_mut() {
        route.attr.input_schema = Arc::new(sanitize_schema_object(&route.attr.input_schema));
        route.attr.output_schema = None;
    }
}

fn sanitize_schema_object(schema: &JsonObject) -> JsonObject {
    let mut root = Value::Object(schema.clone());
    let defs = root
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    sanitize_schema_value(&mut root, &defs);
    match root {
        Value::Object(map) => map,
        _ => JsonObject::new(),
    }
}

fn sanitize_schema_value(value: &mut Value, defs: &Map<String, Value>) {
    match value {
        Value::Object(map) => {
            if let Some(replacement) = expand_ref(map, defs) {
                *value = replacement;
                sanitize_schema_value(value, defs);
                return;
            }

            let one_of = map.remove("oneOf").or_else(|| map.remove("anyOf"));
            if let Some(Value::Array(variants)) = one_of {
                merge_variants_into_object(map, variants, defs);
            }

            map.remove("$schema");
            map.remove("$defs");
            map.remove("format");
            map.remove("const");

            if let Some(Value::Array(types)) = map.get_mut("type") {
                let first_non_null = types
                    .iter()
                    .find(|ty| ty.as_str() != Some("null"))
                    .cloned()
                    .unwrap_or_else(|| Value::String("string".to_string()));
                map.insert("type".to_string(), first_non_null);
            }

            for child in map.values_mut() {
                sanitize_schema_value(child, defs);
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_schema_value(item, defs);
            }
        }
        _ => {}
    }
}

fn expand_ref(map: &Map<String, Value>, defs: &Map<String, Value>) -> Option<Value> {
    let ref_name = map
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("#/$defs/"))?;
    let mut replacement = defs.get(ref_name)?.clone();
    if let (Value::Object(dst), Some(description)) =
        (&mut replacement, map.get("description").cloned())
    {
        dst.entry("description".to_string()).or_insert(description);
    }
    Some(replacement)
}

fn merge_variants_into_object(
    map: &mut Map<String, Value>,
    variants: Vec<Value>,
    defs: &Map<String, Value>,
) {
    let mut merged_props = Map::new();
    let mut enum_values = Vec::new();

    for mut variant in variants {
        sanitize_schema_value(&mut variant, defs);
        let Value::Object(obj) = variant else {
            continue;
        };

        if let Some(Value::Array(values)) = obj.get("enum") {
            enum_values.extend(values.iter().cloned());
        }

        if let Some(Value::Object(props)) = obj.get("properties") {
            for (key, value) in props {
                merged_props
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }

    if !merged_props.is_empty() {
        let props = map
            .entry("properties".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(existing) = props {
            for (key, value) in merged_props {
                existing.entry(key).or_insert(value);
            }
        }
    }

    if !enum_values.is_empty() {
        map.insert("enum".to_string(), Value::Array(enum_values));
        map.insert("type".to_string(), Value::String("string".to_string()));
    } else {
        map.entry("type".to_string())
            .or_insert_with(|| Value::String("object".to_string()));
    }

    // The runtime still validates the real typed shape. For schema conversion,
    // optional is better than advertising impossible cross-variant requirements.
    map.remove("required");
}

#[derive(serde::Serialize, JsonSchema)]
pub struct CredentialResponse { pub result: Value }

#[derive(Deserialize, JsonSchema)]
pub struct ServiceId { pub id: String }

#[derive(Deserialize, JsonSchema)]
pub struct GatewayRequest {
    pub card_id: String,
    pub method: String,
    pub url: String,
    #[serde(default)] pub headers: std::collections::BTreeMap<String, String>,
    #[serde(default)] pub body: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GatewayCallMcp {
    pub card_id: String,
    /// 完整 MCP 端点，由模型每次给出
    pub url: String,
    pub tool_name: String,
    /// 声明为对象：无类型字段在调用方构造参数时会退化成字符串，服务端取不到内容。
    #[serde(default)] pub arguments: HashMap<String, Value>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GatewayRun {
    pub card_id: String,
    pub command: String,
    #[serde(default)] pub cwd: Option<String>,
    #[serde(default)] pub timeout: Option<u64>,
}

#[tool_router]
impl McpServer {
    // 服务适配机制（详见 README「服务适配机制设计」）：
    // 每个服务一张卡片 = 名称 + 允许的地址 + 凭据 + 注入方式（这四项是机制），
    // 外加建议性的常用端点与调用注意事项。网关只做三件事：按地址查凭据、注入、
    // 把响应里的凭据抹掉；方法/路径/参数/请求体都由模型自己决定，所以新增服务
    // 只需加一张卡片，不改代码。凭据永不进入模型上下文。
                    #[tool(description = "调用任何外部服务前先读这里。返回每张卡片：名称、允许的地址、注入方式、常用端点、调用注意事项、代理去向回显，以及凭据配了哪几个字段（绝不返回值）。注意事项每次调用现读数据库，用户改完立即生效，不需要重启任何进程或重新握手。用户在网页上编辑卡片不需要临时开关；只有智能体自己写卡片才需要。不得要求用户在聊天发送密钥。")]
    async fn gateway_list_cards(&self) -> Result<Json<CredentialResponse>, ErrorData> {
        let cards = self.state.vault.service_cards().map_err(err_to_mcp)?;
        Ok(Json(CredentialResponse { result: serde_json::json!({"cards": cards, "management_open": self.state.vault.is_management_unlocked(), "remaining_seconds": self.state.vault.management_remaining_seconds()}) }))
    }

    #[tool(description = "新增或修改一张服务卡片（智能体通道，需要用户在网页打开30分钟临时管理开关；用户在网页上编辑不需要开）。字段：id；name；addresses（允许的地址，一组主机名，支持 *.example.com 且只匹配一层子域）；credentials（键值对，可多个字段如 AppKey + Secret；留空表示保留原值）；auth（bearer / header / basic / query:<参数名> / none）；header_name；endpoints（建议性的常用端点）；notes（调用注意事项——这是给智能体的提醒，写在这里会即时生效，不要写进工具说明）。凭据永不回显。")]
    async fn gateway_register_card(&self, Parameters(card): Parameters<crate::gateway::ServiceCard>) -> Result<Json<OkResult>, ErrorData> {
        let id = card.id.clone();
        let auth = card.auth.clone();
        self.state.vault.put_service_card(card).map_err(err_to_mcp)?;
        self.state.audit.record(AuditLog::entry("card_register").with_detail(serde_json::json!({"card":id,"auth":auth})));
        Ok(Json(OkResult { ok:true }))
    }

    #[tool(description = "删除一张服务卡片（智能体通道，需用户在网页打开30分钟临时管理开关）。")]
    async fn gateway_remove_card(&self, Parameters(req): Parameters<ServiceId>) -> Result<Json<OkResult>, ErrorData> {
        self.state.vault.remove_service_card(&req.id).map_err(err_to_mcp)?;
        self.state.audit.record(AuditLog::entry("card_remove").with_detail(serde_json::json!({"card":req.id})));
        Ok(Json(OkResult { ok:true }))
    }

    #[tool(description = "按服务卡片发一次 HTTP 请求。方法、完整网址、请求头和请求体都由你决定；程序按卡片校验目标主机、按卡片的注入方式附加凭据，再把响应里出现的凭据抹掉，所以你看不到凭据的值。目标主机必须在该卡片的 addresses 里，否则直接拒绝。不要自带 Host、Forwarded、X-Forwarded-* 这类会改道请求的头，也不要试图把凭据值写进请求，两者都会被拒。跳转允许，但跳到卡片地址之外的地址时不会带凭据。")]
    async fn gateway_request(&self, Parameters(req): Parameters<GatewayRequest>) -> Result<Json<CredentialResponse>, ErrorData> {
        let card = self.state.vault.get_service_card(&req.card_id).map_err(err_to_mcp)?;
        let outcome = crate::gateway::execute_http(&card, &req.method, &req.url, req.headers, req.body).await;
        match &outcome {
            Ok(v) => audit_call(&self.state, "gateway_request", &card, serde_json::json!({"card":req.card_id,"method":req.method,"url":req.url,"status":v.get("status")})),
            Err(e) => audit_call(&self.state, "gateway_request_failed", &card, serde_json::json!({"card":req.card_id,"method":req.method,"url":req.url,"code":e.code.as_str(),"message":e.message})),
        }
        let out = outcome.map_err(err_to_mcp)?;
        Ok(Json(CredentialResponse { result: out }))
    }

    #[tool(description = "按 MCP 协议调用一次远程服务（exa、微信公众号这类）。程序先握手再调用你指定的 tool_name：tool_name 是该服务提供的工具名，arguments 是它的参数。card_id 指卡片（地址与凭据都按卡片来），url 是完整 MCP 端点（必须在该卡片的允许地址内）。程序按卡片附加凭据，并把返回里出现的凭据抹掉。")]
    async fn gateway_call_mcp(&self, Parameters(req): Parameters<GatewayCallMcp>) -> Result<Json<CredentialResponse>, ErrorData> {
        let card = self.state.vault.get_service_card(&req.card_id).map_err(err_to_mcp)?;
        let outcome = crate::gateway::execute_mcp(&card, &req.url, &req.tool_name, serde_json::json!(req.arguments)).await;
        match &outcome {
            Ok(_) => audit_call(&self.state, "gateway_call_mcp", &card, serde_json::json!({"card":req.card_id,"url":req.url,"tool":req.tool_name})),
            Err(e) => audit_call(&self.state, "gateway_call_mcp_failed", &card, serde_json::json!({"card":req.card_id,"url":req.url,"tool":req.tool_name,"code":e.code.as_str(),"message":e.message})),
        }
        let out = outcome.map_err(err_to_mcp)?;
        Ok(Json(CredentialResponse { result: out }))
    }

    #[tool(description = "按服务卡片跑一次本地命令。卡片里的凭据会作为环境变量注入子进程，命令输出里出现的凭据同样会被抹掉，所以你看不到凭据的值，也不要把它写进命令。command 是整条命令行（支持单双引号），cwd 默认 /app/data/github（git 操作务必指向仓库目录），timeout 默认 120 秒、上限 10800 秒。")]
    async fn gateway_run(&self, Parameters(req): Parameters<GatewayRun>) -> Result<Json<CredentialResponse>, ErrorData> {
        let card = self.state.vault.get_service_card(&req.card_id).map_err(err_to_mcp)?;
        let cwd = req.cwd.unwrap_or_else(|| "/app/data/github".to_string());
        let outcome = crate::gateway::execute_command(&card, &req.command, &cwd, req.timeout.unwrap_or(120)).await;
        match &outcome {
            Ok(v) => audit_call(&self.state, "gateway_run", &card, serde_json::json!({"card":req.card_id,"command":req.command,"cwd":cwd,"exit_code":v.get("exit_code")})),
            Err(e) => audit_call(&self.state, "gateway_run_failed", &card, serde_json::json!({"card":req.card_id,"command":req.command,"cwd":cwd,"code":e.code.as_str(),"message":e.message})),
        }
        let out = outcome.map_err(err_to_mcp)?;
        Ok(Json(CredentialResponse { result: out }))
    }

    #[tool(
        description = "List all configured hosts with connection status. Returns redacted summaries only — never credentials."
    )]
    async fn host_list(&self) -> Result<Json<HostListResult>, ErrorData> {
        let hosts = self.state.list_hosts().await.map_err(err_to_mcp)?;
        Ok(Json(HostListResult { hosts }))
    }

    #[tool(
        description = "Create a new SSH host and encrypted credential entry. Required fields: alias, host, user, auth. Optional fields: port (default 22), notes, jump_hosts, env, become_root. Auth is a tagged object: password = {\"type\":\"password\",\"password\":\"...\"}; private_key = {\"type\":\"private_key\",\"key_pem\":\"-----BEGIN OPENSSH PRIVATE KEY-----\\n...\",\"passphrase\":\"optional\"}; keyboard_interactive = {\"type\":\"keyboard_interactive\",\"answers\":[\"answer1\",\"answer2\"]}. jump_hosts is an ordered bastion chain: [{\"host\":\"bastion.example.com\",\"port\":22,\"user\":\"root\",\"auth\":{...}}], and each hop has its own auth object. become_root enables login-as-user-then-su workflows for session_open_root: {\"enabled\":true,\"command\":\"su -\",\"password\":\"root-password\",\"prompt_timeout_ms\":5000}. env is a string key/value object applied to interactive sessions. Secrets are stored encrypted and are write-only to AI; read tools return redacted summaries. Returns the new host_id. Requires management unlock; temporary management authority expires after 30 minutes."
    )]
    async fn host_add(
        &self,
        Parameters(req): Parameters<AddHostRequest>,
    ) -> Result<Json<HostIdResult>, ErrorData> {
        let host_id = self.state.add_host(req.spec).map_err(err_to_mcp)?;
        Ok(Json(HostIdResult { host_id }))
    }

    #[tool(
        description = "Update an existing host wholesale by host_id. Provide host_id plus the same full host shape as host_add: alias, host, user, auth, optional port, optional jump_hosts, optional env, optional become_root. Auth shapes are: {\"type\":\"password\",\"password\":\"...\"}, {\"type\":\"private_key\",\"key_pem\":\"-----BEGIN OPENSSH PRIVATE KEY-----\\n...\",\"passphrase\":\"optional\"}, or {\"type\":\"keyboard_interactive\",\"answers\":[\"answer1\",\"answer2\"]}. jump_hosts entries are {host, port, user, auth} and each hop authenticates independently. become_root is {\"enabled\":true,\"command\":\"su -\",\"password\":\"root-password\",\"prompt_timeout_ms\":5000} for session_open_root."
    )]
    async fn host_update(
        &self,
        Parameters(req): Parameters<UpdateHostRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .update_host(&req.host_id, req.spec)
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Delete a host and drop any live connection.")]
    async fn host_remove(
        &self,
        Parameters(req): Parameters<HostIdRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .remove_host(&req.host_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Open/establish the SSH transport to a host (runs the full jump chain and host-key TOFU). Idempotent."
    )]
    async fn host_connect(
        &self,
        Parameters(req): Parameters<HostIdRequest>,
    ) -> Result<Json<ConnectResult>, ErrorData> {
        self.state
            .connect_host(&req.host_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(ConnectResult {
            status: "connected".into(),
        }))
    }

    #[tool(
        description = "Disconnect and drop a host's live SSH transport. One-shot exec, PTY, and SFTP can reconnect on demand later."
    )]
    async fn host_disconnect(
        &self,
        Parameters(req): Parameters<HostIdRequest>,
    ) -> Result<Json<ConnectResult>, ErrorData> {
        self.state
            .disconnect_host(&req.host_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(ConnectResult {
            status: "disconnected".into(),
        }))
    }

    #[tool(
        description = "Run a one-shot command and wait for it to finish. Choose exactly one payload: `argv` (array, auto-quoted — preferred), `script` (multi-line, uploaded and run as a file), or `raw` (you own all quoting). Returns stdout/stderr/exit_code with truncation and timeout flags."
    )]
    async fn exec(
        &self,
        Parameters(req): Parameters<ExecRequest>,
    ) -> Result<Json<crate::types::ExecResult>, ErrorData> {
        let payload = exec_payload_from_request(req)?;
        let r = self
            .state
            .exec(&payload.host_id, &payload.payload)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(r))
    }

    #[tool(
        description = "Open a persistent interactive PTY session (stateful shell) on a host. Returns session metadata including session_id."
    )]
    async fn session_open(
        &self,
        Parameters(req): Parameters<OpenPtyRequest>,
    ) -> Result<Json<crate::types::SessionInfo>, ErrorData> {
        let info = self
            .state
            .open_pty(&req.host_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(info))
    }

    #[tool(
        description = "Open a persistent interactive PTY session and automatically become root using the host's encrypted become_root config. Configure hosts with become_root: {\"enabled\":true,\"command\":\"su -\",\"password\":\"root-password\",\"prompt_timeout_ms\":5000}. This is for login-as-user-then-`su` workflows; it does not expose the root password to the AI."
    )]
    async fn session_open_root(
        &self,
        Parameters(req): Parameters<OpenPtyRequest>,
    ) -> Result<Json<crate::types::SessionInfo>, ErrorData> {
        let info = self
            .state
            .open_root_pty(&req.host_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(info))
    }

    #[tool(description = "List all live PTY sessions with idle TTL remaining.")]
    async fn session_list(&self) -> Result<Json<SessionListResult>, ErrorData> {
        let sessions = self.state.list_sessions().await;
        Ok(Json(SessionListResult { sessions }))
    }

    #[tool(
        description = "Send literal text to a PTY session's stdin (no implicit newline — include \\n or use a key to submit)."
    )]
    async fn session_send_text(
        &self,
        Parameters(req): Parameters<SendTextRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_send_text(&req.session_id, &req.text)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Send a semantic key (enter, tab, up, ctrl_c, f(n), etc.) to a PTY session."
    )]
    async fn session_send_key(
        &self,
        Parameters(req): Parameters<SendKeyRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_send_key(&req.session_id, &req.key)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Get a structured snapshot of a PTY session's current screen (rows of text, cursor, attributes, alt-screen flag, seq)."
    )]
    async fn session_screen(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<crate::types::ScreenSnapshot>, ErrorData> {
        let snap = self
            .state
            .pty_snapshot(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(snap))
    }

    #[tool(
        description = "Read newly produced text from a PTY session since the last read. Includes a heuristic likely_waiting_input flag."
    )]
    async fn session_read(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<crate::types::ReadResult>, ErrorData> {
        let r = self
            .state
            .pty_read(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(r))
    }

    #[tool(description = "Resize a PTY session's terminal.")]
    async fn session_resize(
        &self,
        Parameters(req): Parameters<ResizeRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .pty_resize(&req.session_id, req.rows, req.cols)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "Close a PTY session and free its channel.")]
    async fn session_close(
        &self,
        Parameters(req): Parameters<SessionIdRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .close_pty(&req.session_id)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(description = "List a remote directory over SFTP. 默认最多返回 200 条（max_entries 可调，上限 2000）；truncated=true 表示还有更多，请改用更窄的路径或 exec 的 ls 继续取，不要重复整目录拉取。")]
    async fn sftp_list(
        &self,
        Parameters(req): Parameters<SftpListRequest>,
    ) -> Result<Json<SftpListResult>, ErrorData> {
        let entries = self
            .state
            .sftp_list(&req.host_id, &req.path)
            .await
            .map_err(err_to_mcp)?;
        let total = entries.len();
        let cap = req.max_entries.unwrap_or(SFTP_LIST_DEFAULT).clamp(1, SFTP_LIST_MAX);
        let truncated = total > cap;
        Ok(Json(SftpListResult { entries: entries.into_iter().take(cap).collect(), total, truncated }))
    }

    #[tool(
        description = "Read a remote text file over SFTP. Returns content as a UTF-8 string (invalid bytes are flagged)."
    )]
    async fn sftp_get(
        &self,
        Parameters(req): Parameters<SftpGetRequest>,
    ) -> Result<Json<SftpGetResult>, ErrorData> {
        let bytes = self
            .state
            .sftp_get(&req.host_id, &req.path)
            .await
            .map_err(err_to_mcp)?;
        let (content, had_invalid_utf8) = match std::str::from_utf8(&bytes) {
            Ok(s) => (s.to_string(), false),
            Err(_) => (String::from_utf8_lossy(&bytes).into_owned(), true),
        };
        Ok(Json(SftpGetResult {
            content,
            bytes: bytes.len(),
            had_invalid_utf8,
        }))
    }

    #[tool(
        description = "Read a small remote file over SFTP as base64. Use only for small binary files where returning content in the MCP response is acceptable. For large files, archives, APKs, zip/tar/gz, installers, images, or anything likely to exceed context limits, use sftp_download_file instead."
    )]
    async fn sftp_get_base64(
        &self,
        Parameters(req): Parameters<SftpGetRequest>,
    ) -> Result<Json<SftpGetBase64Result>, ErrorData> {
        let bytes = self
            .state
            .sftp_get(&req.host_id, &req.path)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(SftpGetBase64Result {
            content_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            bytes: bytes.len(),
        }))
    }

    #[tool(description = "Write a remote UTF-8 text file over SFTP (overwrites).")]
    async fn sftp_put(
        &self,
        Parameters(req): Parameters<SftpPutRequest>,
    ) -> Result<Json<OkResult>, ErrorData> {
        self.state
            .sftp_put(&req.host_id, &req.path, req.content.as_bytes())
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Write a small remote file over SFTP from base64 (overwrites). Use only for small binary payloads. For large files, archives, APKs, zip/tar/gz, installers, images, or anything likely to exceed context limits, put the file under /tmp or the current project and use sftp_upload_file instead."
    )]
    async fn sftp_put_base64(
        &self,
        Parameters(req): Parameters<SftpPutBase64Request>,
    ) -> Result<Json<OkResult>, ErrorData> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(req.content_base64.as_bytes())
            .map_err(|e| ErrorData::invalid_params(format!("invalid base64 content: {e}"), None))?;
        self.state
            .sftp_put(&req.host_id, &req.path, &bytes)
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(OkResult { ok: true }))
    }

    #[tool(
        description = "Atomically download a remote file over SFTP to a local path without putting content in MCP context. local_path must be under /tmp or the daemon's current project. The transfer streams in configurable chunks to a same-directory .part file, creates missing local parents by default, fsyncs, verifies size and SHA-256 by default, then commits without exposing a partial destination. overwrite defaults to false. Returns bytes, sha256, and verified. Prefer this for large binaries, archives, APKs, installers, images, and exact-byte transfers."
    )]
    async fn sftp_download_file(
        &self,
        Parameters(req): Parameters<SftpDownloadFileRequest>,
    ) -> Result<Json<SftpFileTransferResult>, ErrorData> {
        let r = self
            .state
            .sftp_download_file(
                &req.host_id,
                &req.remote_path,
                &req.local_path,
                req.overwrite,
                req.create_parent_dirs,
                req.chunk_size_bytes,
                req.verify_sha256,
            )
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(SftpFileTransferResult {
            local_path: r.local_path.display().to_string(),
            remote_path: r.remote_path,
            bytes: r.bytes,
            sha256: r.sha256,
            verified: r.verified,
        }))
    }

    #[tool(
        description = "Atomically upload a local file over SFTP without putting content in MCP parameters. local_path must be under /tmp or the daemon's current project. The transfer streams in configurable chunks to a same-directory remote .part file, creates missing remote parents by default, verifies remote size and SHA-256 by default, then renames into place. overwrite defaults to false and uses a rollback backup when replacing. Failed transfers remove temporary files. Returns bytes, sha256, and verified. Prefer this for large binaries, archives, APKs, installers, images, and exact-byte transfers."
    )]
    async fn sftp_upload_file(
        &self,
        Parameters(req): Parameters<SftpUploadFileRequest>,
    ) -> Result<Json<SftpFileTransferResult>, ErrorData> {
        let r = self
            .state
            .sftp_upload_file(
                &req.host_id,
                &req.local_path,
                &req.remote_path,
                req.overwrite,
                req.create_parent_dirs,
                req.chunk_size_bytes,
                req.verify_sha256,
            )
            .await
            .map_err(err_to_mcp)?;
        Ok(Json(SftpFileTransferResult {
            local_path: r.local_path.display().to_string(),
            remote_path: r.remote_path,
            bytes: r.bytes,
            sha256: r.sha256,
            verified: r.verified,
        }))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "SSH maintenance connector. When the user asks to operate SSH hosts, remote Linux \
             machines, VPS instances, or server-side files and commands that are available in this \
             connector, prefer these MCP tools over spawning local `ssh`, `scp`, or `sftp` shell \
             commands. Start with `host_list` to discover configured hosts and connection state; \
             use `host_connect` only when an explicit connection check is needed because `exec`, \
             PTY, and SFTP operations connect on demand. Hosts and credentials are managed by a \
             human via a separate Web UI; you can create/update hosts and reference them by \
             host_id, but you can never read stored credentials. Prefer `exec` with the `argv` \
             payload for one-shot commands because it is auto-quoted. Use `script` for multi-line \
             non-interactive work, `raw` only when you intentionally own shell quoting, \
             `session_open` for stateful interactive work (editors, REPLs, prompts), \
             `session_open_root` when the host is configured to log in as a normal user and then \
             run `su -` to root, text SFTP for UTF-8 files, `sftp_download_file`/`sftp_upload_file` \
             for large binary files, archives, packages, images, APKs, and exact-byte file transfer, \
             and base64 SFTP tools only for small binary payloads that safely fit in MCP context.",
        )
    }
}

use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

const MCP_IDLE_TIMEOUT_ENV: &str = "SSH_CONNECTOR_MCP_IDLE_TIMEOUT_MINUTES";

fn parse_mcp_idle_timeout(raw: Option<&str>) -> Result<Duration, &'static str> {
    let minutes = match raw {
        None => 120,
        Some(value) => value.trim().parse::<u64>()
            .map_err(|_| "must be an integer number of minutes (5..=1440)")?,
    };
    if !(5..=1440).contains(&minutes) {
        return Err("must be between 5 and 1440 minutes inclusive");
    }
    Ok(Duration::from_secs(minutes * 60))
}

/// Build a Streamable-HTTP MCP service that the daemon mounts under `/mcp`.
/// Each connection gets a fresh `McpServer` sharing the same `AppState`.
pub fn build_http_service(
    state: Arc<AppState>,
) -> StreamableHttpService<McpServer, LocalSessionManager> {
    // rmcp validates the inbound `Host` header and only allows loopback by
    // default (DNS-rebinding protection). Container-to-container callers reach
    // this service by container name, so extend that list with hosts named in
    // `SSH_CONNECTOR_ALLOWED_HOSTS` (comma separated, `host` or `host:port`).
    // Entries are appended, never substituted, so the loopback defaults stay.
    let mut config = StreamableHttpServerConfig::default();
    if let Ok(extra) = std::env::var("SSH_CONNECTOR_ALLOWED_HOSTS") {
        for host in extra.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
            if !config.allowed_hosts.iter().any(|existing| existing == host) {
                config.allowed_hosts.push(host.to_string());
            }
        }
    }
    let saved_minutes = state.config.mcp_idle_timeout_minutes.to_string();
    let timeout = parse_mcp_idle_timeout(Some(&saved_minutes))
        .unwrap_or_else(|error| panic!("{MCP_IDLE_TIMEOUT_ENV}: {error}"));
    let mut sessions = LocalSessionManager::default();
    sessions.session_config.keep_alive = Some(timeout);
    tracing::info!(idle_timeout_minutes = timeout.as_secs() / 60, "MCP session idle timeout configured");
    StreamableHttpService::new(
        move || Ok(McpServer::new(state.clone())),
        Arc::new(sessions),
        config,
    )
}

/// Serve the MCP tool surface over stdio (for editors that speak stdio MCP).
/// Spins up its own full `AppState`; runs until the client disconnects.
pub async fn serve_stdio(state: Arc<AppState>) -> anyhow::Result<()> {
    use rmcp::ServiceExt;
    use rmcp::transport::stdio;
    let service = McpServer::new(state).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_idle_timeout_default_and_bounds() {
        assert_eq!(parse_mcp_idle_timeout(None).unwrap(), Duration::from_secs(7200));
        for minutes in [5, 120, 1440] {
            let value = minutes.to_string();
            assert_eq!(parse_mcp_idle_timeout(Some(&value)).unwrap(), Duration::from_secs(minutes * 60));
        }
        assert_eq!(parse_mcp_idle_timeout(Some(" 120 ")).unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn mcp_idle_timeout_rejects_invalid_values() {
        for value in ["", "0", "4", "1441", "-5", "1.5", "abc", "18446744073709551616"] {
            assert!(parse_mcp_idle_timeout(Some(value)).is_err(), "accepted: {value}");
        }
    }

    #[test]
    fn ai_tool_surface_has_transfers_but_no_credential_reveal() {
        let router = McpServer::tool_router();
        let names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        assert!(names.iter().any(|name| name == "sftp_download_file"));
        assert!(names.iter().any(|name| name == "sftp_upload_file"));
        assert!(!names.iter().any(|name| name.contains("reveal")));
        assert!(!names.iter().any(|name| name.contains("credential_get")));
    }

    #[test]
    fn large_transfer_schema_exposes_safety_controls() {
        let mut router = McpServer::tool_router();
        sanitize_tool_schemas_for_ai_clients(&mut router);
        let upload = router.get("sftp_upload_file").unwrap();
        let properties = upload.input_schema["properties"].as_object().unwrap();
        for field in [
            "overwrite",
            "create_parent_dirs",
            "chunk_size_bytes",
            "verify_sha256",
        ] {
            assert!(properties.contains_key(field), "missing {field}");
        }
    }
}
