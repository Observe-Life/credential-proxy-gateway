//! 服务卡片与通用凭据注入。凭据只注入外发请求，永不进入模型上下文。
//!
//! 卡片只有一套字段（名称、允许的地址、入口地址、凭据、注入方式、常用端点、注意事项），
//! 不区分服务类型。怎么把请求发出去，由模型每次自己挑工具：
//! - `execute_http`    ：普通 HTTP/HTTPS 请求，方法/路径/参数/请求体都由模型决定
//! - `execute_mcp`     ：按 MCP 协议对话（握手后调用指定工具），给 exa、微信公众号这类服务用
//! - `execute_command` ：本地命令，凭据作为环境变量注入子进程
//! 三者共用同一套地址校验、凭据注入与结果脱敏。
//!
//! 设计（见 README「服务适配机制设计」）：
//! - 每个服务一张卡片：名称、允许的地址、凭据（键值对）、注入方式，这四项是机制；
//!   可用端点与调用注意事项只是给智能体的建议，不约束它。
//! - 智能体自己决定方法、路径、请求体、参数；网关不定义工具、不做字段映射，
//!   所以新增服务只需要加一张卡片，不改代码。
//! - 允许的地址既是"可请求的地址"，也是"可注入凭据的地址"：上游跳转到清单外的
//!   地址时不注入凭据（跳转本身允许，那是上游自己的分流行为）。
//! - 响应里的凭据一律抹掉，包括常见的编码形态。
//!
//! 参考实现对照（代码级）：mvplab-ai/agent-vault `agent_vault/server.py`
//! 的 auth_style（bearer/header/basic/query:<param>）、编码形态脱敏、响应上限与
//! 边界读取、以及拒绝智能体自带改道请求头；AliProgrammin/agentic-vault
//! `src/scrub/scrub.ts` 的"按值长度从长到短替换"。

use crate::error::{ConnectorError, ErrorCode, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// 短于这个长度的凭据不做替换，否则会把正文里的普通词误伤。
const MIN_SCRUB_LEN: usize = 4;
/// 响应体上限：超出即截断，避免单个响应吃光内存。
const MAX_BODY: usize = 512 * 1024;
/// 单次请求超时（秒）。卡片未配置时使用。
const DEFAULT_TIMEOUT: u64 = 120;

/// 智能体自带这些头可以把请求改道到别的源，从而绕过地址清单，一律拒绝。
const BLOCKED_HEADERS: [&str; 11] = [
    "host",
    ":authority",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-server",
    "x-real-ip",
    "x-original-host",
    "x-host",
];

/// 建议性端点：只用来告诉智能体"常用的是这几个"，不构成限制。
#[derive(Clone, Deserialize, Serialize, JsonSchema, Default)]
pub struct Endpoint {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub summary: String,
}

/// 一张服务卡片。前四个字段是机制，后两个只是建议。
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct ServiceCard {
    pub id: String,
    pub name: String,
    /// 允许的地址。填主机名；`*.example.com` 只匹配一层子域。
    #[serde(default)]
    pub addresses: Vec<String>,
    /// 凭据键值对。允许一个服务多个字段（例如 AppKey + Secret）。
    #[serde(default)]
    pub credentials: BTreeMap<String, String>,
    /// 注入方式：`bearer` | `header` | `basic` | `query:<参数名>` | `none`
    #[serde(default = "default_auth")]
    pub auth: String,
    /// `auth = header` 时注入到哪个请求头。
    #[serde(default)]
    pub header_name: String,
    /// 建议性：常用端点。
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    /// 建议性：调用注意事项。只写与调用直接相关的必要信息。
    #[serde(default)]
    pub notes: String,
    /// 单次请求超时（秒），留空用默认。
    #[serde(default)]
    pub timeout: Option<u64>,
}

fn default_auth() -> String {
    "bearer".to_string()
}

impl ServiceCard {
    /// 对外可见的元数据：只说明凭据配了几个字段，绝不回显值。
    pub fn metadata(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "addresses": self.addresses,
            "endpoint": self.endpoint(),
            "auth": self.auth,
            "header_name": self.header_name,
            "endpoints": self.endpoints,
            "notes": self.notes,
            "credential_fields": self.credentials.keys().collect::<Vec<_>>(),
            "has_credential": !self.credentials.is_empty(),
            // 代理去向如实回显：出站代理是容器环境变量决定的，代码不拦、也不猜。
            // 配置者看到 proxy_configured=true 而 bypass_matched 为空，就该明白
            // 这张卡片的请求会经代理转发，是否把地址加进 NO_PROXY 由人决定。
            "proxy_configured": proxy_configured(),
            "bypass_matched": self.addresses.iter().filter(|a| no_proxy_covers(a)).cloned().collect::<Vec<_>>(),
        })
    }

    /// 卡片里登记的第一个完整网址，作为这类服务的默认入口。
    /// 服务方给的原始信息通常就是完整网址，有了它调用时不必再拼。
    pub fn endpoint(&self) -> Option<String> {
        self.addresses
            .iter()
            .map(|a| a.trim())
            .find(|a| a.contains("://"))
            .map(str::to_string)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(bad("卡片编号只能用字母、数字、下划线或短横线，且不超过 64 字符"));
        }
        // 允许为空：本地命令类不需要地址。为空时任何 HTTP 目标都会被拒，是安全方向。
        // 服务方网址只填一个：这是调用时直接取用的入口，也是凭据可去的边界。
        if self.addresses.len() > 1 {
            return Err(bad("服务方网址只能填一个"));
        }
        // 允许直接填完整网址（服务方给的原始信息常是这样）：入库保留原样，比较时只取主机名。
        for a in &self.addresses {
            let a = a.trim();
            if a.is_empty() || a.contains(' ') {
                return Err(bad("允许的地址不能为空，也不能含空格"));
            }
            if a.contains("://") {
                let u = reqwest::Url::parse(a).map_err(|_| bad("这个地址不是合法网址"))?;
                if !matches!(u.scheme(), "http" | "https") {
                    return Err(bad("只有 http/https 网址可以这样填"));
                }
                if !u.username().is_empty() || u.password().is_some() {
                    return Err(bad("网址里不允许带用户名密码"));
                }
                if u.host_str().unwrap_or("").is_empty() {
                    return Err(bad("网址里没有主机名"));
                }
            } else if a.contains('/') {
                return Err(bad("只填主机名时不要带路径：要么填完整网址，要么只填主机名"));
            }
        }
        match self.auth.as_str() {
            "bearer" | "basic" | "none" => {}
            "header" => {
                if self.header_name.trim().is_empty() {
                    return Err(bad("注入方式为 header 时必须填请求头名"));
                }
            }
            other => {
                if let Some(param) = other.strip_prefix("query:") {
                    if param.is_empty() {
                        return Err(bad("注入方式 query: 后面必须跟参数名"));
                    }
                } else {
                    return Err(bad("注入方式只支持 bearer / header / basic / query:<参数名> / none"));
                }
            }
        }
        Ok(())
    }

    pub fn timeout_secs(&self) -> u64 {
        self.timeout.unwrap_or(DEFAULT_TIMEOUT).clamp(1, 10800)
    }

    /// 卡片里所有凭据值。
    pub fn values(&self) -> BTreeMap<String, String> {
        self.credentials.clone()
    }
}

fn bad(m: &str) -> ConnectorError {
    ConnectorError::new(ErrorCode::BadRequest, m)
}

fn internal(m: &str) -> ConnectorError {
    ConnectorError::internal(m)
}

/// 主机是否落在允许清单里。`*.example.com` 只匹配一层子域，避免 `a.b.evil.com` 混进来。
pub fn host_allowed(host: &str, patterns: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    patterns.iter().any(|p| {
        // 卡片允许直接填完整网址（服务方给的原始信息常是这样），比较时只取主机部分。
        let p = pattern_host(p).trim_end_matches('.').to_ascii_lowercase();
        match p.strip_prefix("*.") {
            Some(base) => {
                host.ends_with(&format!(".{base}")) && host.matches('.').count() == base.matches('.').count() + 1
            }
            None => host == p,
        }
    })
}

/// 把一条允许地址规范化成主机名：完整网址取主机，其余原样返回。
fn pattern_host(p: &str) -> String {
    let p = p.trim();
    if p.contains("://") {
        if let Ok(u) = reqwest::Url::parse(p) {
            if let Some(h) = u.host_str() { return h.to_string(); }
        }
    }
    p.to_string()
}

/// 校验目标地址：协议只允许 http/https，主机必须在允许清单里。
pub fn check_target(url: &str, card: &ServiceCard) -> Result<()> {
    let u = reqwest::Url::parse(url).map_err(|_| bad("目标地址不是合法网址"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(bad("只允许 http/https"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(bad("网址里不允许带用户名密码"));
    }
    let host = u.host_str().unwrap_or("").to_ascii_lowercase();
    if !host_allowed(&host, &card.addresses) {
        return Err(bad(&format!("目标主机 {host} 不在这张卡片的允许地址里")));
    }
    Ok(())
}

/// 把文本里出现的凭据值换成占位符。按值长度从长到短替换，避免短值先命中长值。
pub fn scrub(text: &str, values: &BTreeMap<String, String>) -> String {
    let mut pairs: Vec<(&String, &String)> = values.iter().collect();
    pairs.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    let mut out = text.to_string();
    for (name, value) in pairs {
        if value.len() >= MIN_SCRUB_LEN && out.contains(value.as_str()) {
            out = out.replace(value.as_str(), &format!("{{{{vault:{name}}}}}"));
        }
    }
    out
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// 连凭据的常见编码形态一起抹掉，防止它被转换过之后绕过替换。
pub fn scrub_all(text: &str, values: &BTreeMap<String, String>) -> String {
    let mut out = scrub(text, values);
    for encode in [base64_encode, percent_encode] {
        let encoded: BTreeMap<String, String> =
            values.iter().map(|(k, v)| (k.clone(), encode(v))).collect();
        out = scrub(&out, &encoded);
    }
    out
}

/// 环境里是否配了出站代理。
pub fn proxy_configured() -> bool {
    ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .any(|k| !std::env::var(k).unwrap_or_default().trim().is_empty())
}

/// 主机是否被 NO_PROXY 覆盖：支持逗号分隔、前导点、`*` 全局与通配卡片地址。
pub fn no_proxy_covers(host: &str) -> bool {
    let raw = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    let h = host.trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
    raw.split(',')
        .map(|e| e.trim().trim_start_matches('.').trim_start_matches("*.").to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .any(|e| e == "*" || h == e || h.ends_with(&format!(".{e}")))
}

/// 按卡片的注入方式，把凭据附加到外发请求上。
/// 返回（可能被改写的网址，需要附加的请求头）。
pub fn apply_auth(
    url: &str,
    card: &ServiceCard,
) -> Result<(String, Vec<(String, String)>)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let value = primary_value(card);
    if card.auth == "none" {
        return Ok((url.to_string(), headers));
    }
    match card.auth.as_str() {
        "bearer" => headers.push(("Authorization".into(), format!("Bearer {value}"))),
        "header" => headers.push((card.header_name.clone(), value)),
        "basic" => headers.push(("Authorization".into(), format!("Basic {}", base64_encode(&value)))),
        other => {
            let param = other
                .strip_prefix("query:")
                .ok_or_else(|| bad("注入方式不支持"))?;
            let sep = if url.contains('?') { '&' } else { '?' };
            return Ok((
                format!("{url}{sep}{param}={}", percent_encode(&value)),
                headers,
            ));
        }
    }
    Ok((url.to_string(), headers))
}

/// 智能体不得自己携带凭据明文；一旦在它给的内容里发现凭据值，直接拒绝。
pub fn reject_leaked_credential(parts: &[String], values: &BTreeMap<String, String>) -> Result<()> {
    for (name, value) in values {
        if value.len() >= MIN_SCRUB_LEN && parts.iter().any(|p| p.contains(value.as_str())) {
            return Err(bad(&format!(
                "请求里出现了凭据 {name} 的明文；只能按名字引用，不能把值写进请求"
            )));
        }
    }
    Ok(())
}

/// 拒绝智能体自带的改道请求头。
pub fn reject_rerouting_headers(headers: &BTreeMap<String, String>) -> Result<()> {
    for k in headers.keys() {
        if BLOCKED_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
            return Err(bad(&format!("请求头 {k} 可以改道请求，不允许自带")));
        }
    }
    Ok(())
}

/// 跟随跳转后的最终响应。
pub struct FinalResponse {
    pub status: u16,
    pub text: String,
    pub session: Option<String>,
}

/// 手动跟随跳转（客户端设成不自动跳）：清单内的下一跳继续带凭据，
/// 清单外照常跟过去但不再带凭据。这条是安全边界，所以不依赖 HTTP 客户端
/// 自己在重定向时怎么处理凭据头——那种行为随版本变，不可审。
pub async fn send_following(
    client: &reqwest::Client,
    card: &ServiceCard,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> Result<FinalResponse> {
    const MAX_REDIRECTS: usize = 5;
    let mut current = url.to_string();
    let mut carry = true;
    let mut first = true;
    for _ in 0..=MAX_REDIRECTS {
        let (target, mut all) = if carry {
            apply_auth(&current, card)?
        } else {
            (current.clone(), Vec::new())
        };
        if first {
            // 首跳（也就是调用方给的目标）必须在允许清单内，协议也只能是 http/https。
            check_target(&target, card)?;
        }
        all.extend(headers.iter().cloned());
        let m = reqwest::Method::from_bytes(method.to_ascii_uppercase().as_bytes())
            .map_err(|_| bad("请求方法不合法"))?;
        let mut req = client.request(m, target.as_str());
        for (k, v) in all {
            req = req.header(k, v);
        }
        if let Some(b) = body {
            req = req.body(b.to_string());
        }
        let resp = req.send().await.map_err(|_| internal("请求发送失败"))?;
        let status = resp.status().as_u16();
        let session = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let text = resp.text().await.map_err(|_| internal("响应读取失败"))?;
        let Some(loc) = location.filter(|_| (300..400).contains(&status)) else {
            return Ok(FinalResponse { status, text, session });
        };
        let base = reqwest::Url::parse(&target).map_err(|_| internal("跳转基准地址无法解析"))?;
        let next = base.join(&loc).map_err(|_| internal("跳转地址无法解析"))?;
        if !matches!(next.scheme(), "http" | "https") {
            return Err(bad("跳转目标不是 http/https"));
        }
        carry = host_allowed(next.host_str().unwrap_or(""), &card.addresses);
        current = next.to_string();
        first = false;
    }
    Err(internal("跳转次数超过上限"))
}

/// 执行一次通用 HTTP 请求：注入凭据、限制目标、抹掉响应里的凭据。
pub async fn execute_http(
    card: &ServiceCard,
    method: &str,
    url: &str,
    headers: BTreeMap<String, String>,
    body: Option<String>,
) -> Result<Value> {
    reject_rerouting_headers(&headers)?;
    let mut parts = vec![url.to_string(), method.to_string()];
    parts.extend(headers.iter().map(|(k, v)| format!("{k}:{v}")));
    if let Some(b) = &body {
        parts.push(b.clone());
    }
    reject_leaked_credential(&parts, &card.values())?;

    // 首跳必须落在允许地址清单内；后续每跳是否继续带凭据由 send_following 判定。
    check_target(url, card)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(card.timeout_secs()))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| internal("HTTP 客户端初始化失败"))?;

    let request_headers: Vec<(String, String)> =
        headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let resp = send_following(&client, card, method, url, &request_headers, body.as_deref()).await?;
    let status = resp.status;
    // 已知缺口：reqwest 未启用流式特性，这里先把整个响应读进内存再截断，
    // 只能约束交给模型的体积，约束不了进程内存。后续给 reqwest 打开 stream
    // 特性后改成边读边截止。
    // 先整体抹掉（跨边界的凭据也能完整替换），再按上限截断。
    let scrubbed = scrub_all(&resp.text, &card.values());
    let body_text: String = scrubbed.chars().take(MAX_BODY).collect();

    Ok(json!({ "status": status, "body": body_text }))
}

/// 取卡片的主凭据值：`query:`/`env:` 指定了字段名就取那个，否则取第一个。
fn primary_value(card: &ServiceCard) -> String {
    for prefix in ["query:", "env:"] {
        if let Some(name) = card.auth.strip_prefix(prefix) {
            if let Some(v) = card.credentials.get(name) {
                return v.clone();
            }
        }
    }
    card.credentials.values().next().cloned().unwrap_or_default()
}

/// 一次 MCP 往返。凭据按卡片配置注入，响应里的凭据抹掉。
async fn mcp_rpc(
    client: &reqwest::Client,
    card: &ServiceCard,
    target: &str,
    sid: Option<&str>,
    body: Value,
) -> Result<(Value, Option<String>)> {
    let mut headers = vec![
        ("Accept".to_string(), "application/json, text/event-stream".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    if let Some(id) = sid {
        headers.push(("Mcp-Session-Id".to_string(), id.to_string()));
        headers.push(("MCP-Protocol-Version".to_string(), "2024-11-05".to_string()));
    }
    let payload = body.to_string();
    let resp = send_following(client, card, "POST", target, &headers, Some(&payload)).await?;
    let session = resp.session;
    if !(200..300).contains(&resp.status) {
        // 上游的错误原文要带回来，否则没法判断是参数错还是上游错
        let short: String = resp.text.chars().take(300).collect();
        return Err(internal(&format!(
            "上游 MCP HTTP {}：{}",
            resp.status,
            scrub_all(&short, &card.values())
        )));
    }
    if resp.status == 202 {
        return Ok((Value::Null, session));
    }
    let text = resp.text;
    if let Ok(v) = serde_json::from_str::<Value>(&text) {
        return Ok((v, session));
    }
    for event in text.replace("\r\n", "\n").split("\n\n") {
        let data = event
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim_start)
            .collect::<Vec<_>>()
            .join("\n");
        if let Ok(v) = serde_json::from_str::<Value>(&data) {
            if v.get("id").is_some() {
                return Ok((v, session));
            }
        }
    }
    Err(internal("上游 MCP 响应格式无法识别"))
}

/// 按 MCP 协议调用一次远程工具：握手 → 通知就绪 → 调用 → 结束会话。
/// 目标网址每次由模型给出（与 execute_http 一致）：卡片只负责“允许去哪 + 凭据怎么带”。
pub async fn execute_mcp(
    card: &ServiceCard,
    target: &str,
    tool_name: &str,
    arguments: Value,
) -> Result<Value> {
    if tool_name.trim().is_empty() {
        return Err(bad("MCP 调用必须给 tool_name"));
    }
    reject_leaked_credential(
        &[target.to_string(), tool_name.to_string(), arguments.to_string()],
        &card.values(),
    )?;
    check_target(target, card)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(card.timeout_secs()))
        // 跳转交给 send_following 逐跳判定，客户端自己不跳
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| internal("HTTP 客户端初始化失败"))?;

    let (init, sid) = mcp_rpc(
        &client,
        card,
        target,
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":"credential-proxy-gateway","version":"0.1.0"}}}),
    )
    .await?;
    if init.get("error").is_some() {
        return Err(internal("上游 MCP 拒绝了初始化"));
    }
    let _ = mcp_rpc(
        &client,
        card,
        target,
        sid.as_deref(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    let (value, _) = mcp_rpc(
        &client,
        card,
        target,
        sid.as_deref(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
               "params":{"name":tool_name,"arguments":arguments}}),
    )
    .await?;
    if let Some(id) = &sid {
        let _ = client
            .delete(target)
            .header("Mcp-Session-Id", id)
            .send()
            .await;
    }
    if value.get("error").is_some() {
        return Err(internal(&format!(
            "上游 MCP 拒绝了这次调用：{}",
            scrub_all(&value["error"].to_string(), &card.values())
        )));
    }
    let result = value.get("result").cloned().unwrap_or(Value::Null);
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(internal(&format!(
            "上游 MCP 返回错误：{}",
            scrub_all(&result.to_string(), &card.values())
        )));
    }
    let scrubbed = scrub_all(&result.to_string(), &card.values());
    serde_json::from_str(&scrubbed).map_err(|_| internal("结果整理失败"))
}

/// 这条命令是否会调用 git。
///
/// 不只看首词：命令常被 `sh -c "..."` 包裹，或出现在 `&&` / `;` 之后，
/// 只看首词会漏注入。这里按词边界扫全串，命中独立的 `git` 或 `/x/git`。
/// 注入的只是环境变量，对非 git 进程没有副作用，所以宁可宽一点。
fn command_invokes_git(command: &str) -> bool {
    command
        .split(|c: char| {
            c.is_whitespace()
                || matches!(c, ';' | '&' | '|' | '(' | ')' | '`' | '\'' | '"' | '=' | ',')
        })
        .map(|t| t.trim_matches(|c: char| c == '\'' || c == '"'))
        .any(|t| t.rsplit('/').next() == Some("git"))
}

/// 执行一次本地命令：凭据作为环境变量注入子进程，输出里的凭据抹掉。
pub async fn execute_command(
    card: &ServiceCard,
    command: &str,
    cwd: &str,
    timeout: u64,
) -> Result<Value> {
    reject_leaked_credential(&[command.to_string(), cwd.to_string()], &card.values())?;
    let argv = crate::services::parse_command(command)?;
    let mut cmd = tokio::process::Command::new(
        argv.first().ok_or_else(|| bad("命令为空"))?,
    );
    cmd.args(&argv[1..]);
    tokio::fs::create_dir_all(cwd)
        .await
        .map_err(|_| internal("工作目录不可用"))?;
    cmd.current_dir(cwd);
    // 凭据只以环境变量形式进入子进程，不进入命令行（否则会出现在进程列表里）。
    for (k, v) in &card.credentials {
        cmd.env(k, v);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_PAGER", "cat")
        .env("GIT_PAGER", "cat");
    // git 的默认配置属于机制，由程序兜住，不让调用方每次手写：
    // 目录信任与提交身份总是给；只有这张卡片带 GH_TOKEN 时才挂凭据助手，
    // 否则会去调用一个没有令牌的 gh，反而让调用方困惑。
    if command_invokes_git(command) {
        let mut keys: Vec<(&str, &str)> = vec![
            ("safe.directory", "*"),
            ("user.name", "vault-connector"),
            ("user.email", "vault@localhost"),
        ];
        if card.credentials.contains_key("GH_TOKEN") {
            keys.push(("credential.helper", "!gh auth git-credential"));
        }
        cmd.env("GIT_CONFIG_COUNT", keys.len().to_string());
        for (i, (key, value)) in keys.iter().enumerate() {
            cmd.env(format!("GIT_CONFIG_KEY_{i}"), *key);
            cmd.env(format!("GIT_CONFIG_VALUE_{i}"), *value);
        }
    }
    cmd.kill_on_drop(true);
    let secs = timeout.clamp(1, 10800);
    let out = tokio::time::timeout(std::time::Duration::from_secs(secs), cmd.output())
        .await
        .map_err(|_| internal("命令超时"))?
        .map_err(|_| internal("命令执行失败"))?;
    let values = card.values();
    Ok(json!({
        "exit_code": out.status.code(),
        "stdout": scrub_all(&String::from_utf8_lossy(&out.stdout), &values),
        "stderr": scrub_all(&String::from_utf8_lossy(&out.stderr), &values),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> ServiceCard {
        ServiceCard {
            id: "mineru".into(),
            name: "MinerU".into(),
            addresses: vec!["mineru.net".into()],
            credentials: BTreeMap::from([("KEY".to_string(), "sk-secret-value".to_string())]),
            auth: "bearer".into(),
            header_name: String::new(),
            endpoints: vec![],
            notes: String::new(),
            timeout: None,
        }
    }

    #[test]
    fn detects_git_invocation_beyond_first_word() {
        for yes in [
            "git status",
            "git -C /app/data/github/log status",
            "/usr/bin/git push",
            "sh -c \"git commit -m x\"",
            "cd /tmp && git log",
            "set -e; git fetch",
            "env A=1 git status",
            "echo ok; git status",
        ] {
            assert!(command_invokes_git(yes), "应识别为 git 调用: {yes}");
        }
        for no in [
            "ls -la",
            "echo github",
            "curl https://github.com",
            "gh api repos",
            "docker ps",
            "git-credential-cache",
            "digital",
            "ls /usr/bin",
        ] {
            assert!(!command_invokes_git(no), "不应误判为 git: {no}");
        }
    }

    #[test]
    fn service_url_accepts_full_url_and_hostname() {
        // 服务方给的是完整网址：入库原样保留，匹配时只取主机。
        let a = vec!["https://mcp.tikhub.io/wechat/mcp".to_string()];
        assert!(host_allowed("mcp.tikhub.io", &a));
        assert!(!host_allowed("evil.com", &a));
        let b = vec!["*.aliyuncs.com".to_string()];
        assert!(host_allowed("bucket.aliyuncs.com", &b));
        assert!(!host_allowed("a.b.aliyuncs.com", &b), "通配只匹配一层");
    }

    #[test]
    fn service_url_is_single_valued() {
        let mut c = card();
        assert!(c.validate().is_ok());
        c.addresses = vec!["a.example.com".into(), "b.example.com".into()];
        assert!(c.validate().is_err(), "服务方网址只能填一个");
        c.addresses = vec!["https://mcp.tikhub.io/wechat/mcp".into()];
        assert!(c.validate().is_ok(), "完整网址应当被接受");
        assert_eq!(c.endpoint().as_deref(), Some("https://mcp.tikhub.io/wechat/mcp"));
        c.addresses = vec!["https://user:pass@evil.com/x".into()];
        assert!(c.validate().is_err(), "网址里不允许带凭据");
    }

    #[test]
    fn host_allowlist_matches_single_label_wildcard() {
        let a = vec!["api.example.com".to_string(), "*.example.org".to_string()];
        assert!(host_allowed("api.example.com", &a));
        assert!(host_allowed("API.EXAMPLE.COM.", &a));
        assert!(host_allowed("x.example.org", &a));
        assert!(!host_allowed("a.b.example.org", &a), "通配只匹配一层");
        assert!(!host_allowed("evil.com", &a));
        assert!(!host_allowed("example.org.evil.com", &a));
    }

    #[test]
    fn target_check_blocks_foreign_host_and_bad_scheme() {
        let c = card();
        assert!(check_target("https://mineru.net/api/v4/x", &c).is_ok());
        assert!(check_target("https://oss.aliyuncs.com/a.zip", &c).is_ok());
        assert!(check_target("https://evil.com/steal", &c).is_err());
        assert!(check_target("file:///etc/passwd", &c).is_err());
        assert!(check_target("https://user:pw@mineru.net/", &c).is_err());
    }

    #[test]
    fn scrub_covers_encoded_forms_longest_first() {
        let v = BTreeMap::from([("K".to_string(), "sk-abcdef".to_string())]);
        assert_eq!(scrub("token=sk-abcdef", &v), "token={{vault:K}}");
        let b64 = base64_encode("sk-abcdef");
        assert!(scrub_all(&format!("Basic {b64}"), &v).contains("{{vault:K}}"));
        assert!(scrub_all(&format!("k={}", percent_encode("sk-abcdef")), &v).contains("{{vault:K}}"));
    }

    #[test]
    fn rejects_agent_supplied_plaintext_and_rerouting_headers() {
        let c = card();
        let vals = c.values();
        assert!(reject_leaked_credential(&["sk-secret-value".into()], &vals).is_err());
        assert!(reject_leaked_credential(&["fine".into()], &vals).is_ok());
        let mut h = BTreeMap::new();
        h.insert("X-Forwarded-Host".to_string(), "evil.com".to_string());
        assert!(reject_rerouting_headers(&h).is_err());
    }

    #[test]
    fn auth_styles_cover_four_forms() {
        let mut c = card();
        let (_, h) = apply_auth("https://mineru.net/a", &c).unwrap();
        assert_eq!(h[0].1, "Bearer sk-secret-value");

        c.auth = "header".into();
        c.header_name = "X-API-Key".into();
        let (_, h) = apply_auth("https://mineru.net/a", &c).unwrap();
        assert_eq!(h[0].0, "X-API-Key");

        c.auth = "query:token".into();
        let (u, h) = apply_auth("https://mineru.net/a", &c).unwrap();
        assert!(u.contains("token=sk-secret-value") && h.is_empty());

        c.auth = "basic".into();
        let (_, h) = apply_auth("https://mineru.net/a", &c).unwrap();
        assert!(h[0].1.starts_with("Basic "));
    }

    #[test]
    fn card_validation_requires_address_and_valid_auth() {
        let mut c = card();
        assert!(c.validate().is_ok());
        // 地址允许为空：本地命令类不需要地址。为空时任何 HTTP 目标都会被拒，
        // 属于安全方向的失败，所以这里校验应当通过。
        c.addresses.clear();
        assert!(c.validate().is_ok(), "地址可以为空");
        c.addresses = vec!["api.example.com".into()];
        c.auth = "magic".into();
        assert!(c.validate().is_err());
        c.auth = "header".into();
        c.header_name = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn primary_value_follows_auth_target() {
        let mut c = card();
        c.credentials = BTreeMap::from([
            ("APPKEY".to_string(), "aaa".to_string()),
            ("SECRET".to_string(), "sss".to_string()),
        ]);
        c.auth = "query:SECRET".to_string();
        assert_eq!(primary_value(&c), "sss");
        c.auth = "env:APPKEY".to_string();
        assert_eq!(primary_value(&c), "aaa");
        c.auth = "header".to_string();
        assert_eq!(primary_value(&c), "aaa", "未指定时取第一个");
    }

    #[test]
    fn metadata_never_echoes_credential_values() {
        let c = card();
        let m = c.metadata().to_string();
        assert!(!m.contains("sk-secret-value"));
        assert!(m.contains("credential_fields"));
    }
}
