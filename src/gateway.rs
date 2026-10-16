//! 服务卡片与通用凭据注入。凭据只注入外发请求，永不进入模型上下文。
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
            "auth": self.auth,
            "header_name": self.header_name,
            "endpoints": self.endpoints,
            "notes": self.notes,
            "credential_fields": self.credentials.keys().collect::<Vec<_>>(),
            "has_credential": !self.credentials.is_empty(),
        })
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
        if self.addresses.is_empty() {
            return Err(bad("必须至少填一个允许的地址，否则凭据无处可去"));
        }
        for a in &self.addresses {
            if a.trim().is_empty() || a.contains('/') || a.contains(' ') {
                return Err(bad("允许的地址只填主机名，例如 api.example.com 或 *.example.com"));
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
        let p = p.trim_end_matches('.').to_ascii_lowercase();
        match p.strip_prefix("*.") {
            Some(base) => {
                host.ends_with(&format!(".{base}")) && host.matches('.').count() == base.matches('.').count() + 1
            }
            None => host == p,
        }
    })
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

/// 按卡片的注入方式，把凭据附加到外发请求上。
/// 返回（可能被改写的网址，需要附加的请求头）。
pub fn apply_auth(
    url: &str,
    card: &ServiceCard,
) -> Result<(String, Vec<(String, String)>)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    // 单字段卡片用第一个字段的值；多字段卡片按 `auth` 指定，缺省取第一个。
    let value = card
        .credentials
        .values()
        .next()
        .cloned()
        .unwrap_or_default();
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

    check_target(url, card)?;
    let (final_url, auth_headers) = apply_auth(url, card)?;
    // 注入后的目标也要校验：query 注入不会换主机，但仍走一遍以防拼接出错。
    check_target(&final_url, card)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(card.timeout_secs()))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|_| internal("HTTP 客户端初始化失败"))?;

    let m = reqwest::Method::from_bytes(method.to_ascii_uppercase().as_bytes())
        .map_err(|_| bad("请求方法不合法"))?;
    let mut req = client.request(m, final_url.as_str());
    let mut all_headers: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    all_headers.extend(auth_headers);
    for (k, v) in all_headers {
        req = req.header(k, v);
    }
    if let Some(b) = body {
        req = req.body(b);
    }
    let resp = req.send().await.map_err(|_| internal("请求发送失败"))?;
    let status = resp.status().as_u16();
    // 已知缺口：reqwest 未启用流式特性，这里先把整个响应读进内存再截断，
    // 只能约束交给模型的体积，约束不了进程内存。后续给 reqwest 打开 stream
    // 特性后改成边读边截止。
    let text = resp.text().await.map_err(|_| internal("响应读取失败"))?;
    // 先整体抹掉（跨边界的凭据也能完整替换），再按上限截断。
    let scrubbed = scrub_all(&text, &card.values());
    let body_text: String = scrubbed.chars().take(MAX_BODY).collect();

    Ok(json!({ "status": status, "body": body_text }))
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
            addresses: vec!["mineru.net".into(), "*.aliyuncs.com".into()],
            credentials: BTreeMap::from([("KEY".to_string(), "sk-secret-value".to_string())]),
            auth: "bearer".into(),
            header_name: String::new(),
            endpoints: vec![],
            notes: String::new(),
            timeout: None,
        }
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
        c.addresses.clear();
        assert!(c.validate().is_err(), "没有地址等于凭据无处可去");
        c.addresses = vec!["api.example.com".into()];
        c.auth = "magic".into();
        assert!(c.validate().is_err());
        c.auth = "header".into();
        c.header_name = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn metadata_never_echoes_credential_values() {
        let c = card();
        let m = c.metadata().to_string();
        assert!(!m.contains("sk-secret-value"));
        assert!(m.contains("credential_fields"));
    }
}
