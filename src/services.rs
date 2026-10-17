//! MCP registry and credential-use adapters. Secret-bearing records remain inside Vault.
//!
//! Design (see README "服务适配机制设计" / "Service Adapter Design"):
//! - Only three adapter classes exist: remote MCP, HTTP API, local CLI program. They are one
//!   "step list" model mapped onto three executors, not three independent logics.
//! - Commonality (step execution, MCP handshake, retry, timeout, credential injection, result
//!   redaction) lives in code; specificity (URL, parameter semantics, notes) lives in the
//!   service record, so adding a service needs no code change.
//! - Specificity is split by cost of error: parameter semantics go to advisory text shown to the
//!   agent on every call, while credential placement and wait conditions stay structured fields
//!   executed by the program. Handing the credential to the model would break the confidentiality
//!   promise; handing polling to the model would turn one call into dozens of round-trips.
use crate::{audit::AuditLog, state::AppState, error::{ConnectorError, ErrorCode, Result}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use schemars::JsonSchema;
use std::collections::HashMap;use std::sync::{Arc,OnceLock};use tokio::sync::{Mutex as AsyncMutex,Semaphore};

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ServiceTool {
    pub name: String,
    /// 参数示例。声明为对象，避免自由形态值在传输中被压成字符串；值本身仍不限制。
    #[serde(default)] pub arguments: HashMap<String, Value>,
}

/// 两种可接受的形状：对象列表（带参数示例）与纯字符串列表（只有工具名）。
fn tools_from_value(raw: &Value) -> Option<Vec<ServiceTool>> {
    if let Ok(v) = serde_json::from_value::<Vec<ServiceTool>>(raw.clone()) { return Some(v); }
    if let Ok(v) = serde_json::from_value::<Vec<String>>(raw.clone()) {
        return Some(v.into_iter().map(|name| ServiceTool { name, arguments: HashMap::new() }).collect());
    }
    None
}

/// 宽容读取 tools：历史数据里它可能被写成 JSON 字符串（无类型字段的老问题），
/// 也可能只有一串工具名。尽量还原成提醒内容，实在读不出才退化为空——
/// 绝不让一条坏记录炸掉整个注册表。
fn lenient_tools<'de, D>(d: D) -> std::result::Result<Vec<ServiceTool>, D::Error>
where D: serde::Deserializer<'de> {
    let raw = Value::deserialize(d)?;
    if raw.is_null() { return Ok(vec![]); }
    if let Some(v) = tools_from_value(&raw) { return Ok(v); }
    if let Some(s) = raw.as_str() {
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            if let Some(v) = tools_from_value(&parsed) { return Ok(v); }
        }
    }
    Ok(vec![])
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct ServiceRecord {
    pub id: String,
    pub name: String,
    pub adapter: String,
    #[serde(default)] pub interface_type: String,
    #[serde(default)] pub invocation_method: String,
    #[serde(default)] pub url: String,
    #[serde(default)] pub credential: String,
    #[serde(default, deserialize_with = "lenient_tools")] pub tools: Vec<ServiceTool>,
    #[serde(default)] pub notes: String,
}
impl ServiceRecord {
    pub fn connection_type(&self) -> &str {
        match self.adapter.as_str() { "exa"|"wechat"=>"remote_mcp", "doubao"=>"http_api", "github"=>"local_program", _=>"unsupported" }
    }
    pub fn metadata(&self) -> Value {
        json!({"id":self.id,"name":self.name,"adapter":self.adapter,"interface_type":self.connection_type(),"invocation_method":self.adapter,"url":self.url,
            "tools":self.tools,"notes":self.notes,"has_credential":!self.credential.is_empty()})
    }
    pub fn validate(&self) -> Result<()> {
        if (!self.interface_type.is_empty() && self.interface_type != self.connection_type()) ||
           (!self.invocation_method.is_empty() && self.invocation_method != self.adapter) {
            return Err(ConnectorError::new(ErrorCode::BadRequest,"接口类型与调用方法不匹配"));
        }
        if self.id.is_empty() || self.id.len()>64 || !self.id.chars().all(|c| c.is_ascii_alphanumeric()||c=='-'||c=='_') {
            return Err(ConnectorError::new(ErrorCode::BadRequest,"invalid registration id"));
        }
        if !["exa","doubao","wechat","github"].contains(&self.adapter.as_str()) {
            return Err(ConnectorError::new(ErrorCode::BadRequest,"unsupported adapter"));
        }
        if self.adapter!="github" {
            let u=reqwest::Url::parse(&self.url).map_err(|_| ConnectorError::new(ErrorCode::BadRequest,"invalid upstream URL"))?;
            if !["https","http"].contains(&u.scheme()) || !u.username().is_empty() || u.password().is_some() {
                return Err(ConnectorError::new(ErrorCode::BadRequest,"invalid upstream URL"));
            }
        }
        Ok(())
    }
}

pub fn redact(text:&str, secret:&str)->String {
    if secret.is_empty(){text.to_string()}else{text.replace(secret,"[凭据已隐藏]")}
}
fn internal(message:&str)->ConnectorError {ConnectorError::internal(message)}
fn http_client()->Result<reqwest::Client>{reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).redirect(reqwest::redirect::Policy::none()).build().map_err(|_|internal("HTTP client initialization failed"))}
/// 读取数字参数：按数字取；传输过程把它变成字符串时也照用，不因此拒绝调用。
fn number_arg(args:&Value,key:&str)->Option<u64>{
    args.get(key).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok())))
}
async fn upstream_rpc(client:&reqwest::Client,url:&str,key:&str,sid:Option<&str>,body:Value)->Result<(Value,Option<String>)> {
    let mut req=client.post(url).header("Accept","application/json, text/event-stream").json(&body);
    if !key.is_empty(){req=req.header("Authorization",key)}
    if let Some(id)=sid {req=req.header("Mcp-Session-Id",id).header("MCP-Protocol-Version","2024-11-05")}
    let r=req.send().await.map_err(|_|internal("upstream MCP transport failed"))?;
    let status=r.status();let session=r.headers().get("mcp-session-id").and_then(|v|v.to_str().ok()).map(str::to_owned);
    if !status.is_success(){return Err(internal(&format!("upstream MCP HTTP {}",status.as_u16())))}
    if status.as_u16()==202 {return Ok((Value::Null,session))}
    let text=r.text().await.map_err(|_|internal("upstream response unreadable"))?;
    if let Ok(value)=serde_json::from_str(&text){return Ok((value,session))}
    for event in text.replace("\r\n","\n").split("\n\n") {
        let data=event.lines().filter_map(|l|l.strip_prefix("data:")).map(str::trim_start).collect::<Vec<_>>().join("\n");
        if let Ok(value)=serde_json::from_str::<Value>(&data){if value.get("id").is_some(){return Ok((value,session))}}
    }
    Err(internal("upstream MCP response format is invalid"))
}
async fn native_call(s:&ServiceRecord,tool:&str,args:Value)->Result<Value>{
    let client=http_client()?;let mut url=reqwest::Url::parse(&s.url).map_err(|_|internal("invalid upstream URL"))?;
    let header=if s.adapter=="exa" {if !s.credential.is_empty(){url.query_pairs_mut().append_pair("exaApiKey",&s.credential);} ""}else{&s.credential};
    let (init,sid)=upstream_rpc(&client,url.as_str(),header,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"credential-proxy-gateway","version":"0.1.0"}}})).await?;
    if init.get("error").is_some(){return Err(internal("upstream MCP initialization rejected"))}
    let _=upstream_rpc(&client,url.as_str(),header,sid.as_deref(),json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await?;
    let result=upstream_rpc(&client,url.as_str(),header,sid.as_deref(),json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":args}})).await;
    if let Some(id)=sid{let _=client.delete(url.as_str()).header("Mcp-Session-Id",id).header("Authorization",header).send().await;}
    let (value,_)=result?;
    if value.get("error").is_some(){return Err(internal("upstream MCP tool rejected request"))}
    let result=value.get("result").cloned().unwrap_or(Value::Null);
    if result.get("isError").and_then(Value::as_bool)==Some(true){return Err(internal("upstream MCP tool returned an error"))}
    Ok(result)
}
fn clean_highlight(s:&str)->String{s.replace("<em class=\"highlight\">","").replace("</em>","")}
fn clean_wechat(v:&mut Value){match v {Value::Array(a)=>for x in a{clean_wechat(x)},Value::Object(o)=>{for(k,x)in o.iter_mut(){if ["title","desc"].contains(&k.as_str()){if let Some(s)=x.as_str(){*x=Value::String(clean_highlight(s))}}else{clean_wechat(x)}}if let Some(timestamp)=o.get("date").and_then(Value::as_i64){if let Ok(t)=time::OffsetDateTime::from_unix_timestamp(timestamp){let t=t.to_offset(time::UtcOffset::from_hms(8,0,0).unwrap());o.insert("date_local".into(),Value::String(format!("{}",t)));}}},_=>{}}}

/// 调用入口：负责审计（成功与失败都留痕），实际派发交给 invoke_record。
pub async fn invoke(st:Arc<AppState>,id:&str,tool:&str,args:Value)->Result<Value>{
    let record=st.vault.get_service_record(id)?;
    let preview=audit_preview(&args.to_string(),&record.credential);
    match invoke_record(&record,tool,args).await{
        Ok(value)=>{
            st.audit.record(AuditLog::entry("credential_invoke").with_detail(json!({"service":id,"tool":tool,"args":preview})));
            Ok(value)
        }
        Err(e)=>{
            st.audit.record(AuditLog::entry("credential_invoke_failed").with_detail(json!({"service":id,"tool":tool,"args":preview,"code":e.code.as_str(),"message":audit_preview(&e.message,&record.credential)})));
            Err(e)
        }
    }
}
async fn invoke_record(record:&ServiceRecord,tool:&str,mut args:Value)->Result<Value>{
    let result=match record.adapter.as_str(){
        "doubao"=>{let q=args.get("Query").or_else(||args.get("query")).and_then(Value::as_str).unwrap_or("");if q.is_empty(){return Err(ConnectorError::new(ErrorCode::BadRequest,"Query required"))}let body=json!({"Query":q,"SearchType":"web","Count":number_arg(&args,"Count").or_else(||number_arg(&args,"count")).unwrap_or(10),"NeedSummary":args.get("need_summary").and_then(Value::as_bool).unwrap_or(true)});let r=http_client()?.post(&record.url).header("Authorization",&record.credential).json(&body).send().await.map_err(|_|internal("search transport failed"))?;if !r.status().is_success(){return Err(internal(&format!("search HTTP {}",r.status().as_u16())))}r.json::<Value>().await.map_err(|_|internal("search result is not JSON"))?},
        "wechat"=>{if let Some(o)=args.as_object_mut(){o.entry("business_type".to_string()).or_insert(json!("article"));o.entry("sort".to_string()).or_insert(json!("0"));}let mut result=native_call(&record,"wechat_search_v2_fetch_search",args).await?;if let Some(content)=result.get_mut("content").and_then(Value::as_array_mut){for item in content{if let Some(raw)=item.get("text").and_then(Value::as_str){if let Ok(mut parsed)=serde_json::from_str::<Value>(raw){clean_wechat(&mut parsed);item["text"]=json!(parsed.to_string());}}}}result},
        "exa"=>{if args.get("objective").and_then(Value::as_str).unwrap_or("").trim().is_empty(){return Err(ConnectorError::new(ErrorCode::BadRequest,"objective required"))}native_call(&record,tool,args).await?},
        "github"=>github_call(&record,tool,args).await?,
        _=>return Err(internal("adapter not supported")),
    };
    let text=redact(&result.to_string(),&record.credential);serde_json::from_str(&text).map_err(|_|internal("result normalization failed"))
}
/// 审计摘要：先抹掉凭据再限长，只留复盘够用的信息，绝不写入密钥本身。
fn audit_preview(text:&str,secret:&str)->String{redact(text,secret).chars().take(240).collect()}
/// GitHub 子进程的全局限流闸门。上限可用 GITHUB_MAX_CONCURRENCY 覆盖（1..=64，默认 4）。
/// 没有它时，一口气来 10 个调用就会同时起 10 个进程，容易把 CPU/内存打满。
fn github_gate()->&'static Semaphore{
    static GATE:OnceLock<Semaphore>=OnceLock::new();
    GATE.get_or_init(||{let n=std::env::var("GITHUB_MAX_CONCURRENCY").ok().and_then(|v|v.parse::<usize>().ok()).filter(|n|(1..=64).contains(n)).unwrap_or(4);Semaphore::new(n)})
}
/// 按工作目录加闸：**不同仓库并行、同一仓库排队**。
/// 直接并发操作同一仓库会撞 .git/index.lock，所以并发要靠这个粒度而不是一把大锁。
fn dir_gate(dir:&str)->Arc<AsyncMutex<()>>{
    static DIRS:OnceLock<std::sync::Mutex<HashMap<String,Arc<AsyncMutex<()>>>>> =OnceLock::new();
    let dirs=DIRS.get_or_init(||std::sync::Mutex::new(HashMap::new()));
    let mut guard=dirs.lock().unwrap_or_else(|e|e.into_inner());
    guard.entry(dir.to_string()).or_insert_with(||Arc::new(AsyncMutex::new(()))).clone()
}
async fn github_call(s:&ServiceRecord,tool:&str,args:Value)->Result<Value>{
    let cwd=args.get("cwd").and_then(Value::as_str).unwrap_or("/app/data/github").to_string();
    let _permit=github_gate().acquire().await.map_err(|_|internal("GitHub concurrency gate unavailable"))?;
    let dir=dir_gate(&cwd);let _dir_guard=dir.lock().await;
    let mut cmd=match tool{"gh_git"=>tokio::process::Command::new("git"),"gh_run"|"gh_status"=>tokio::process::Command::new("gh"),_=>return Err(ConnectorError::new(ErrorCode::BadRequest,"unknown GitHub tool"))};
    if tool=="gh_status"{cmd.args(["auth","status"]);}else{
        let command=args.get("command").and_then(Value::as_str).ok_or_else(||ConnectorError::new(ErrorCode::BadRequest,"command required"))?;
        let argv=parse_command(command)?;cmd.args(argv);
    }
    tokio::fs::create_dir_all(&cwd).await.map_err(|_|internal("GitHub work directory unavailable"))?;cmd.current_dir(&cwd);
    cmd.env("GH_TOKEN",&s.credential).env("GH_PROMPT_DISABLED","1").env("GH_PAGER","cat").env("GIT_PAGER","cat").env("GIT_TERMINAL_PROMPT","0");
    if tool=="gh_git"{
        // git 的默认配置：凭据助手 + 目录信任 + 提交身份。
        // 这些以前要每次手工 config，现在由程序注入，调用方不用管。
        cmd.env("GIT_CONFIG_COUNT","4")
            .env("GIT_CONFIG_KEY_0","credential.helper").env("GIT_CONFIG_VALUE_0","!gh auth git-credential")
            .env("GIT_CONFIG_KEY_1","safe.directory").env("GIT_CONFIG_VALUE_1","*")
            .env("GIT_CONFIG_KEY_2","user.name").env("GIT_CONFIG_VALUE_2","vault-connector")
            .env("GIT_CONFIG_KEY_3","user.email").env("GIT_CONFIG_VALUE_3","vault@localhost");
    }
    let timeout=args.get("timeout").and_then(Value::as_u64).unwrap_or(120).clamp(1,10800);cmd.kill_on_drop(true);
    let output=tokio::time::timeout(std::time::Duration::from_secs(timeout),cmd.output()).await.map_err(|_|internal("GitHub command timed out"))?.map_err(|_|internal("GitHub executable failed"))?;
    Ok(json!({"exit_code":output.status.code(),"stdout":redact(&String::from_utf8_lossy(&output.stdout),&s.credential),"stderr":redact(&String::from_utf8_lossy(&output.stderr),&s.credential)}))
}
/// 拆命令：空白分词，单/双引号成对包裹。
/// 注意反斜杠**不再**当转义符：旧实现会把 `\u517c`、`C:\path`、正则 `\d` 里的反斜杠静默吃掉，
/// 造成参数被悄悄改坏。唯一保留的转义是双引号里的 `\"`，用来表达字面双引号。
pub(crate) fn parse_command(s:&str)->Result<Vec<String>> {
    let mut words=Vec::new();let mut word=String::new();let mut quote:Option<char>=None;let mut started=false;let mut chars=s.chars().peekable();
    while let Some(c)=chars.next(){
        match quote{
            Some(q)=>{
                if c=='\\'&&q=='"'&&chars.peek()==Some(&'"'){word.push('"');chars.next();}
                else if c==q{quote=None;}
                else{word.push(c);}
                started=true;
            }
            None=>{
                if c=='\''||c=='"'{quote=Some(c);started=true;}
                else if c.is_whitespace(){if started{words.push(std::mem::take(&mut word));started=false;}}
                else{word.push(c);started=true;}
            }
        }
    }
    if quote.is_some(){return Err(ConnectorError::new(ErrorCode::BadRequest,"unclosed command quoting"))}if started{words.push(word)}if words.is_empty(){return Err(ConnectorError::new(ErrorCode::BadRequest,"empty command"))}Ok(words)
}
#[cfg(test)]mod tests{use super::*;
#[test]fn command_parser_keeps_backslashes(){
    // 反斜杠必须原样保留：旧实现会吞掉它，导致 `-f message=\u517c` 变成 `u517c`
    assert_eq!(parse_command(r"--jq .a\b").unwrap(),vec!["--jq",r".a\b"]);
    assert_eq!(parse_command(r#"--notes "\u517c 容""#).unwrap(),vec!["--notes",r"\u517c 容"]);
    assert_eq!(parse_command(r"--path C:\tmp\repo").unwrap(),vec!["--path",r"C:\tmp\repo"]);
    // 双引号内的 \" 仍表示字面双引号
    assert_eq!(parse_command(r#"--notes "a\"b""#).unwrap(),vec!["--notes","a\"b"]);
    assert!(parse_command("  ").is_err());
    assert!(parse_command("'unclosed").is_err());
}
#[test]fn tools_forms_decode_leniently(){
    // 对象列表、纯名字列表、被压成字符串的列表，都要能还原
    for raw in [
        r#"[{"name":"gh_run","arguments":{"command":"gh子命令"}}]"#,
        r#"["gh_status"]"#,
    ] {
        let v: Value = serde_json::from_str(raw).unwrap();
        for shape in [v.clone(), Value::String(raw.to_string())] {
            let s = ServiceRecord{
                id:"t".into(),name:"t".into(),adapter:"github".into(),
                interface_type:String::new(),invocation_method:String::new(),
                url:String::new(),credential:String::new(),
                tools:tools_from_value(&shape).unwrap_or_default(),
                notes:String::new(),
            };
            assert!(!s.tools.is_empty(), "tools 不该被静默丢弃: {shape}");
            assert_eq!(s.tools[0].name, if raw.contains("gh_run") {"gh_run"} else {"gh_status"});
        }
    }
}
#[test]fn service_arguments_and_redaction(){assert_eq!(parse_command("issue create --title '中文 标题'").unwrap(),vec!["issue","create","--title","中文 标题"]);assert!(parse_command("'unclosed").is_err());assert_eq!(redact("Bearer secret","secret"),"Bearer [凭据已隐藏]");let mut v=json!({"title":"<em class=\"highlight\">中文</em>","date":0});clean_wechat(&mut v);assert_eq!(v["title"],"中文");assert!(v.get("date_local").is_some());}}

#[cfg(test)] mod interface_tests {
    use super::*;
    #[test] fn legacy_metadata_and_type_validation() {
        for (method, kind) in [("exa","remote_mcp"),("wechat","remote_mcp"),("doubao","http_api"),("github","local_program")] {
            let mut record: ServiceRecord = serde_json::from_value(json!({"id":"test","name":"test","adapter":method,"url":"https://example.com/mcp"})).unwrap();
            assert_eq!(record.metadata()["interface_type"],kind);
            record.interface_type=kind.into(); record.invocation_method=method.into();assert!(record.validate().is_ok());
            record.interface_type="wrong".into();assert!(record.validate().is_err());
        }
    }
}
