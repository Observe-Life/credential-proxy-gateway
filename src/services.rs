//! MCP registry and credential-use adapters. Secret-bearing records remain inside Vault.
use crate::{state::AppState, error::{ConnectorError, ErrorCode, Result}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use schemars::JsonSchema;
use std::sync::Arc;

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
pub struct ServiceRecord {
    pub id: String,
    pub name: String,
    pub adapter: String,
    #[serde(default)] pub url: String,
    #[serde(default)] pub credential: String,
    #[serde(default)] pub tools: Value,
    #[serde(default)] pub notes: String,
}
impl ServiceRecord {
    pub fn metadata(&self) -> Value {
        json!({"id":self.id,"name":self.name,"adapter":self.adapter,"url":self.url,
            "tools":self.tools,"notes":self.notes,"has_credential":!self.credential.is_empty()})
    }
    pub fn validate(&self) -> Result<()> {
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
    let (init,sid)=upstream_rpc(&client,url.as_str(),header,None,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"credential-proxy-vault","version":"0.1.0"}}})).await?;
    if init.get("error").is_some(){return Err(internal("upstream MCP initialization rejected"))}
    let _=upstream_rpc(&client,url.as_str(),header,sid.as_deref(),json!({"jsonrpc":"2.0","method":"notifications/initialized"})).await?;
    let result=upstream_rpc(&client,url.as_str(),header,sid.as_deref(),json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":args}})).await;
    if let Some(id)=sid{let _=client.delete(url.as_str()).header("Mcp-Session-Id",id).header("Authorization",header).send().await;}
    let (value,_)=result?;
    if value.get("error").is_some(){return Err(internal("upstream MCP tool rejected request"))}
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
}
fn clean_highlight(s:&str)->String{s.replace("<em class=\"highlight\">","").replace("</em>","")}
fn clean_wechat(v:&mut Value){match v {Value::Array(a)=>for x in a{clean_wechat(x)},Value::Object(o)=>{for(k,x)in o.iter_mut(){if ["title","desc"].contains(&k.as_str()){if let Some(s)=x.as_str(){*x=Value::String(clean_highlight(s))}}else{clean_wechat(x)}}if let Some(timestamp)=o.get("date").and_then(Value::as_i64){if let Ok(t)=time::OffsetDateTime::from_unix_timestamp(timestamp){let t=t.to_offset(time::UtcOffset::from_hms(8,0,0).unwrap());o.insert("date_local".into(),Value::String(format!("{}",t)));}}},_=>{}}}

pub async fn invoke(st:Arc<AppState>,id:&str,tool:&str,mut args:Value)->Result<Value>{
    let record=st.vault.get_service_record(id)?;
    let result=match record.adapter.as_str(){
        "doubao"=>{let q=args.get("Query").or_else(||args.get("query")).and_then(Value::as_str).unwrap_or("");if q.is_empty(){return Err(ConnectorError::new(ErrorCode::BadRequest,"Query required"))}let body=json!({"Query":q,"SearchType":"web","Count":args.get("Count").or_else(||args.get("count")).and_then(Value::as_u64).unwrap_or(10).clamp(1,50),"NeedSummary":args.get("need_summary").and_then(Value::as_bool).unwrap_or(true)});let r=http_client()?.post(&record.url).header("Authorization",&record.credential).json(&body).send().await.map_err(|_|internal("search transport failed"))?;if !r.status().is_success(){return Err(internal(&format!("search HTTP {}",r.status().as_u16())))}r.json::<Value>().await.map_err(|_|internal("search result is not JSON"))?},
        "wechat"=>{if let Some(o)=args.as_object_mut(){o.insert("business_type".into(),json!("article"));o.insert("sort".into(),json!(0));}let mut result=native_call(&record,"wechat_search_v2_fetch_search",args).await?;if let Some(content)=result.get_mut("content").and_then(Value::as_array_mut){for item in content{if let Some(raw)=item.get("text").and_then(Value::as_str){if let Ok(mut parsed)=serde_json::from_str::<Value>(raw){clean_wechat(&mut parsed);item["text"]=json!(parsed.to_string());}}}}result},
        "exa"=>{if args.get("objective").and_then(Value::as_str).unwrap_or("").trim().is_empty(){return Err(ConnectorError::new(ErrorCode::BadRequest,"objective required"))}native_call(&record,tool,args).await?},
        "github"=>github_call(&record,tool,args).await?,
        _=>return Err(internal("adapter not supported")),
    };
    let text=redact(&result.to_string(),&record.credential);serde_json::from_str(&text).map_err(|_|internal("result normalization failed"))
}
async fn github_call(s:&ServiceRecord,tool:&str,args:Value)->Result<Value>{
    let mut cmd=match tool{"gh_git"=>tokio::process::Command::new("git"),"gh_run"|"gh_status"=>tokio::process::Command::new("gh"),_=>return Err(ConnectorError::new(ErrorCode::BadRequest,"unknown GitHub tool"))};
    if tool=="gh_status"{cmd.args(["auth","status"]);}else{
        let command=args.get("command").and_then(Value::as_str).ok_or_else(||ConnectorError::new(ErrorCode::BadRequest,"command required"))?;
        let argv=parse_command(command)?;cmd.args(argv);
    }
    let cwd=args.get("cwd").and_then(Value::as_str).unwrap_or("/app/data/github");tokio::fs::create_dir_all(cwd).await.map_err(|_|internal("GitHub work directory unavailable"))?;cmd.current_dir(cwd);
    cmd.env("GH_TOKEN",&s.credential).env("GH_PROMPT_DISABLED","1").env("GH_PAGER","cat").env("GIT_PAGER","cat").env("GIT_TERMINAL_PROMPT","0");
    if tool=="gh_git"{cmd.env("GIT_CONFIG_COUNT","1").env("GIT_CONFIG_KEY_0","credential.helper").env("GIT_CONFIG_VALUE_0","!gh auth git-credential");}
    let timeout=args.get("timeout").and_then(Value::as_u64).unwrap_or(120).clamp(1,10800);cmd.kill_on_drop(true);
    let output=tokio::time::timeout(std::time::Duration::from_secs(timeout),cmd.output()).await.map_err(|_|internal("GitHub command timed out"))?.map_err(|_|internal("GitHub executable failed"))?;
    Ok(json!({"exit_code":output.status.code(),"stdout":redact(&String::from_utf8_lossy(&output.stdout),&s.credential),"stderr":redact(&String::from_utf8_lossy(&output.stderr),&s.credential)}))
}
fn parse_command(s:&str)->Result<Vec<String>> {
    let mut words=Vec::new();let mut word=String::new();let mut quote=None;let mut escape=false;let mut started=false;
    for c in s.chars(){if escape {word.push(c);escape=false;started=true;continue}if c=='\\'&&quote!=Some('\''){escape=true;started=true;continue}if let Some(q)=quote{if c==q{quote=None}else{word.push(c)}started=true;}else if c=='\''||c=='"'{quote=Some(c);started=true;}else if c.is_whitespace(){if started{words.push(std::mem::take(&mut word));started=false}}else{word.push(c);started=true}}
    if escape||quote.is_some(){return Err(ConnectorError::new(ErrorCode::BadRequest,"unclosed command quoting"))}if started{words.push(word)}if words.is_empty(){return Err(ConnectorError::new(ErrorCode::BadRequest,"empty command"))}Ok(words)
}
#[cfg(test)]mod tests{use super::*;#[test]fn service_arguments_and_redaction(){assert_eq!(parse_command("issue create --title '中文 标题'").unwrap(),vec!["issue","create","--title","中文 标题"]);assert!(parse_command("'unclosed").is_err());assert_eq!(redact("Bearer secret","secret"),"Bearer [凭据已隐藏]");let mut v=json!({"title":"<em class=\"highlight\">中文</em>","date":0});clean_wechat(&mut v);assert_eq!(v["title"],"中文");assert!(v.get("date_local").is_some());}}
