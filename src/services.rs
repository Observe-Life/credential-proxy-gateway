//! 共享的命令行切分。
//!
//! 旧的服务注册面（ServiceRecord / mcp_services 表 / 四个 credential_* 工具）已退役：
//! 服务现在只有一种登记方式——服务卡片。这里只保留卡片与本地命令执行都要用的命令切分。

use crate::error::{ConnectorError, ErrorCode, Result};

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
    if quote.is_some(){return Err(ConnectorError::new(ErrorCode::BadRequest,"命令里的引号没有成对闭合，请检查单引号或双引号"))}if started{words.push(word)}if words.is_empty(){return Err(ConnectorError::new(ErrorCode::BadRequest,"command 不能为空"))}Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

#[test]
fn command_parser_keeps_backslashes(){
    // 反斜杠必须原样保留：旧实现会吞掉它，导致 `-f message=\u517c` 变成 `u517c`
    assert_eq!(parse_command(r"--jq .a\b").unwrap(),vec!["--jq",r".a\b"]);
    assert_eq!(parse_command(r#"--notes "\u517c 容""#).unwrap(),vec!["--notes",r"\u517c 容"]);
    assert_eq!(parse_command(r"--path C:\tmp\repo").unwrap(),vec!["--path",r"C:\tmp\repo"]);
    // 双引号内的 \" 仍表示字面双引号
    assert_eq!(parse_command(r#"--notes "a\"b""#).unwrap(),vec!["--notes","a\"b"]);
    assert!(parse_command("  ").is_err());
    assert!(parse_command("'unclosed").is_err());
}
}
