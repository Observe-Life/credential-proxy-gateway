# 凭证统一代理网关（credential-proxy-gateway）

## 设计原则（本项目最高指导）

本项目是为了让智能体调用带密钥的联网请求时，**密钥不进入模型上下文**。只对安全边界做硬性管理；每个 MCP 的可调用工具和调用注意事项，**只做提醒、不做强制**，目的是在不涉及安全边界时尽量让智能体在使用时灵活调用。

一切文档、代码与评审以此条为最高指导：与本条冲突的表述，以本条为准。

---

由SSH连接器演进，保留原数据卷、主机、PTY、SFTP和审计。凭据加密存储；智能体决定调用，程序在网络请求内注入凭据，不提供明文读取工具。

## 当前能力（main 分支，已构建已部署）

- **服务卡片机制**：一张卡片对应一个服务（服务方网址、凭据键值对、注入方式是机制；常用工具名与注意事项是提醒）。三条执行路径——通用 HTTP 请求、按 MCP 协议调用远程服务、本地命令（凭据走环境变量）。**新增服务只需加卡片，不改代码。**
- **已接入四个服务**：Exa 搜索、豆包搜索（国内版）、微信公众号文章、GitHub（`gh` / `git` 完整命令能力）。
- **设备与终端**（承自 SSH 连接器）：设备登记与连接、一次性命令（三种载荷）、持久交互终端、二进制安全的文件传输与 SHA-256 校验。
- **凭据边界**：凭据加密存储；智能体侧只写不可读；外发请求由程序注入凭据；响应与命令输出里出现的凭据一律抹掉，含 base64 与百分号编码形态。
- **管理授权**：写入与删除凭据需人在网页打开 30 分钟临时开关；每次开与关都留审计。
- **审计**：SSH 面与服务调用面全覆盖，**失败的越界尝试同样留痕**。
- **上下文保护**：响应体有上限；目录列表默认 200 条并返回 `total` / `truncated`，不静默丢弃。
- 构建完成通过 Server酱 通知，地址只存放在 Actions Secret。

> 开发分支时代的"待部署"内容已全部上线；本节只描述线上实际状态。
## 服务适配机制设计

### 1. 一张卡片 = 一个服务

| 字段 | 性质 | 说明 |
| --- | --- | --- |
| 名称 | — | 给人看 |
| 服务方网址 | **机制** | **只填一个**：完整网址（如 `https://mcp.tikhub.io/wechat/mcp`）或主机名/通配（`*.example.com`，只匹配一层子域）。它既是调用入口，也是凭据可去的边界；**整张卡片只有这里能填网址**，调用时可直接取用、不必再拼 |
| 凭据 | **机制** | 一组键值对（一个服务可以有多个字段，例如 AppKey + Secret）。用户可查可改，只注入外发请求 |
| 注入方式 | **机制** | `bearer` / `header`（配头名）/ `basic` / `query:<参数名>` / `none` |
| 常用端点 | 建议 | 只告诉智能体常用的是哪几个，不构成限制 |
| 调用注意事项 | 建议 | 只写与调用直接相关的必要信息 |

### 2. 网关只做三件事

**按地址查凭据、注入、把响应里的凭据抹掉。**

其余自由度全交给智能体：方法、路径、参数、请求体都由它自己决定。所以**新增服务只需要加一张卡片，不改代码**。

### 3. 两个通用工具

- `gateway_request(卡片, 方法, 地址, 请求头, 请求体)` —— 按卡片注入凭据后转发
- `gateway_run(卡片, 命令, 工作目录, 超时)` —— 凭据作为环境变量注入子进程，输出里的凭据抹掉

工具入参里凡是自由形态的字段都必须声明类型（对象或数组），不能留成无类型值：无类型字段在调用方构造参数时会退化成字符串，服务端取不到内容，智能体首次调用必然失败。`gateway_call_mcp` 的子参数包、卡片里的常用端点列表都按此约束。

不定义"每个服务一套工具"。服务接口多而用得少时，靠卡片里的"常用端点"提醒；智能体想用别的，自己按接口文档填即可。

### 4. 安全边界（唯一的硬性管理范围）

只有这四条是强制的，其余一律只提醒、不强制：

- 目标主机必须在卡片的允许地址里，否则拒绝
- **跳转不禁**，最多跟随 5 跳：跳到清单内的下一跳继续带凭据，跳到清单外照常跟过去但不带凭据；跳转目标仍只允许 http/https
- 智能体不得自带凭据明文，也不得自带可改道的请求头（`Host`、`Forwarded`、`X-Forwarded-*` 等）
- 响应里的凭据一律抹掉，包括 base64 与百分号编码形态

### 4b. 上下文保护（不是安全边界）

响应体与目录列表都有体积上限，**超出会被标记，不静默丢弃**：`gateway_request` 上限 512 KiB；`sftp_list` 默认返回 200 条，`max_entries` 可调、上限 2000，`truncated=true` 时换更窄路径或用 `exec` 过滤，不要重复整目录拉取。这是保护模型上下文，不限制智能体拿到全部数据的能力。

### 5. 覆盖边界

**覆盖**：任意 HTTP/HTTPS 接口；远程 MCP（它本身就是 HTTP）；本地命令（凭据走环境变量）。

**不覆盖**：需要多轮派生或特殊转义的复杂签名、需要中途人机交互的流程、非 HTTP 协议。这类走 `gateway_run` 用现成命令行工具兜底。

### 6. 为什么不做"万能适配器"

适配器按"服务"分，等于每加一个服务就改一次代码。按"机制/建议"分，机制只保留三件事（地址、凭据、注入方式），语义部分交给提醒性质的文本，才能既覆盖广、又不用改代码。

参考实现对照（代码级）：`mvplab-ai/agent-vault` 的 `auth_style` 与编码形态脱敏、响应上限与边界读取、拒绝改道请求头；`AliProgrammin/agentic-vault` 的按值长度从长到短替换。

## 部署

镜像 `ghcr.io/observe-life/credential-proxy-gateway`，标签有 `latest` 与 `sha-<短哈希>`；用短哈希标签部署便于回滚。

所有容器加入外部网桥 `backend`；服务地址 `credential-proxy-gateway:7600`，**端口不发布到宿主机**。管理网页由 `container-login-gateway` 以 `/vault/` 反代。

关键环境变量：

| 变量 | 作用 |
| --- | --- |
| `SSH_CONNECTOR_BIND_ADDRESS` | 容器内需设为 `0.0.0.0` 才能被同网桥访问；默认仍是 `127.0.0.1` |
| `SSH_CONNECTOR_ALLOWED_HOSTS` | MCP 允许的 `Host` 头，追加到库自带的回环白名单之后 |
| `CREDENTIAL_VAULT_GATEWAY_AUTH_FILE` | 服务间密钥文件，与登录网关的 `INTERNAL_AUTH_TOKEN_FILE` 指向同一份，**绝不写入仓库** |
| `CREDENTIAL_VAULT_IMPORT_FILE` | 一次性导入服务卡片（JSON 数组，卡片格式），加密写入后删除该文件 |
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | 出站代理与免代理清单，**必须与卡片登记的服务方网址一起维护** |
| `GITHUB_MAX_CONCURRENCY` | GitHub 命令并发上限，默认 4，允许 1～64 |
| `SSH_CONNECTOR_MCP_IDLE_TIMEOUT_MINUTES` | MCP 会话空闲回收，默认 120 分钟，允许 5～1440 |

数据：整个 `/app/data` 数据卷都要备份，不能只备份 `vault.db`——还需 `runtime-key` 与 `audit/`。GitHub 命令的持久工作目录是 `/app/data/github`，`gh` / `git` 使用完整命令能力、没有业务操作白名单，输出会遮蔽已知令牌。
## 调用要求（提醒，不是强制）

各服务的调用注意事项**存在卡片里**，不在工具说明书里——因此改完立即生效，不需要重启任何东西。用 `gateway_list_cards` 读当前值，以它为准。

写入卡片时的三条经验（当前四个服务的卡片已按此配置）：

- Exa：`query` 写完整描述；`objective` 是上游必填（要什么 + 排除什么）。
- 豆包：`Query` 上游必填；`SearchType` 与 `Count` 有缺省值，调用方给了就按调用方的来。
- 微信：`keyword` 上游必填；`business_type` 缺省 `article`、`sort` 缺省 `0`，调用方给了就尊重；结果里的 `date` 会附 UTC+8 的 `date_local`，高亮标签会被移除。
- GitHub：`gh_status` / `gh_run` / `gh_git`，权限取决于令牌 scope。
## 为什么需要它

很多编程代理可以直接在本地 shell 里运行 `ssh`，但这会带来很差的安全边界和可控性：

- 凭据可能进入 shell 历史、prompt、日志、截图或代理上下文；
- 长时间交互 shell 和一次性命令混在一起；
- 文件传输通常变成临时 `scp`、`cat` 或 here-doc；
- 没有干净的主机注册表、脱敏 AI 视图和本地审计记录。

凭证统一代理网关 把职责拆开：

- **人类拥有凭据**：凭据存入本地加密 vault。
- **AI 只看到脱敏摘要**：AI 使用稳定的 `host_id`，不读取密码或私钥。
- **命令通过类型化 MCP 工具执行**：不让代理随意拼本地 `ssh`。
- **短命令、长 PTY、SFTP 和审计**：共用同一个本地 daemon 和连接池。

## 特性

- **智能体不接触密钥**：密码与私钥用主密码加密落盘，MCP 工具永不返回存储的明文凭据；查看明文只走人工网页路径。
- **服务调用不写代码**：网关只做"按地址查凭据、注入、抹掉响应里的凭据"三件事，方法、路径、参数、请求体由智能体自己决定。
- **安全边界是硬性的，其余是提醒性的**：目标主机必须在卡片允许清单内；智能体不得自带凭据明文，也不得自带可改道的请求头；跳转允许，但跳到清单外不再带凭据。
- **强制跳转策略可控**：HTTP 客户端不自动跳转，由网关逐跳判定并限制最多 5 跳，跳转目标仍只允许 http/https。
- **仅内部网桥可见**：端口不发布到宿主机，局域网访问不到；管理网页经统一登录网关反代。
- **连接生命周期自管**：SSH 传输复用，一次性操作按需连接，断线后可自动重连；每台设备限并发通道数。
- **审计可追溯**：设备、终端、文件传输、服务调用、授权开关都有本地留痕。
## 接入方式

服务只在内部网桥 `backend` 上提供，MCP 端点是 `http://credential-proxy-gateway:7600/mcp`，**没有发布到宿主机端口**，局域网里访问不到。

任何支持 Streamable HTTP 的 MCP 客户端都按这个地址接：

```json
{
  "mcpServers": {
    "credential-proxy-gateway": {
      "type": "http",
      "url": "http://credential-proxy-gateway:7600/mcp"
    }
  }
}
```

在容器里接入：`docker network connect backend 你的容器名`。
在容器里不要用 `127.0.0.1:7600` 或 `localhost:7600`——那指向容器自己。

管理网页不直接暴露，由 `container-login-gateway` 以 `/vault/` 路径反向代理，需先通过统一登录。

**接口本身不做调用方身份鉴权，这是设计目标**：接入网桥的智能体可以直接使用全部工具，凭据保护靠加密存储与响应脱敏，不靠调用方身份。所以只把信任的容器接进这个网桥。

> 上游提供的单机安装（`cargo install`、`--mcp-stdio`、只监听 `127.0.0.1`）本仓库不使用，容器化部署见下方。
## 为智能体推荐的用法

网关在 MCP 握手下发使用指引，引导智能体走安全路径：

1. 要调用外部服务：先 `gateway_list_cards` 看有哪些卡片、允许去哪些地址、注意事项是什么，再选工具发请求。
2. 要操作设备：先 `host_list` 看设备与状态；一次性命令优先 `exec` 的 `argv`。
3. 多行非交互任务用 `script`；编辑器、REPL、需要提示符的操作用 `session_open`。
4. 远端文件用 SFTP 工具；大文件一律走路径型传输，不要把字节塞进参数。
5. 不要要求查看已存凭据，除非人明确要在网页上看。

注意事项里的内容（参数必填、字段大小写、结果字段含义）**只是提醒**，网关不会因为"不符合最佳实践"而拒绝调用；它只在违反安全边界时拒绝。
## 管理网页

供人工操作（经 `container-login-gateway` 的 `/vault/` 反代访问，需先通过统一登录）：

- 初始化与解锁保险箱、打开或关闭 30 分钟临时管理开关；
- 登记、编辑、连接、删除设备，配置跳板链与环境变量；
- 维护服务卡片：服务方网址、凭据字段、注入方式、常用工具名、注意事项；
- 查看明文凭据（只有人工路径，且需登录态）；
- 查看实时终端会话与审计记录。
## 安全模型

```text
人工网页（统一登录）── 写入凭据、开授权 ─┐
                                        ├─ 保险箱(加密) ─ 状态 ─ SSH / 上游服务
智能体 MCP 工具 ── 只引用卡片与服务名 ──┘

凭据：加密落盘，只注入外发请求，永不进入模型上下文
审计：设备、终端、文件、服务调用、授权开关全部留痕
网络：默认只监听回环；容器部署刻意暴露到内部网桥，不做调用方鉴权
```

安全属性：

- **智能体侧凭据只写不可读**：可以创建和修改服务与设备，但所有读取路径返回脱敏摘要。
- **人工专用的明文查看路径**：只有网页能做，MCP 面上不存在对应工具。
- **命令优先 argv**：类型化参数数组，避免拼 shell 造成注入。
- **主机密钥首次信任**（TOFU）：后续不匹配即拒绝，尚未支持预置 known_hosts。
- **凭据不经第三方转手**：出站代理由容器环境变量决定，卡片地址必须与免代理清单一起维护；卡片元数据会如实回显 `proxy_configured` 与 `bypass_matched`，让配置者自己判断。
## 工具列表

共 29 个工具，分四组。**服务只有一种登记方式：服务卡片。**

**服务卡片**

| 工具 | 作用 |
| --- | --- |
| `gateway_list_cards` | **调用任何外部服务前先读这里**：名称、服务方网址、注入方式、常用工具名、调用注意事项、代理去向回显、凭据配了哪几个字段（绝不返回值） |
| `gateway_register_card` | 新增或修改卡片（智能体通道，需临时开关；人在网页上改不需要） |
| `gateway_remove_card` | 删除卡片（智能体通道，需临时开关） |
| `gateway_request` | 按卡片发一次通用 HTTP 请求：方法、完整网址、请求头、请求体都由智能体决定 |
| `gateway_call_mcp` | 按 MCP 协议调用一次远程服务：先握手，再调用指定工具 |
| `gateway_run` | 按卡片跑一次本地命令，凭据作为环境变量注入子进程 |

**设备与连接**：`host_list`、`host_add`、`host_update`、`host_remove`、`host_connect`、`host_disconnect`
**一次性命令**：`exec`（`argv` / `script` / `raw` 三种载荷）
**交互终端**：`session_open`、`session_open_root`、`session_send_text`、`session_send_key`、`session_screen`、`session_read`、`session_resize`、`session_close`、`session_list`
**文件传输**：`sftp_list`、`sftp_get`、`sftp_put`、`sftp_get_base64`、`sftp_put_base64`、`sftp_download_file`、`sftp_upload_file`

两条入参约束，都是踩过坑才写下的：

- 凡承载结构的字段都必须声明类型（对象或数组）。无类型字段会在调用方构造参数时退化成字符串，服务端取不到内容，首次调用必然失败。
- **可变的信息一律放在调用返回里，绝不写进工具说明书**。说明书是握手时一次性下发的常量，写在那里的东西改了必须重新握手才可见；而返回里的内容每次现读数据库，改完立即生效。
## 主机凭据参数结构

`host_add` 和 `host_update` 使用同一套主机参数。必填字段是 `alias`、
`host`、`user`、`auth`；可选字段是 `port`、`jump_hosts`、`env`、`become_root`。

密码认证：

```json
{
  "alias": "prod-box",
  "host": "203.0.113.10",
  "port": 22,
  "user": "root",
  "auth": { "type": "password", "password": "..." }
}
```

私钥认证：

```json
{
  "alias": "key-box",
  "host": "203.0.113.11",
  "user": "ubuntu",
  "auth": {
    "type": "private_key",
    "key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
    "passphrase": "optional"
  }
}
```

键盘交互认证：

```json
{
  "alias": "mfa-box",
  "host": "203.0.113.12",
  "user": "admin",
  "auth": {
    "type": "keyboard_interactive",
    "answers": ["password-or-first-answer", "otp-or-second-answer"]
  }
}
```

跳板机链路里每一跳也使用同样的 `auth` 对象：

```json
{
  "alias": "internal-box",
  "host": "10.0.0.20",
  "user": "root",
  "auth": { "type": "password", "password": "..." },
  "jump_hosts": [
    {
      "host": "203.0.113.100",
      "port": 22,
      "user": "bastion",
      "auth": { "type": "private_key", "key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----\n..." }
    }
  ],
  "env": { "TERM": "xterm-256color" }
}
```

先用普通用户登录，再通过 `su -` 打开 root PTY 会话：

```json
{
  "alias": "root-via-su",
  "host": "203.0.113.20",
  "user": "deploy",
  "auth": {
    "type": "private_key",
    "key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
  },
  "become_root": {
    "enabled": true,
    "command": "su -",
    "password": "root-password",
    "prompt_timeout_ms": 5000
  }
}
```

之后调用 `session_open_root`：

```json
{
  "host_id": "host-id",
  "rows": 24,
  "cols": 100
}
```

root 密码保存在加密 vault 里，不需要在工具调用时再次传给 AI。

## Exec Payload

优先使用 `argv`：

```json
{
  "host_id": "host-id",
  "argv": { "argv": ["uname", "-a"] }
}
```

多行任务使用 `script`：

```json
{
  "host_id": "host-id",
  "script": { "script": "#!/bin/bash\nset -e\nhostname\nid" }
}
```

只有明确需要 shell quoting 时使用 `raw`：

```json
{
  "host_id": "host-id",
  "raw": { "raw": "echo ok && systemctl status nginx" }
}
```

返回结构：

```json
{
  "stdout": "...",
  "stderr": "...",
  "exit_code": 0,
  "duration_ms": 123,
  "truncated": false,
  "timed_out": false,
  "had_invalid_utf8": false
}
```

## SFTP Payload

`sftp_get` / `sftp_put` 只用于 UTF-8 文本。

zip/tar/gz、安装包、APK、图片、数据库、编译产物，或任何可能超过模型
上下文的大体积精确字节传输，使用路径型传输。文件内容不会进入工具参数或
工具返回值；本地路径只允许 `/tmp` 和 daemon 当前项目目录。

两个路径工具都会有界分块流式传输。下载先写同目录隐藏 `.part` 文件，完成
sync，并对比本地与远端 SHA-256 后再提交，不会提前暴露半个目标文件。
上传先写远端同目录隐藏 `.part`，再在远端本机校验文件大小和 SHA-256，
不会为了校验把整个文件再下载一次。校验后再 rename；覆盖已有文件时会先
暂存同目录 backup，提交失败则回滚。普通错误会自动清理传输临时文件。
SHA-256 校验需要远端存在 `sha256sum` 或 `shasum`。

```json
{
  "host_id": "host-id",
  "remote_path": "/tmp/app-release.apk",
  "local_path": "/tmp/app-release.apk",
  "overwrite": false,
  "create_parent_dirs": true,
  "chunk_size_bytes": 262144,
  "verify_sha256": true
}
```

配合 `sftp_download_file`；上传时用：

```json
{
  "host_id": "host-id",
  "local_path": "/tmp/package.tar.gz",
  "remote_path": "/tmp/releases/package.tar.gz",
  "overwrite": false,
  "create_parent_dirs": true,
  "chunk_size_bytes": 262144,
  "verify_sha256": true
}
```

配合 `sftp_upload_file`。

`overwrite` 默认 `false`；`create_parent_dirs` 和 `verify_sha256` 默认
`true`。`chunk_size_bytes` 默认 256 KiB，可设置为 64 KiB 到 8 MiB。
远端读取采用 8 路按顺序提交的并发区间，在控制内存上限的同时避免每个
SFTP packet 都串行等待公网往返。结果返回 `bytes`、`sha256` 和 `verified`。

`sftp_get_base64` / `sftp_put_base64` 只用于小体积二进制 payload。84MB APK
会膨胀成约 112MB base64，再加 JSON 开销，必须走路径型传输。

## 从源码构建

要求：

- 支持 Rust edition 2024 的稳定 Rust 工具链。
- macOS、Linux，或 Rust 依赖支持的平台。

```bash
git clone https://github.com/LCYLYM/ssh-connector-mcp.git
cd ssh-connector-mcp
cargo build --release
cargo test
./target/release/ssh-connector --data-dir ~/.ssh-connector
```

## 配置

数据目录中的可选 `config.toml`：

| 字段 | 默认值 | 含义 |
| --- | ---: | --- |
| `web_port` | `7600` | Web UI、Web API 和 MCP HTTP 端口。 |
| `mcp_port` | `7601` | 预留的独立 MCP 端口。 |
| `exec_timeout_ms` | `120000` | 一次性命令超时。 |
| `exec_output_cap_bytes` | `1048576` | 单流输出上限。 |
| `pty_idle_ttl_secs` | `1800` | 空闲 PTY 清理 TTL；`0` 表示禁用。 |
| `keepalive_secs` | `30` | SSH keepalive 间隔。 |
| `max_channels_per_host` | `8` | 每台主机最大并发 exec channel 数。 |


## 测试

单元测试随镜像构建一起跑（`cargo generate-lockfile && cargo test --locked && cargo build --release --locked`），覆盖命令切分与反斜杠保留、参数脱敏与编码形态替换、注入方式四种形式、地址通配只匹配一层、跳转与越界拒绝、卡片参数校验、UTF-8 边界裁剪等。

冒烟与端到端：

- `tests/smoke_http_mcp.py` 对运行中的服务做握手与工具面检查；
- `tests/real_e2e.py` 需要一台由 root 管理的测试机，会自建临时用户与两个隔离的高端口 `sshd`，结束自动删除，覆盖保险箱锁与解锁、四种认证方式、跳板成功与失败、主机密钥不匹配、大体积二进制双向传输、创建与覆盖、临时文件清理、SHA-256 一致性，以及只能由人工解锁的明文查看边界。

部署后建议按这四项确认本轮能力在线上生效：服务调用是否写入审计（含失败尝试）、卡片是否回显代理去向、目录列表是否返回 `total` / `truncated`、以及智能体首次调用带子参数包的服务能否一次成功。
## 已知限制

- **接口无调用方鉴权**：接入内部网桥的容器可以使用全部工具（含写入设备与服务注册）。这是刻意的设计取舍，靠网桥成员名单与审计承担风险。
- **管理授权窗口内不可提前收回**：开关一旦打开，只有 30 分钟自然到期或人工显式关闭两种收权路径；未登录的只读请求不再影响授权。窗口期内同网桥容器可写入凭据，需要主动查看审计才能发现。
- **已退役**：旧的服务注册表与四个 `credential_*` 工具已删除，服务只剩卡片一种登记方式。
- **凭据经明文 http 时依赖免代理清单**：卡片地址若不在 `NO_PROXY` 内，请求会经容器配置的出站代理转发。代码不拦也不猜，只在卡片元数据里回显事实。
- **`tools` 字段遇到无法识别的形状会退化为空**：可用性优先，不让一条坏记录让整个注册表读不出来；代价是那份提醒会静默消失，需要人工补回。
- **主密码没有修改接口**：遗忘只能重置保险箱，会丢失已存凭据。
- **主机密钥首次信任**：尚未支持导入预置 known_hosts。
- **跳转凭据策略未经端到端实测**：清单外不带凭据目前只有代码与单元测试支撑，缺一个真实会重定向且在允许地址内的目标。
- **响应截断只约束交给模型的体积**：未启用流式读取，进程内存仍会先吃下完整响应。
- 进程崩溃或断电可能留下隐藏 `.part` / `.backup`；普通工具错误会自动清理，且不会发布半个目标文件。
## 本仓库的改动（相对上游）

上游是单机版 SSH 连接器；本仓库在它之上长出第二层——**凭据统一代理网关**。改动分两类。

**容器化（不改语义）**

| 改动 | 文件 | 说明 |
| --- | --- | --- |
| 监听地址可配置 | `src/daemon/mod.rs` | 新增 `SSH_CONNECTOR_BIND_ADDRESS`；**默认仍是回环** |
| MCP 允许的 Host 可扩展 | `src/mcp/mod.rs` | 新增 `SSH_CONNECTOR_ALLOWED_HOSTS`；**追加**到库自带回环白名单之后，不替换 |
| 容器镜像与发布 | `Dockerfile`、`.github/workflows/container.yml` | 两阶段构建（`rust:1.89` → `debian:bookworm-slim`），非 root（uid 10001）运行；推 `ghcr.io/observe-life/credential-proxy-gateway`，标签 `latest` / tag / 短 SHA |
| 编排示例 | `deploy/docker-compose.yml` | 接入外部网桥 `backend`，按容器名访问 |
| 会话失效可恢复 | `Cargo.toml` 的本地补丁 | 上游对已终止会话返回 500，会使标准客户端永久卡住；补丁让它返回 404 触发重新握手 |
| 空闲回收可配 | `src/config.rs` | `SSH_CONNECTOR_MCP_IDLE_TIMEOUT_MINUTES`，5～1440 分钟 |

**网关层（新增能力）**

| 改动 | 文件 | 说明 |
| --- | --- | --- |
| 服务卡片与三条执行路径 | `src/gateway.rs`、`src/mcp/mod.rs` | 通用 HTTP 请求、按 MCP 协议调用、本地命令；共用同一套地址校验、凭据注入与脱敏。加新服务只需加卡片 |
| 安全边界硬化 | `src/gateway.rs` | 拒绝自带凭据明文、拒绝可改道请求头、通配地址只匹配一层子域、跳转逐跳判定且清单外不带凭据 |
| 编码形态脱敏与响应上限 | `src/gateway.rs` | 明文、base64、百分号三种形态都替换；响应体截断 |
| 旧服务注册面**已退役** | `src/services.rs`、`src/vault/mod.rs` | 四个 `credential_*` 工具与 `mcp_services` 表已删除，只留卡片一种登记方式；`services.rs` 仅保留共享的命令切分 |
| 审计扩展到服务面 | `src/services.rs`、`src/mcp/mod.rs`、`src/daemon/mod.rs` | 服务调用、注册与卡片增删、授权开关全部留痕，失败与越界尝试也在内 |
| 管理授权生命周期 | `src/web/mod.rs`、`src/vault/mod.rs` | 运行钥匙与主密码分离；未登录只读请求不再改动授权 |
| 目录列表上下文保护 | `src/mcp/mod.rs` | `max_entries` 可调，返回 `total` / `truncated`，不静默丢弃 |
| 管理网页 | `static/index.html`、`static/app.js`、`src/web/mod.rs` | 卡片表单、统一登录共享会话、服务间密钥核验 |

### 为什么需要容器化那几个环境变量

上游把服务强制绑定到回环，并且假定不需要远程鉴权，因此在容器里只有容器自己能访问；而 MCP 库默认只接受 `localhost`、`127.0.0.1`、`::1` 三种 `Host` 头（防 DNS 重绑定），其他容器按容器名访问会拿到 `403 Host header is not allowed`。这两个变量都保留了安全默认值，只在显式配置时放开。
## 容器化部署

### 1. 创建自建网桥

```bash
docker network create backend
```

### 2. 启动容器

使用 `deploy/docker-compose.yml`：

```bash
docker compose -f deploy/docker-compose.yml up -d
```

或直接用已发布的镜像：

```bash
docker run -d --name credential-proxy-gateway --restart unless-stopped \
  --network backend \
  -e SSH_CONNECTOR_BIND_ADDRESS=0.0.0.0 \
  -e SSH_CONNECTOR_ALLOWED_HOSTS=credential-proxy-gateway \
  -v credential-proxy-gateway-data:/app/data \
  -p 7600:7600 \
  ghcr.io/observe-life/credential-proxy-gateway:latest
```

### 3. 其他容器如何访问

把需要访问它的容器接进同一个 `backend` 网桥，再用**容器名**访问：

```text
Web UI   http://credential-proxy-gateway:7600/
MCP      http://credential-proxy-gateway:7600/mcp
```

```bash
docker network connect backend 你的容器名
```

> 在容器 A 中不要使用 `127.0.0.1:7600` 或 `localhost:7600`，那指向的是容器 A 自己。

### 4. 验证

在同一网桥中另起一个容器探测：

```bash
# Web 界面
docker run --rm --network backend curlimages/curl:latest \
  -s -o /dev/null -w "%{http_code}\n" --max-time 20 http://credential-proxy-gateway:7600/

# MCP 初始化握手
docker run --rm --network backend curlimages/curl:latest \
  -s --max-time 25 -X POST http://credential-proxy-gateway:7600/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1.0"}}}'
```

预期：前者返回 `200`；后者返回 `serverInfo` 为 `rmcp` 的 JSON-RPC 结果。

### 5. 重启后自动解锁（可选）

保险箱默认每次启动都处于锁定状态。希望容器重启后自动解锁时，把主密码放进一个仅自己可读的 env 文件，并打开 `deploy/docker-compose.yml` 中注释掉的 `command` 与 `env_file`：

```bash
mkdir -p secrets && chmod 700 secrets
printf 'SSH_CONNECTOR_MASTER_PASSWORD=%s\n' '你的主密码' > secrets/master_password.env
chmod 600 secrets/master_password.env
```

```yaml
command: ["--data-dir", "/app/data", "--master-password-env", "SSH_CONNECTOR_MASTER_PASSWORD"]
env_file:
  - ./secrets/master_password.env
```

> **注意**：主密码填错时，容器会在启动阶段直接退出并反复重启，日志为
> `[vault_bad_password] decryption failed (wrong key or corrupted vault)`。
> 不打算自动解锁就不要启用这两项。

## 目标主机的 shell 差异（实测）

`exec` 提供三种载荷，行为不同，选错会直接失败：

| 载荷 | 行为 | 适用 |
| --- | --- | --- |
| `argv` | 连接器为每个参数套 POSIX 单引号后交给远端 shell | Linux / macOS 等 POSIX shell |
| `raw` | 原样交给远端登录 shell，**引号由调用方负责** | Windows（`cmd.exe`）等非 POSIX shell |
| `script` | 多行脚本，经 SFTP 上传后作为文件执行 | 复杂批处理 |

**Windows 目标（OpenSSH 默认 `cmd.exe`）不要用 `argv`。** 参数会被加上单引号，
`cmd.exe` 无法识别，命令以退出码 1 失败并提示「不是内部或外部命令」。改用 `raw`：

```json
{ "host_id": "<host_id>", "raw": "hostname" }
```

**中文输出要用 PowerShell 显式切到 UTF-8。** 否则远端返回的 GBK 字节会被判定为非法
UTF-8：结果里 `had_invalid_utf8` 为 `true`，内容显示为乱码。

```json
{
  "host_id": "<host_id>",
  "raw": "powershell -NoProfile -Command \"[Console]::OutputEncoding=[Text.Encoding]::UTF8; hostname\""
}
```

此外，`session_open` 等**交互式 PTY 是 POSIX 专用**；Windows 目标请使用 one-shot 命令。

## 运行凭据与管理锁定

本分支把“管理解锁”和“运行解锁”分开：

- **主密码**只用于初始化、添加、修改、删除和查看明文凭据。
- 主密码不会写入 `docker-compose.yml`、环境文件或 GitHub。
- 管理授权有独立的 30 分钟临时窗口，窗口内凭据可写；到期或人工显式关闭才收回。
- **运行解密钥匙**保存在数据目录 `/app/data/runtime-key`，权限为 `600`。
- 运行解密钥匙随 `/app/data` 数据卷迁移，容器重启后可恢复运行凭据。
- MCP 可以使用已登记设备、按需建立 SSH 连接、断线后重新连接；MCP 不会返回私钥、密码或运行解密钥匙。

因此，容器重启后不需要再次输入主密码即可执行 SSH 操作；只有再次管理凭据或查看明文凭据时才需要主密码。

管理授权的收回**只有两条路径**：30 分钟自然到期，或显式调用下面的锁定接口。未通过登录校验的网页请求只拒绝当次请求，**不会**改动授权状态——网页会话过期或别的容器做一次只读探测，都不该把人正开着的管理开关关掉。

每一次授权开与关都写审计；服务调用、注册与卡片增删同样留痕。完整动作清单与三条记录约束见「审计与留痕」。

管理锁定接口：

```bash
# 在网关容器内执行（该接口同样受统一登录态保护）
curl -X POST http://127.0.0.1:7600/vault/lock-management
```

迁移时必须完整迁移 Docker 数据卷，而不能只复制 `vault.db`：

```text
/app/data/vault.db
/app/data/runtime-key
/app/data/audit/
```

> 能读取完整数据卷或拥有宿主机 Docker 管理权限的人，可以同时取得密文数据库和运行解密钥匙。运行解密钥匙的目标是降低日常人工管理成本，不是抵御宿主机管理员级别的攻击。

### MCP 连接等待

MCP 首次操作设备或发现连接断开时，连接器会在服务内部建立 SSH 连接；调用方保持 MCP 请求等待，连接成功后再返回结果。连接失败或超过执行超时会返回脱敏错误，不会返回凭据内容。

### 设备注意事项

每台设备可以保存 `notes` 非敏感说明，例如远端 shell 类型、命令格式、编码方式和高风险权限提示。`host_list`、设备详情和管理界面可以返回这些说明；私钥、密码、口令和跳板机凭据不会返回。

## 审计与留痕

审计按天滚动写入 `audit/audit-YYYY-MM-DD.jsonl`，一行一个 JSON。管理面板按每页 10 条分页显示（最新在前，底部可翻页与输入页码跳转）。当日线上实测出现的动作共 31 种：

| 分组 | 动作 |
| --- | --- |
| 设备与连接 | `host_add`、`host_update`、`host_remove`、`host_connect`、`host_disconnect` |
| 命令与终端 | `exec`、`pty_open`、`pty_close`、`pty_open_root_failed`、`pty_send_text`、`pty_send_key` |
| 文件传输 | `sftp_list`、`sftp_get`、`sftp_put`、`sftp_download_file`、`sftp_upload_file` |
| 服务调用（成功与失败成对） | `gateway_request` / `gateway_request_failed`、`gateway_run` / `gateway_run_failed`、`gateway_call_mcp` / `gateway_call_mcp_failed` |
| 注册与卡片增删 | `service_register`、`service_remove`、`card_register`、`card_remove` |
| 管理授权 | `management_grant_open`、`management_grant_close` |
| 人工查看明文 | `card_credential_reveal` |

历史日志里可能仍能看到已退役的 `credential_invoke` / `credential_register` 等动作，那是旧接口留下的记录，不影响当前行为。代码里还会在另一些分支写审计：保险箱初始化与解锁、显式关闭管理授权、设备明文查看、命令与终端打开失败、一次性凭据迁移导入、会话回收时间调整。

三条约束：

- **失败也留痕**：越界地址、自带凭据明文、自带改道头、参数不合形状，都会记下动作名、错误码与脱敏后的说明，便于发现有人在试探边界。
- **不落密钥**：记录的网址、命令、工作目录与错误文本先按卡片凭据（含 base64 与百分号形态）抹掉，再截断到 240 字符。
- **只记够复盘的信息**：终端输入只记字节数与"已脱敏"标记，不记内容；注册与卡片只记编号与注入方式，不记凭据字段值。

## 容器化后的安全须知

- **接口不做调用方鉴权，这是设计目标**：接入 `backend` 网桥的容器可以使用全部工具，包括登记设备、在已配置设备上执行命令、在授权窗口内写入服务与凭据。因此只把信任的容器接进这个网桥，并把审计当作事后追责手段。
- **`7600` 端口当前没有发布到宿主机**，局域网访问不到；管理网页经统一登录网关反代。若将来要发布端口，请把它当作新增攻击面重新评估。
- **免代理清单要与卡片地址一起维护**：出站代理由容器环境变量决定，代码不拦也不猜。卡片元数据会回显 `proxy_configured` 与 `bypass_matched`；若某张卡片有凭据、走明文 http、又不在免代理清单内，凭据会经代理明文转发。
- **管理授权窗口内不会被提前收回**：只有 30 分钟到期或人工显式关闭两种收权路径；期间发生的写入要靠审计发现。
- **主密码不可修改**：遗忘只能重置保险箱，会丢失已保存的凭据。程序不保存主密码。
- **数据卷要整体备份**：`/app/data` 下的保险箱、`runtime-key`、`audit/` 三者缺一不可。
## License

MIT

## MCP 通信会话空闲回收时间

默认 **120 分钟**。通过环境变量 `SSH_CONNECTOR_MCP_IDLE_TIMEOUT_MINUTES` 配置，允许整数 **5～1440**（含边界），单位为分钟。更改后重建连接器容器生效。非法值会阻止服务启动并给出配置错误，不会静默使用别的期限。

```yaml
environment:
  SSH_CONNECTOR_MCP_IDLE_TIMEOUT_MINUTES: "120"
```

此项仅控制 MCP 通信会话，不修改 SSH 凭据或交互终端的回收策略。会话过期继续返回规范要求的 404；不能替代客户端的重新握手能力。
