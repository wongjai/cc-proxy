# CC Proxy

Claude Code 伪装反向代理。接收标准 Anthropic `/v1/messages` 请求，自动注入 Claude Code 指纹后转发至 Anthropic API，让普通 API 调用享受 Claude Code 同等待遇。

## 特性

- **Claude Code 指纹注入** — 自动伪装为 Claude CLI 客户端（版本号、User-Agent、Beta Features、CCH 签名、Fingerprint）
- **OAuth Token 管理** — 使用 Anthropic OAuth 认证，Token 过期前自动刷新
- **多 API Key** — 支持多个自定义 API Key，通过 `Authorization: Bearer <key>` 或 `x-api-key` 鉴权
- **智能 Thinking** — 根据模型自动选择 thinking 模式：Opus 用 adaptive，Sonnet 用 enabled（budget 10K），Haiku 不启用
- **缓存断点** — 自动在最后两条用户消息上注入 `cache_control`，最大化 Prompt Caching 命中率
- **SSE 流式透传** — 完整转发上游 SSE 流，实时记录 Token 用量和耗时
- **SQLite 日志** — 每条请求记录状态、耗时、Token 用量、完整请求/响应体
- **Telegram Bot** — 可选的管理面板：API Key 管理、OAuth 管理、统计汇总、调用日志

## 部署

### 环境要求

- Python 3.10+
- pip

### 安装

```bash
# 克隆或复制项目文件
mkdir -p /opt/cc-proxy
cp server.py tgbot.py db.py config.json /opt/cc-proxy/

# 创建虚拟环境并安装依赖
cd /opt/cc-proxy
python3 -m venv venv
source venv/bin/activate
pip install requests xxhash
```

### 配置

#### config.json

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 18081,
  "api_keys": {
    "my-app": "ccp-your-api-key-here"
  },
  "oauth_file": "oauth.json",
  "telegram_bot_token": "",
  "telegram_admin_ids": [],
  "db_path": "cc-proxy.db",
  "log_dir": "logs"
}
```

| 字段 | 说明 |
|------|------|
| `listen_host` | 监听地址，`0.0.0.0` 监听所有接口 |
| `listen_port` | 监听端口 |
| `api_keys` | API Key 映射，`名称: Key`，可通过 TG Bot 管理 |
| `oauth_file` | OAuth Token 文件路径（相对于项目目录） |
| `telegram_bot_token` | Telegram Bot Token，留空则不启用 Bot |
| `telegram_admin_ids` | 允许使用 Bot 的 Telegram 用户 ID 列表，空数组表示不限制 |
| `db_path` | SQLite 数据库路径 |
| `log_dir` | 日志目录（预留字段） |

#### oauth.json

从 Claude 平台获取 OAuth Token，格式如下：

```json
{
  "access_token": "sk-ant-oat01-your-access-token",
  "disabled": false,
  "email": "your-email@example.com",
  "expired": "2026-01-01T00:00:00Z",
  "id_token": "",
  "last_refresh": "2026-01-01T00:00:00Z",
  "refresh_token": "sk-ant-ort01-your-refresh-token",
  "type": "claude"
}
```

> Token 过期前 5 分钟会自动使用 `refresh_token` 刷新。

### 启动

```bash
# 直接运行
cd /opt/cc-proxy
./venv/bin/python3 -u server.py

# 或使用 systemd（推荐）
sudo cp cc-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cc-proxy
```

#### systemd 服务文件

```ini
[Unit]
Description=CC Proxy - Claude Code API Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/cc-proxy
ExecStart=/opt/cc-proxy/venv/bin/python3 -u /opt/cc-proxy/server.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

## 使用

### API 调用

与标准 Anthropic API 完全兼容，只需将 base URL 指向 CC Proxy：

```bash
curl -X POST http://your-server:18081/v1/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ccp-your-api-key-here" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 8192,
    "stream": true,
    "messages": [
      {"role": "user", "content": "Hello!"}
    ]
  }'
```

支持的鉴权方式：
- `Authorization: Bearer <api-key>`
- `x-api-key: <api-key>`

### Telegram Bot

启用 Bot 后，发送 `/start` 或 `/menu` 打开管理面板：

| 功能 | 说明 |
|------|------|
| 🔑 管理 API Key | 添加/删除 API Key |
| 🔐 管理 OAuth | 查看/设置/刷新 OAuth Token |
| 📊 统计汇总 | 按时间范围查看请求统计、Token 用量、错误详情 |
| 📋 最近日志 | 查看最近 20 条调用日志及耗时 |

快捷命令：`/keys`、`/oauth`、`/stats`、`/logs`

## 技术细节

### 伪装机制

CC Proxy 模拟 Claude Code CLI 客户端的完整特征：

| 特征 | 实现 |
|------|------|
| **User-Agent** | `claude-cli/{version} (external, cli)` |
| **Beta Features** | 7 个 Claude Code 专属 beta flag |
| **Fingerprint** | 基于首条用户消息 + 盐值 + 版本号的 SHA256 前 3 位 |
| **CCH 签名** | xxHash64 全 body 签名，嵌入 billing header |
| **System Prompt** | 注入 billing attribution + Claude Code 身份声明 |
| **Metadata** | 包含 device_id 和 account_uuid |
| **Thinking** | Opus: adaptive / Sonnet: enabled (10K budget) / Haiku: 关闭 |
| **缓存断点** | 最后两条 user 消息 + tools 末尾 + system 末尾 |
| **Context Management** | `clear_thinking_20251015` + `keep: all` |

### 请求转换流程

```
客户端请求
  ↓
API Key 验证
  ↓
提取 user system prompt → 注入为 messages[0] (user) + messages[1] (assistant: "Understood.")
  ↓
注入 Claude Code system blocks (billing header + identity)
  ↓
添加缓存断点 (最后两条 user message + tools 末尾)
  ↓
设置 thinking 模式 (根据模型)
  ↓
工具名重写 (sessions_ → sessions_, session_ → cc_ses_)
  ↓
CCH 签名 (xxHash64)
  ↓
获取 OAuth access_token (自动刷新)
  ↓
转发至 Anthropic API
  ↓
响应流中还原工具名 → 透传给客户端
```

### 数据库结构

两张表：

- **request_log** — 轻量日志（状态、耗时、Token 用量）
- **request_detail** — 完整请求/响应体（调试用）

## 文件说明

```
cc-proxy/
├── server.py           # 主服务：HTTP 代理 + OAuth + 指纹注入
├── tgbot.py            # Telegram Bot 管理面板
├── db.py               # SQLite 日志模块
├── config.json         # 配置文件
├── oauth.json          # OAuth Token（需自行填写）
├── cc-proxy.service    # systemd 服务文件
└── cc-proxy.db         # SQLite 数据库（运行后自动创建）
```

## 注意事项

- OAuth Token 需要从 Claude 平台获取，首次需手动填写 `oauth.json`
- `api_keys` 为空时所有请求都会被拒绝，至少需要添加一个
- 数据库文件 `cc-proxy.db` 运行后自动创建，使用 WAL 模式
- `telegram_admin_ids` 为空数组时任何人都可以使用 Bot，生产环境建议填写管理员 ID
- 默认伪装版本为 Claude CLI v2.1.92，如需更新请修改 `server.py` 中的 `CC_VERSION` 和 `BETAS`

## License

MIT
