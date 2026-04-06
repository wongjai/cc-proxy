"""
CC Proxy v2.0 — Claude Code 模拟中转服务
接收 /v1/messages 请求，注入 Claude Code 参数后转发至 Anthropic API。
支持多 API Key、SQLite 日志、Telegram Bot 管理。
"""

import json
import hashlib
import uuid
import os
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone, timedelta

import requests
import xxhash

import db
import tgbot

# ─── 配置加载 ───

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


CFG = load_config()

LISTEN_HOST = CFG.get("listen_host", "0.0.0.0")
LISTEN_PORT = CFG.get("listen_port", 18081)
ANTHROPIC_API_BASE = "https://api.anthropic.com"
OAUTH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), CFG.get("oauth_file", "oauth.json"))
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), CFG.get("db_path", "cc-proxy.db"))

CC_VERSION = "2.1.92"
FINGERPRINT_SALT = "59cf53e54c78"
CC_ENTRYPOINT = "cli"
USER_TYPE = "external"

BETAS = [
    "claude-code-20250219",
    "oauth-2025-04-20",
    "interleaved-thinking-2025-05-14",
    "prompt-caching-scope-2026-01-05",
    "effort-2025-11-24",
    "redact-thinking-2026-02-12",
    "context-management-2025-06-27",
]


# ─── 持久 device_id ───

def _load_or_create_device_id(path):
    ids_file = os.path.join(path, ".cc_proxy_ids.json")
    if os.path.exists(ids_file):
        with open(ids_file) as f:
            return json.load(f).get("device_id", os.urandom(32).hex())
    device_id = os.urandom(32).hex()
    os.makedirs(path, exist_ok=True)
    with open(ids_file, "w") as f:
        json.dump({"device_id": device_id}, f)
    return device_id


DEVICE_ID = _load_or_create_device_id(os.path.dirname(os.path.abspath(__file__)))


# ─── API Key 验证 ───

def validate_api_key(headers):
    """从请求 headers 中提取并验证 API Key，返回 (key_name, error_msg)"""
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    api_key = headers.get("x-api-key") or ""

    token = ""
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
    elif api_key:
        token = api_key.strip()

    if not token:
        return None, "Missing API key"

    cfg = load_config()
    for name, key in cfg.get("api_keys", {}).items():
        if key == token:
            return name, None

    return None, "Invalid API key"


# ─── OAuth token 管理 ───

_token_lock = threading.Lock()


def _load_oauth():
    with open(OAUTH_FILE) as f:
        return json.load(f)


def _save_oauth(data):
    with open(OAUTH_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _refresh_token(oauth_data):
    print(f"[OAuth] Refreshing token...")
    resp = requests.post(
        "https://platform.claude.com/v1/oauth/token",
        json={
            "grant_type": "refresh_token",
            "refresh_token": oauth_data["refresh_token"],
            "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            "scope": "user:inference user:profile",
        },
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    token_data = resp.json()
    oauth_data["access_token"] = token_data["access_token"]
    if "refresh_token" in token_data:
        oauth_data["refresh_token"] = token_data["refresh_token"]
    expires_in = token_data.get("expires_in", 28800)
    expired_dt = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    oauth_data["expired"] = expired_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    oauth_data["last_refresh"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _save_oauth(oauth_data)
    print(f"[OAuth] Token refreshed, expires at {oauth_data['expired']}")
    return oauth_data["access_token"]


def get_access_token():
    with _token_lock:
        oauth_data = _load_oauth()
        expired_str = oauth_data.get("expired", "")
        if expired_str:
            try:
                expired_dt = datetime.fromisoformat(expired_str.replace("Z", "+00:00"))
                if (expired_dt - datetime.now(timezone.utc)).total_seconds() < 300:
                    return _refresh_token(oauth_data)
            except Exception:
                return _refresh_token(oauth_data)
        return oauth_data["access_token"]


# ─── Fingerprint ───

def compute_fingerprint(messages):
    first_text = ""
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                first_text = content
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        first_text = block.get("text", "")
                        break
            break
    indices = [4, 7, 20]
    chars = "".join(first_text[i] if i < len(first_text) else "0" for i in indices)
    return hashlib.sha256(f"{FINGERPRINT_SALT}{chars}{CC_VERSION}".encode()).hexdigest()[:3]


# ─── System prompt ───

def build_system_blocks(messages):
    fp = compute_fingerprint(messages)
    version = f"{CC_VERSION}.{fp}"
    attribution = f"x-anthropic-billing-header: cc_version={version}; cc_entrypoint={CC_ENTRYPOINT}; cch=00000;"
    return [
        {"type": "text", "text": attribution},
        {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude.", "cache_control": {"type": "ephemeral"}},
    ]


def inject_user_system_to_messages(messages, user_system):
    if not user_system:
        if messages and messages[0].get("role") != "user":
            messages = list(messages)
            messages.insert(0, {"role": "user", "content": [{"type": "text", "text": "..."}]})
        return messages
    system_text = user_system if isinstance(user_system, str) else ""
    if isinstance(user_system, list):
        parts = []
        for block in user_system:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        system_text = "\n\n".join(parts)
    if not system_text.strip():
        if messages and messages[0].get("role") != "user":
            messages = list(messages)
            messages.insert(0, {"role": "user", "content": [{"type": "text", "text": "..."}]})
        return messages
    messages = list(messages)
    messages.insert(0, {"role": "user", "content": [{"type": "text", "text": system_text}]})
    messages.insert(1, {"role": "assistant", "content": [{"type": "text", "text": "Understood."}]})
    return messages


# ─── 缓存断点 ───

def _inject_cache_on_msg(msg):
    msg = dict(msg)
    content = msg.get("content")
    if isinstance(content, list) and content:
        content = list(content)
        last_block = dict(content[-1])
        last_block["cache_control"] = {"type": "ephemeral"}
        content[-1] = last_block
        msg["content"] = content
    elif isinstance(content, str):
        msg["content"] = [{"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}]
    return msg


def add_cache_breakpoints(messages):
    if not messages:
        return messages
    messages = [dict(m) for m in messages]
    messages[-1] = _inject_cache_on_msg(messages[-1])
    if len(messages) >= 3:
        for i in range(len(messages) - 2, -1, -1):
            if messages[i].get("role") == "user":
                messages[i] = _inject_cache_on_msg(messages[i])
                break
    return messages


# ─── Metadata ───

def build_metadata():
    try:
        email = _load_oauth().get("email", "")
        account_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, email)) if email else ""
    except Exception:
        account_uuid = ""
    return {"user_id": json.dumps({"device_id": DEVICE_ID, "account_uuid": account_uuid}, separators=(",", ":"))}


# ─── 工具名重写 ───

TOOL_NAME_REWRITES = {"sessions_": "cc_sess_", "session_": "cc_ses_"}


def _sanitize_tool_name(name):
    for prefix, replacement in TOOL_NAME_REWRITES.items():
        if name.startswith(prefix):
            return replacement + name[len(prefix):]
    return name


def _restore_tool_names_in_chunk(chunk_bytes):
    for prefix, replacement in TOOL_NAME_REWRITES.items():
        chunk_bytes = chunk_bytes.replace(replacement.encode(), prefix.encode())
    return chunk_bytes


# ─── 请求转换 ───

def transform_request(body):
    messages = body.get("messages", [])
    user_system = body.get("system")
    messages = inject_user_system_to_messages(messages, user_system)
    messages = add_cache_breakpoints(messages)
    system_blocks = build_system_blocks(messages)

    model = body.get("model", "claude-sonnet-4-20250514")
    ml = model.lower()
    supports_adaptive = "opus-4-6" in ml
    supports_thinking = "haiku" not in ml and not supports_adaptive

    payload = {
        "model": model,
        "messages": messages,
        "system": system_blocks,
        "max_tokens": body.get("max_tokens", 128000),
        "stream": True,
        "metadata": build_metadata(),
        "temperature": 1,
    }

    if supports_adaptive:
        payload["thinking"] = {"type": "adaptive"}
    elif supports_thinking:
        max_out = body.get("max_tokens", 128000)
        budget = min(max_out - 1, 10000)
        if budget >= 1024:
            payload["thinking"] = {"type": "enabled", "budget_tokens": budget}
        # budget < 1024 时不启用 thinking（API 要求最少 1024）

    if body.get("tools"):
        tools = [dict(t) for t in body["tools"]]
        for t in tools:
            t["name"] = _sanitize_tool_name(t["name"])
        tools[-1] = dict(tools[-1])
        tools[-1]["cache_control"] = {"type": "ephemeral"}
        payload["tools"] = tools

    if "tool_choice" in body:
        tc = body["tool_choice"]
        if isinstance(tc, dict) and "name" in tc:
            tc = dict(tc)
            tc["name"] = _sanitize_tool_name(tc["name"])
        payload["tool_choice"] = tc

    if supports_adaptive or supports_thinking:
        payload["context_management"] = {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]}
        payload["output_config"] = {"effort": "high"}

    return payload


# ─── CCH 签名 ───

CCH_SEED = 0x6E52736AC806831E
CCH_PLACEHOLDER = b"cch=00000"


def sign_body(payload_dict):
    body_bytes = json.dumps(payload_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    h = xxhash.xxh64(body_bytes, seed=CCH_SEED).intdigest()
    cch = f"{h & 0xFFFFF:05x}"
    return body_bytes.replace(CCH_PLACEHOLDER, f"cch={cch}".encode("ascii"), 1)


def build_upstream_headers(access_token):
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "anthropic-version": "2023-06-01",
        "anthropic-beta": ",".join(BETAS),
        "x-app": "cli",
        "User-Agent": f"claude-cli/{CC_VERSION} ({USER_TYPE}, {CC_ENTRYPOINT})",
        "x-client-request-id": str(uuid.uuid4()),
    }


# ─── SSE 流解析（提取 usage）───

def _parse_sse_usage(sse_text):
    """从完整的 SSE 文本中提取 usage 信息"""
    usage = {"input_tokens": 0, "output_tokens": 0, "cache_creation": 0, "cache_read": 0}
    for line in sse_text.split("\n"):
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            evt = json.loads(data)
        except Exception:
            continue
        t = evt.get("type", "")
        if t == "message_start":
            u = evt.get("message", {}).get("usage", {})
            usage["input_tokens"] = u.get("input_tokens", 0)
            usage["cache_creation"] = u.get("cache_creation_input_tokens", 0)
            usage["cache_read"] = u.get("cache_read_input_tokens", 0)
        elif t == "message_delta":
            u = evt.get("usage", {})
            usage["output_tokens"] = u.get("output_tokens", 0)
    return usage


# ─── HTTP Handler ───

class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path not in ("/v1/messages", "/v1/messages?beta=true"):
            self._json_response(404, {"error": "not_found"})
            return

        t_start = time.time()
        request_id = str(uuid.uuid4())
        client_ip = self.client_address[0] if self.client_address else "?"

        # API Key 验证
        key_name, err = validate_api_key(self.headers)
        if err:
            self._json_response(401, {"error": err})
            return

        # 读取请求体
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length) if content_length > 0 else b""
        try:
            body = json.loads(raw)
        except Exception as e:
            self._json_response(400, {"error": f"invalid json: {e}"})
            return

        model = body.get("model", "?")
        is_stream = body.get("stream", True)
        msg_count = len(body.get("messages", []))
        tool_count = len(body.get("tools", []))

        # 记录请求头（脱敏）
        req_headers = dict(self.headers)
        for h in ("Authorization", "authorization", "x-api-key"):
            if h in req_headers:
                req_headers[h] = "***"

        # 写入 pending 日志
        db.insert_pending(request_id, client_ip, key_name, model, is_stream,
                          msg_count, tool_count, req_headers, body)

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[{ts}] {client_ip} {key_name} -> {model} | msgs={msg_count} tools={tool_count}")

        # 转换请求
        try:
            payload = transform_request(body)
        except Exception as e:
            import traceback; traceback.print_exc()
            db.finish_error(request_id, str(e), 0, int((time.time() - t_start) * 1000))
            self._json_response(500, {"error": f"transform error: {e}"})
            return

        # 获取 token
        try:
            access_token = get_access_token()
        except Exception as e:
            import traceback; traceback.print_exc()
            db.finish_error(request_id, f"oauth: {e}", 0, int((time.time() - t_start) * 1000))
            self._json_response(502, {"error": f"oauth error: {e}"})
            return

        headers = build_upstream_headers(access_token)
        signed_body = sign_body(payload)

        # 转发
        t_connect_start = time.time()
        try:
            resp = requests.post(
                f"{ANTHROPIC_API_BASE}/v1/messages?beta=true",
                headers=headers, data=signed_body, stream=True, timeout=(15, 600),
            )
            t_connected = time.time()
            connect_ms = int((t_connected - t_connect_start) * 1000)

            if resp.status_code >= 400:
                err_body = resp.text[:4000]
                total_ms = int((time.time() - t_start) * 1000)
                db.finish_error(request_id, f"HTTP {resp.status_code}: {err_body}", connect_ms, total_ms, err_body)
                self.send_response(resp.status_code)
                self.send_header("Content-Type", resp.headers.get("content-type", "application/json"))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                restored = _restore_tool_names_in_chunk(err_body.encode())
                self.wfile.write(restored)
                return

            # 透传
            self.send_response(resp.status_code)
            for h in ("content-type", "x-request-id", "request-id"):
                if h in resp.headers:
                    self.send_header(h, resp.headers[h])
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            full_response = b""
            first_chunk = True
            t_first_token = None

            for chunk in resp.iter_content(chunk_size=None):
                if chunk:
                    if first_chunk:
                        t_first_token = time.time()
                        first_chunk = False
                    restored = _restore_tool_names_in_chunk(chunk)
                    full_response += restored
                    self.wfile.write(restored)
                    self.wfile.flush()

            # 解析 usage
            total_ms = int((time.time() - t_start) * 1000)
            first_token_ms = int((t_first_token - t_start) * 1000) if t_first_token else None
            usage = _parse_sse_usage(full_response.decode("utf-8", errors="replace"))

            db.finish_success(
                request_id,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                cache_creation=usage["cache_creation"],
                cache_read=usage["cache_read"],
                connect_ms=connect_ms,
                first_token_ms=first_token_ms,
                total_ms=total_ms,
                response_body=full_response.decode("utf-8", errors="replace")[:500000],
            )

        except requests.Timeout:
            total_ms = int((time.time() - t_start) * 1000)
            db.finish_error(request_id, "upstream timeout", None, total_ms)
            self._json_response(504, {"error": "upstream timeout"})
        except requests.ConnectionError as e:
            total_ms = int((time.time() - t_start) * 1000)
            db.finish_error(request_id, f"connection error: {e}", None, total_ms)
            self._json_response(502, {"error": f"upstream connection error: {e}"})
        except Exception as e:
            total_ms = int((time.time() - t_start) * 1000)
            db.finish_error(request_id, str(e), None, total_ms)
            try:
                self._json_response(502, {"error": str(e)})
            except Exception:
                pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def _json_response(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


# ─── 启动 ───

def main():
    # 初始化数据库
    db.init(DB_PATH)

    # 初始化 TG Bot
    tg_token = CFG.get("telegram_bot_token", "")
    tg_admins = CFG.get("telegram_admin_ids", [])
    if tg_token:
        tgbot.init(tg_token, tg_admins, CONFIG_PATH,
                    get_access_token, _refresh_token, _load_oauth, _save_oauth)
        tgbot.start()

    print(f"CC Proxy v2.0 | claude-cli/{CC_VERSION}")
    print(f"  device_id: {DEVICE_ID[:16]}...")
    print(f"  betas: {len(BETAS)}")
    print(f"  api_keys: {len(CFG.get('api_keys', {}))}")
    print(f"  oauth: {OAUTH_FILE}")
    print(f"  db: {DB_PATH}")
    print(f"  telegram: {'enabled' if tg_token else 'disabled'}")
    print(f"Listening on http://{LISTEN_HOST}:{LISTEN_PORT}/v1/messages")
    print()

    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), ProxyHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
