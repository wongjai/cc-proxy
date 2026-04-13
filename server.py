"""
CC Proxy v3.0 — Claude Code 模擬中轉服務
基於 FastAPI + uvicorn + httpx，異步併發，連接池複用。
"""

import json
import hashlib
import hmac
import uuid
import os
import time
import asyncio
import threading
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager

import httpx
import xxhash
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.background import BackgroundTask

import db
import tgbot

# ─── 配置加載（帶緩存）───

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

_config_cache = None
_config_mtime = 0
_config_lock = threading.Lock()


def load_config():
    global _config_cache, _config_mtime
    with _config_lock:
        try:
            mt = os.path.getmtime(CONFIG_PATH)
        except OSError:
            mt = 0
        if _config_cache is None or mt != _config_mtime:
            with open(CONFIG_PATH) as f:
                _config_cache = json.load(f)
            _config_mtime = mt
        return _config_cache


CFG = load_config()

LISTEN_HOST = CFG.get("listen_host", "0.0.0.0")
LISTEN_PORT = CFG.get("listen_port", 18081)
ANTHROPIC_API_BASE = "https://api.anthropic.com"
OAUTH_FILE = os.path.join(BASE_DIR, CFG.get("oauth_file", "oauth.json"))
DB_PATH = os.path.join(BASE_DIR, CFG.get("db_path", "cc-proxy.db"))

CC_VERSION = "2.1.104"
FINGERPRINT_SALT = "59cf53e54c78"
CC_ENTRYPOINT = "cli"
USER_TYPE = "external"

BASE_BETAS = [
    "claude-code-20250219",
    "oauth-2025-04-20",
]
THINKING_BETAS = [
    "interleaved-thinking-2025-05-14",
    "redact-thinking-2026-02-12",
]
CONTEXT_MANAGEMENT_BETA = "context-management-2025-06-27"
PROMPT_CACHING_SCOPE_BETA = "prompt-caching-scope-2026-01-05"
EFFORT_BETA = "effort-2025-11-24"
EXTENDED_CACHE_TTL_BETA = "extended-cache-ttl-2025-04-11"

UPSTREAM_TIMEOUT = httpx.Timeout(connect=15.0, read=330.0, write=30.0, pool=15.0)
CLI_USER_AGENT = f"claude-cli/{CC_VERSION} ({USER_TYPE}, {CC_ENTRYPOINT})"


# ─── 持久 device_id ───

def _load_or_create_device_id():
    ids_file = os.path.join(BASE_DIR, ".cc_proxy_ids.json")
    if os.path.exists(ids_file):
        with open(ids_file) as f:
            return json.load(f).get("device_id", os.urandom(32).hex())
    device_id = os.urandom(32).hex()
    with open(ids_file, "w") as f:
        json.dump({"device_id": device_id}, f)
    return device_id


DEVICE_ID = _load_or_create_device_id()


# ─── API Key 驗證（常數時間比較）───

def validate_api_key(headers):
    auth = headers.get("authorization") or ""
    api_key = headers.get("x-api-key") or ""

    token = ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    elif api_key:
        token = api_key.strip()

    if not token:
        return None, "Missing API key"

    cfg = load_config()
    for name, key in cfg.get("api_keys", {}).items():
        if hmac.compare_digest(key, token):
            return name, None

    return None, "Invalid API key"


# ─── OAuth token 管理（帶緩存）───

_oauth_lock = asyncio.Lock()
_oauth_cache = None
_oauth_mtime = 0


def _load_oauth_sync():
    global _oauth_cache, _oauth_mtime
    try:
        mt = os.path.getmtime(OAUTH_FILE)
    except OSError:
        mt = 0
    if _oauth_cache is None or mt != _oauth_mtime:
        with open(OAUTH_FILE) as f:
            _oauth_cache = json.load(f)
        _oauth_mtime = mt
    return _oauth_cache


def _save_oauth_sync(data):
    global _oauth_cache, _oauth_mtime
    tmp = OAUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, OAUTH_FILE)
    _oauth_cache = data
    try:
        _oauth_mtime = os.path.getmtime(OAUTH_FILE)
    except OSError:
        _oauth_mtime = 0


# 同步版本供 tgbot 使用
_sync_token_lock = threading.Lock()


def _load_oauth():
    return _load_oauth_sync()


def _save_oauth(data):
    with _sync_token_lock:
        _save_oauth_sync(data)


def _refresh_token(oauth_data):
    """刷新 OAuth token — 使用 _sync_token_lock 序列化所有調用者（async + tgbot）"""
    with _sync_token_lock:
        print("[OAuth] Refreshing token...")
        resp = httpx.post(
            "https://api.anthropic.com/v1/oauth/token",
            json={
                "grant_type": "refresh_token",
                "refresh_token": oauth_data["refresh_token"],
                "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            },
            headers={"Content-Type": "application/json", "User-Agent": CLI_USER_AGENT},
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
        _save_oauth_sync(oauth_data)
        print(f"[OAuth] Token refreshed, expires at {oauth_data['expired']}")
        return oauth_data["access_token"]


async def _proactive_token_refresh():
    """主動檢查 token 是否即將過期（< 10 分鐘），提前刷新並通知 TG。
    刷新最多重試 3 次，用量獲取最多重試 2 次。"""
    try:
        oauth_data = _load_oauth_sync()
    except Exception as e:
        print(f"[OAuth] Proactive: load oauth failed: {e}")
        return

    expired_str = oauth_data.get("expired", "")
    if not expired_str:
        return

    try:
        expired_dt = datetime.fromisoformat(expired_str.replace("Z", "+00:00"))
        remaining = (expired_dt - datetime.now(timezone.utc)).total_seconds()
    except Exception:
        remaining = -1  # 解析失敗視爲已過期，直接刷

    if remaining >= 600:
        return  # 還有 10 分鐘以上，不動

    print(f"[OAuth] Proactive: {remaining:.0f}s remaining, refreshing...")

    # 刷新 token，最多重試 3 次
    access_token = None
    last_err = None
    for attempt in range(1, 4):
        try:
            access_token = await asyncio.to_thread(_refresh_token, oauth_data)
            print(f"[OAuth] Proactive: refresh OK (attempt {attempt})")
            break
        except Exception as e:
            last_err = e
            print(f"[OAuth] Proactive: refresh attempt {attempt} failed: {e}")
            if attempt < 3:
                await asyncio.sleep(10 * attempt)  # 10s, 20s

    if access_token is None:
        msg = f"⚠️ OAuth 主動刷新失敗（已重試 3 次）\n錯誤: {last_err}"
        print(f"[OAuth] Proactive: all retries failed")
        tgbot.notify_admins(msg)
        return

    # 重新讀取刷新後的 oauth（_refresh_token 已寫入文件）
    try:
        oauth_data = _load_oauth_sync()
        new_expired = oauth_data.get("expired", "?")
    except Exception:
        new_expired = "?"

    # 獲取用量，最多重試 2 次
    usage_text = ""
    for attempt in range(1, 3):
        try:
            usage_data = await asyncio.to_thread(tgbot._fetch_oauth_usage, access_token)
            usage_text = tgbot._format_usage(usage_data)
            break
        except Exception as e:
            print(f"[OAuth] Proactive: usage fetch attempt {attempt} failed: {e}")
            if attempt < 2:
                await asyncio.sleep(5)
            else:
                usage_text = f"⚠️ 用量獲取失敗: {e}"

    # 北京時間格式化
    def _to_bjt(s):
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            bjt = dt.astimezone(timezone(timedelta(hours=8)))
            return bjt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return s

    msg = (
        f"✅ OAuth Token 已主動刷新\n"
        f"新過期時間: <code>{_to_bjt(new_expired)}</code>\n\n"
        f"<b>📊 當前用量</b>\n{usage_text}"
    )
    tgbot.notify_admins(msg)


async def get_access_token():
    async with _oauth_lock:
        oauth_data = _load_oauth_sync()
        expired_str = oauth_data.get("expired", "")
        if expired_str:
            try:
                expired_dt = datetime.fromisoformat(expired_str.replace("Z", "+00:00"))
                if (expired_dt - datetime.now(timezone.utc)).total_seconds() < 300:
                    try:
                        return await asyncio.to_thread(_refresh_token, oauth_data)
                    except Exception as e:
                        tgbot.notify_admins(f"⚠️ OAuth 自動刷新失敗: {e}")
                        raise
            except Exception:
                try:
                    return await asyncio.to_thread(_refresh_token, oauth_data)
                except Exception as e:
                    tgbot.notify_admins(f"⚠️ OAuth 自動刷新失敗: {e}")
                    raise
        return oauth_data["access_token"]


def get_access_token_sync():
    """同步版本供 tgbot 使用"""
    oauth_data = _load_oauth_sync()
    expired_str = oauth_data.get("expired", "")
    if expired_str:
        try:
            expired_dt = datetime.fromisoformat(expired_str.replace("Z", "+00:00"))
            if (expired_dt - datetime.now(timezone.utc)).total_seconds() < 300:
                return _refresh_token(oauth_data)  # _refresh_token 內部持有 _sync_token_lock
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

def get_cache_control_config():
    cfg = load_config()
    raw = cfg.get("cache_control", {})
    if not isinstance(raw, dict):
        raw = {}

    default_ttl = raw.get("default_ttl", "")
    if default_ttl is None:
        default_ttl = ""
    default_ttl = str(default_ttl).strip().lower()
    if default_ttl in ("", "default", "5m", "none", "off"):
        default_ttl = ""
    elif default_ttl != "1h":
        default_ttl = ""

    return {
        "default_ttl": default_ttl,
        "respect_client_cache_control": bool(raw.get("respect_client_cache_control", False)),
    }


def make_cache_control(default_ttl=""):
    cache_control = {"type": "ephemeral"}
    if default_ttl == "1h":
        cache_control["ttl"] = "1h"
    return cache_control


def build_system_blocks(messages, default_ttl=""):
    fp = compute_fingerprint(messages)
    version = f"{CC_VERSION}.{fp}"
    attribution = f"x-anthropic-billing-header: cc_version={version}; cc_entrypoint={CC_ENTRYPOINT}; cch=00000;"
    return [
        {"type": "text", "text": attribution},
        {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude.", "cache_control": make_cache_control(default_ttl)},
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


# ─── 緩存斷點 ───

def _inject_cache_on_msg(msg, default_ttl=""):
    msg = dict(msg)
    content = msg.get("content")
    if isinstance(content, list) and content:
        content = list(content)
        if isinstance(content[-1], dict):
            last_block = dict(content[-1])
            last_block["cache_control"] = make_cache_control(default_ttl)
            content[-1] = last_block
            msg["content"] = content
    elif isinstance(content, str):
        msg["content"] = [{"type": "text", "text": content, "cache_control": make_cache_control(default_ttl)}]
    return msg


def _msg_has_cache_control(msg):
    """檢查消息的 content block 中是否已有 cache_control"""
    content = msg.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and "cache_control" in block:
                return True
    return False


def _strip_message_cache_control(messages):
    """移除客戶端在 messages 中設置的所有 cache_control 標記。
    客戶端會在最後一條 user message 上設置 cache_control，當下一輪對話中該消息
    不再是最後一條時，標記消失導致內容塊變化，使前綴緩存失效。
    由代理統一管理 cache_control 可確保前綴在連續請求間保持穩定。"""
    result = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, list):
            changed = False
            for block in content:
                if isinstance(block, dict) and "cache_control" in block:
                    changed = True
                    break
            if changed:
                msg = dict(msg)
                new_content = []
                for block in content:
                    if isinstance(block, dict) and "cache_control" in block:
                        block = {k: v for k, v in block.items() if k != "cache_control"}
                    new_content.append(block)
                msg["content"] = new_content
            result.append(msg)
        else:
            result.append(msg)
    return result


def _tools_have_cache_control(tools):
    for tool in tools:
        if isinstance(tool, dict) and "cache_control" in tool:
            return True
    return False


def _strip_tool_cache_control(tools):
    result = []
    for tool in tools:
        if isinstance(tool, dict) and "cache_control" in tool:
            tool = {k: v for k, v in tool.items() if k != "cache_control"}
        result.append(tool)
    return result


def add_cache_breakpoints(messages, default_ttl="", preserve_existing=False):
    """注入緩存斷點。斷點位置：倒數第二個 user turn + 最後一條消息。
    加上 system + tools 共 4 個斷點（上限）。
    preserve_existing=True 時，若客戶端已在 messages 中提供 cache_control，則完全保留。"""
    if not messages:
        return messages
    messages = [dict(m) for m in messages]

    if preserve_existing and any(_msg_has_cache_control(msg) for msg in messages):
        return messages

    # 1. 最後一條消息
    messages[-1] = _inject_cache_on_msg(messages[-1], default_ttl)

    # 2. 倒數第二個 user turn：緩存多輪對話歷史
    #    確保會話前綴在連續請求間可被複用
    if len(messages) >= 4:
        user_count = 0
        for i in range(len(messages) - 1, -1, -1):
            if messages[i].get("role") == "user":
                user_count += 1
                if user_count == 2:
                    messages[i] = _inject_cache_on_msg(messages[i], default_ttl)
                    break

    return messages


def normalize_cache_control_ttl(payload):
    """1h TTL 不能出現在任意更早的 5m/default breakpoint 之後；較晚出現的 1h 會降級為預設 5m。"""
    seen_default_ttl = False

    def normalize_cache_control(cache_control):
        nonlocal seen_default_ttl
        if not isinstance(cache_control, dict):
            seen_default_ttl = True
            return cache_control

        ttl = cache_control.get("ttl")
        if ttl == "1h":
            if seen_default_ttl:
                cache_control = dict(cache_control)
                cache_control.pop("ttl", None)
                seen_default_ttl = True
                return cache_control
            return cache_control

        seen_default_ttl = True
        if ttl == "5m":
            cache_control = dict(cache_control)
            cache_control.pop("ttl", None)
        return cache_control

    tools = payload.get("tools")
    if isinstance(tools, list):
        new_tools = []
        for tool in tools:
            if isinstance(tool, dict) and "cache_control" in tool:
                tool = dict(tool)
                tool["cache_control"] = normalize_cache_control(tool.get("cache_control"))
            new_tools.append(tool)
        payload["tools"] = new_tools

    system = payload.get("system")
    if isinstance(system, list):
        new_system = []
        for block in system:
            if isinstance(block, dict) and "cache_control" in block:
                block = dict(block)
                block["cache_control"] = normalize_cache_control(block.get("cache_control"))
            new_system.append(block)
        payload["system"] = new_system

    messages = payload.get("messages")
    if isinstance(messages, list):
        new_messages = []
        for msg in messages:
            if isinstance(msg, dict) and isinstance(msg.get("content"), list):
                msg = dict(msg)
                new_content = []
                for block in msg["content"]:
                    if isinstance(block, dict) and "cache_control" in block:
                        block = dict(block)
                        block["cache_control"] = normalize_cache_control(block.get("cache_control"))
                    new_content.append(block)
                msg["content"] = new_content
            new_messages.append(msg)
        payload["messages"] = new_messages

    return payload


def payload_uses_one_hour_ttl(payload):
    def has_one_hour(items):
        if not isinstance(items, list):
            return False
        for item in items:
            if isinstance(item, dict):
                cache_control = item.get("cache_control")
                if isinstance(cache_control, dict) and cache_control.get("ttl") == "1h":
                    return True
        return False

    if has_one_hour(payload.get("tools")) or has_one_hour(payload.get("system")):
        return True

    for msg in payload.get("messages", []):
        if isinstance(msg, dict) and has_one_hour(msg.get("content")):
            return True
    return False


def _append_beta(betas, beta):
    if beta and beta not in betas:
        betas.append(beta)


def payload_uses_thinking(payload):
    thinking = payload.get("thinking")
    return isinstance(thinking, dict) and thinking.get("type") in {"enabled", "adaptive"}


def payload_uses_context_management(payload):
    cm = payload.get("context_management")
    edits = cm.get("edits") if isinstance(cm, dict) else None
    return isinstance(edits, list) and bool(edits)


def payload_uses_effort(payload):
    output_config = payload.get("output_config")
    return isinstance(output_config, dict) and bool(output_config.get("effort"))


def build_anthropic_betas(payload):
    betas = list(BASE_BETAS)
    if payload_uses_thinking(payload):
        for beta in THINKING_BETAS:
            _append_beta(betas, beta)
    if payload_uses_context_management(payload):
        _append_beta(betas, CONTEXT_MANAGEMENT_BETA)
    _append_beta(betas, PROMPT_CACHING_SCOPE_BETA)
    if payload_uses_effort(payload):
        _append_beta(betas, EFFORT_BETA)
    if payload_uses_one_hour_ttl(payload):
        _append_beta(betas, EXTENDED_CACHE_TTL_BETA)
    return betas


# ─── Metadata（使用緩存的 oauth）───

def build_metadata():
    try:
        email = _load_oauth_sync().get("email", "")
        account_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, email)) if email else ""
    except Exception:
        account_uuid = ""
    return {"user_id": json.dumps({"device_id": DEVICE_ID, "account_uuid": account_uuid}, separators=(",", ":"))}


# ─── 工具名重寫 ───

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


# ─── 請求轉換 ───

def transform_request(body):
    cache_cfg = get_cache_control_config()
    messages = body.get("messages", [])
    user_system = body.get("system")
    messages = inject_user_system_to_messages(messages, user_system)
    if not cache_cfg["respect_client_cache_control"]:
        messages = _strip_message_cache_control(messages)
    messages = add_cache_breakpoints(
        messages,
        default_ttl=cache_cfg["default_ttl"],
        preserve_existing=cache_cfg["respect_client_cache_control"],
    )
    system_blocks = build_system_blocks(messages, cache_cfg["default_ttl"])

    model = body.get("model", "claude-sonnet-4-20250514")
    ml = model.lower()
    supports_adaptive = "opus-4-6" in ml
    supports_thinking = "haiku" not in ml and not supports_adaptive

    payload = {
        "model": model,
        "messages": messages,
        "system": system_blocks,
        "max_tokens": body.get("max_tokens", 128000),
        "stream": body.get("stream", True),
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

    if body.get("tools"):
        tools = [dict(t) for t in body["tools"]]
        for t in tools:
            t["name"] = _sanitize_tool_name(t["name"])
        if not cache_cfg["respect_client_cache_control"]:
            tools = _strip_tool_cache_control(tools)
        if tools and not _tools_have_cache_control(tools):
            tools[-1] = dict(tools[-1])
            tools[-1]["cache_control"] = make_cache_control(cache_cfg["default_ttl"])
        payload["tools"] = tools

    if "tool_choice" in body:
        tc = body["tool_choice"]
        if isinstance(tc, dict) and "name" in tc:
            tc = dict(tc)
            tc["name"] = _sanitize_tool_name(tc["name"])
        payload["tool_choice"] = tc

    if payload_uses_thinking(payload):
        payload["context_management"] = {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]}
    if supports_adaptive:
        payload["output_config"] = {"effort": "high"}

    return normalize_cache_control_ttl(payload)


# ─── CCH 簽名 ───

CCH_SEED = 0x6E52736AC806831E
CCH_PLACEHOLDER = b"cch=00000"


def sign_body(payload_dict):
    body_bytes = json.dumps(payload_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    h = xxhash.xxh64(body_bytes, seed=CCH_SEED).intdigest()
    cch = f"{h & 0xFFFFF:05x}"
    return body_bytes.replace(CCH_PLACEHOLDER, f"cch={cch}".encode("ascii"), 1)


def build_upstream_headers(access_token, payload):
    betas = build_anthropic_betas(payload)
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "anthropic-version": "2023-06-01",
        "anthropic-beta": ",".join(betas),
        "x-app": "cli",
        "User-Agent": CLI_USER_AGENT,
        "x-client-request-id": str(uuid.uuid4()),
    }


def build_claude_error_payload(err_type, message):
    return {
        "type": "error",
        "error": {
            "type": err_type,
            "message": message,
        },
    }


def build_claude_error_response(status_code, err_type, message):
    return JSONResponse(
        status_code=status_code,
        content=build_claude_error_payload(err_type, message),
    )


def is_retryable_transport_error(exc):
    return isinstance(exc, (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError))


async def retry_sleep(attempt):
    await asyncio.sleep(0.5 * attempt)


def extract_usage_from_response_json(response_obj):
    usage = response_obj.get("usage", {}) if isinstance(response_obj, dict) else {}
    return {
        "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0),
        "cache_creation": usage.get("cache_creation_input_tokens", 0),
        "cache_read": usage.get("cache_read_input_tokens", 0),
    }


# ─── SSE 流式 usage 解析器（流式提取，不存全量）───

class SSEUsageTracker:
    """從 SSE 流中實時提取 usage，同時收集完整響應用於 DB 存儲。
    使用行緩衝處理跨 chunk 的 JSON 事件。"""

    def __init__(self):
        self.usage = {"input_tokens": 0, "output_tokens": 0, "cache_creation": 0, "cache_read": 0}
        self._chunks = []
        self._buf = b""

    def feed(self, chunk_bytes):
        self._chunks.append(chunk_bytes)
        self._buf += chunk_bytes
        # 按行處理，保留不完整的尾行到下次
        while b"\n" in self._buf:
            line_bytes, self._buf = self._buf.split(b"\n", 1)
            line = line_bytes.decode("utf-8", errors="replace")
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
                self.usage["input_tokens"] = u.get("input_tokens", 0)
                self.usage["cache_creation"] = u.get("cache_creation_input_tokens", 0)
                self.usage["cache_read"] = u.get("cache_read_input_tokens", 0)
            elif t == "message_delta":
                u = evt.get("usage", {})
                self.usage["output_tokens"] = u.get("output_tokens", 0)

    def get_full_response(self):
        """返回完整響應文本，不截斷"""
        return b"".join(self._chunks).decode("utf-8", errors="replace")


# ─── FastAPI 應用 ───

_http_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client
    # 啓動
    db.init(DB_PATH)
    db.cleanup_stale_pending(timeout_seconds=600)

    _http_client = httpx.AsyncClient(
        timeout=UPSTREAM_TIMEOUT,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        http2=False,
    )

    tg_token = CFG.get("telegram_bot_token", "")
    tg_admins = CFG.get("telegram_admin_ids", [])
    if tg_token:
        tgbot.init(tg_token, tg_admins, CONFIG_PATH,
                    get_access_token_sync, _refresh_token, _load_oauth, _save_oauth)
        tgbot.start()

    cache_cfg = get_cache_control_config()
    print(f"CC Proxy v3.0 | claude-cli/{CC_VERSION}")
    print(f"  device_id: {DEVICE_ID[:16]}...")
    print(f"  betas: {len(BASE_BETAS)} base + dynamic per payload")
    print(f"  cache ttl default: {cache_cfg['default_ttl'] or '5m'}")
    print(f"  respect client cache_control: {cache_cfg['respect_client_cache_control']}")
    print(f"  api_keys: {len(CFG.get('api_keys', {}))}")
    print(f"  oauth: {OAUTH_FILE}")
    print(f"  db: {DB_PATH}")
    print(f"  telegram: {'enabled' if tg_token else 'disabled'}")
    print(f"Listening on http://{LISTEN_HOST}:{LISTEN_PORT}/v1/messages")
    print()

    # 啓動定期 WAL checkpoint
    async def wal_checkpoint_loop():
        while True:
            await asyncio.sleep(300)
            try:
                db.checkpoint()
            except Exception as e:
                print(f"[DB] WAL checkpoint failed: {e}")

    async def stale_pending_cleanup_loop():
        while True:
            await asyncio.sleep(300)
            try:
                await asyncio.to_thread(db.cleanup_stale_pending, 1800)
            except Exception as e:
                print(f"[DB] stale pending cleanup failed: {e}")

    # 主動 OAuth token 刷新循環（剩餘 < 10 分鐘時刷新）
    async def oauth_proactive_refresh_loop():
        await asyncio.sleep(30)  # 啓動後等 30s 再開始
        while True:
            try:
                await _proactive_token_refresh()
            except Exception as e:
                print(f"[OAuth] Proactive refresh loop error: {e}")
            await asyncio.sleep(60)

    _wal_task = asyncio.create_task(wal_checkpoint_loop())
    _cleanup_task = asyncio.create_task(stale_pending_cleanup_loop())
    _refresh_task = asyncio.create_task(oauth_proactive_refresh_loop())

    yield

    # 關閉
    _wal_task.cancel()
    _cleanup_task.cancel()
    _refresh_task.cancel()
    await _http_client.aclose()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/v1/messages")
async def proxy_messages(request: Request):
    t_start = time.time()
    request_id = str(uuid.uuid4())
    client_ip = request.client.host if request.client else "?"

    # API Key 驗證
    key_name, err = validate_api_key(request.headers)
    if err:
        return build_claude_error_response(401, "authentication_error", err)

    # 讀取請求體
    raw = await request.body()
    try:
        body = json.loads(raw)
    except Exception as e:
        return build_claude_error_response(400, "invalid_request_error", f"invalid json: {e}")

    model = body.get("model", "?")
    is_stream = body.get("stream", True)
    msg_count = len(body.get("messages", []))
    tool_count = len(body.get("tools", []))

    # 記錄請求頭（脫敏）
    req_headers = dict(request.headers)
    for h in ("authorization", "x-api-key"):
        if h in req_headers:
            req_headers[h] = "***"

    # 寫入 pending 日誌
    await asyncio.to_thread(db.insert_pending, request_id, client_ip, key_name, model, is_stream,
                            msg_count, tool_count, req_headers, body)

    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {client_ip} {key_name} -> {model} | msgs={msg_count} tools={tool_count}")

    # 轉換請求
    try:
        payload = transform_request(body)
    except Exception as e:
        import traceback; traceback.print_exc()
        await asyncio.to_thread(
            db.finish_error,
            request_id,
            str(e),
            0,
            int((time.time() - t_start) * 1000),
            retry_count=0,
        )
        return build_claude_error_response(400, "invalid_request_error", f"transform error: {e}")

    # 獲取 token
    try:
        access_token = await get_access_token()
    except Exception as e:
        import traceback; traceback.print_exc()
        await asyncio.to_thread(
            db.finish_error,
            request_id,
            f"oauth: {e}",
            0,
            int((time.time() - t_start) * 1000),
            retry_count=0,
        )
        return build_claude_error_response(502, "api_error", f"oauth error: {e}")

    headers = build_upstream_headers(access_token, payload)
    signed_body = sign_body(payload)
    max_attempts = 2
    retry_count = 0

    # 轉發（異步流式）
    refreshed_after_auth_error = False

    try:
        for attempt in range(1, max_attempts + 1):
            t_connect_start = time.time()
            upstream_resp = None
            connect_ms = None
            try:
                headers = build_upstream_headers(access_token, payload)
                upstream_req = _http_client.build_request(
                    "POST",
                    f"{ANTHROPIC_API_BASE}/v1/messages?beta=true",
                    headers=headers,
                    content=signed_body,
                )
                upstream_resp = await _http_client.send(upstream_req, stream=is_stream)
                t_connected = time.time()
                connect_ms = int((t_connected - t_connect_start) * 1000)

                if upstream_resp.status_code >= 400:
                    err_body = (await upstream_resp.aread()).decode("utf-8", errors="replace")
                    await upstream_resp.aclose()

                    if upstream_resp.status_code in (401, 403) and not refreshed_after_auth_error:
                        refreshed_after_auth_error = True
                        oauth_data = _load_oauth_sync()
                        access_token = await asyncio.to_thread(_refresh_token, oauth_data)
                        retry_count += 1
                        continue

                    if 500 <= upstream_resp.status_code < 600 and attempt < max_attempts:
                        retry_count += 1
                        await retry_sleep(attempt)
                        continue

                    total_ms = int((time.time() - t_start) * 1000)
                    await asyncio.to_thread(
                        db.finish_error,
                        request_id,
                        f"HTTP {upstream_resp.status_code}: {err_body[:4000]}",
                        connect_ms,
                        total_ms,
                        err_body,
                        retry_count=retry_count,
                    )
                    restored = _restore_tool_names_in_chunk(err_body.encode())
                    resp_headers = {}
                    for h in ("content-type", "x-request-id", "request-id"):
                        if h in upstream_resp.headers:
                            resp_headers[h] = upstream_resp.headers[h]
                    return Response(
                        content=restored,
                        status_code=upstream_resp.status_code,
                        headers=resp_headers,
                        media_type=upstream_resp.headers.get("content-type", "application/json"),
                    )

                if not is_stream:
                    try:
                        raw_resp = await upstream_resp.aread()
                    except Exception as e:
                        await upstream_resp.aclose()
                        if is_retryable_transport_error(e) and attempt < max_attempts:
                            retry_count += 1
                            await retry_sleep(attempt)
                            continue
                        raise

                    await upstream_resp.aclose()
                    if not raw_resp:
                        if attempt < max_attempts:
                            await retry_sleep(attempt)
                            continue
                        total_ms = int((time.time() - t_start) * 1000)
                        await asyncio.to_thread(
                            db.finish_error,
                            request_id,
                            "upstream returned empty response body",
                            connect_ms,
                            total_ms,
                            retry_count=retry_count,
                        )
                        return build_claude_error_response(
                            502,
                            "api_error",
                            "Upstream returned an empty response before any content was available.",
                        )

                    restored = _restore_tool_names_in_chunk(raw_resp)
                    total_ms = int((time.time() - t_start) * 1000)
                    try:
                        response_obj = json.loads(restored)
                        usage = extract_usage_from_response_json(response_obj)
                    except Exception:
                        response_obj = None
                        usage = {
                            "input_tokens": 0,
                            "output_tokens": 0,
                            "cache_creation": 0,
                            "cache_read": 0,
                        }
                    await asyncio.to_thread(
                        db.finish_success,
                        request_id,
                        input_tokens=usage["input_tokens"],
                        output_tokens=usage["output_tokens"],
                        cache_creation=usage["cache_creation"],
                        cache_read=usage["cache_read"],
                        connect_ms=connect_ms,
                        first_token_ms=None,
                        total_ms=total_ms,
                        response_body=restored.decode("utf-8", errors="replace"),
                        retry_count=retry_count,
                    )
                    resp_headers = {}
                    for h in ("content-type", "x-request-id", "request-id"):
                        if h in upstream_resp.headers:
                            resp_headers[h] = upstream_resp.headers[h]
                    if response_obj is not None:
                        return JSONResponse(
                            content=response_obj,
                            status_code=upstream_resp.status_code,
                            headers=resp_headers,
                        )
                    return Response(
                        content=restored,
                        status_code=upstream_resp.status_code,
                        headers=resp_headers,
                        media_type=upstream_resp.headers.get("content-type", "application/json"),
                    )

                try:
                    first_chunk = b""
                    stream_iter = upstream_resp.aiter_bytes()
                    upstream_stream_empty = False
                    while True:
                        chunk = await anext(stream_iter)
                        if chunk:
                            first_chunk = _restore_tool_names_in_chunk(chunk)
                            break
                except StopAsyncIteration:
                    upstream_stream_empty = True
                    if attempt < max_attempts:
                        await upstream_resp.aclose()
                        retry_count += 1
                        await retry_sleep(attempt)
                        continue
                    total_ms = int((time.time() - t_start) * 1000)
                    await asyncio.to_thread(
                        db.finish_error,
                        request_id,
                        "upstream closed stream before first chunk",
                        connect_ms,
                        total_ms,
                        retry_count=retry_count,
                    )
                    return build_claude_error_response(
                        502,
                        "api_error",
                        "Upstream stream closed before first token was returned.",
                    )
                except Exception as e:
                    await upstream_resp.aclose()
                    if is_retryable_transport_error(e) and attempt < max_attempts:
                        retry_count += 1
                        await retry_sleep(attempt)
                        continue
                    raise

                tracker = SSEUsageTracker()
                finalized = False
                finalize_lock = asyncio.Lock()
                first_token_ts = time.time() if first_chunk else None
                if first_chunk:
                    tracker.feed(first_chunk)

                async def finalize_success():
                    nonlocal finalized
                    async with finalize_lock:
                        if finalized:
                            return
                        finalized = True
                        total_ms = int((time.time() - t_start) * 1000)
                        first_token_ms = int((first_token_ts - t_start) * 1000) if first_token_ts else None
                        await asyncio.to_thread(
                            db.finish_success,
                            request_id,
                            input_tokens=tracker.usage["input_tokens"],
                            output_tokens=tracker.usage["output_tokens"],
                            cache_creation=tracker.usage["cache_creation"],
                            cache_read=tracker.usage["cache_read"],
                            connect_ms=connect_ms,
                            first_token_ms=first_token_ms,
                            total_ms=total_ms,
                            response_body=tracker.get_full_response(),
                            retry_count=retry_count,
                        )

                async def finalize_error(message, response_body=None):
                    nonlocal finalized
                    async with finalize_lock:
                        if finalized:
                            return
                        finalized = True
                        total_ms = int((time.time() - t_start) * 1000)
                        await asyncio.to_thread(
                            db.finish_error,
                            request_id,
                            message,
                            connect_ms,
                            total_ms,
                            response_body,
                            retry_count=retry_count,
                        )

                async def stream_generator():
                    completed = False
                    try:
                        if first_chunk:
                            yield first_chunk
                        if not upstream_stream_empty:
                            async for chunk in stream_iter:
                                if chunk:
                                    restored = _restore_tool_names_in_chunk(chunk)
                                    tracker.feed(restored)
                                    yield restored
                        completed = True
                    except BaseException as e:
                        err_type = type(e).__name__
                        await finalize_error(f"stream {err_type}: {e}", tracker.get_full_response())
                        return
                    finally:
                        await upstream_resp.aclose()

                    if completed:
                        await finalize_success()

                async def on_response_close():
                    await upstream_resp.aclose()
                    await finalize_error("response closed before stream completed", tracker.get_full_response())

                resp_headers = {}
                for h in ("content-type", "x-request-id", "request-id"):
                    if h in upstream_resp.headers:
                        resp_headers[h] = upstream_resp.headers[h]

                return StreamingResponse(
                    stream_generator(),
                    status_code=upstream_resp.status_code,
                    headers=resp_headers,
                    background=BackgroundTask(on_response_close),
                )

            except Exception as e:
                if upstream_resp is not None:
                    try:
                        await upstream_resp.aclose()
                    except Exception:
                        pass
                if is_retryable_transport_error(e) and attempt < max_attempts:
                    retry_count += 1
                    await retry_sleep(attempt)
                    continue
                raise

    except httpx.TimeoutException as e:
        total_ms = int((time.time() - t_start) * 1000)
        msg = f"upstream timeout: {e}"
        await asyncio.to_thread(db.finish_error, request_id, msg, None, total_ms, retry_count=retry_count)
        return build_claude_error_response(504, "api_error", "Upstream request timed out before any response was returned.")
    except httpx.ConnectError as e:
        total_ms = int((time.time() - t_start) * 1000)
        msg = f"connection error: {e}"
        await asyncio.to_thread(db.finish_error, request_id, msg, None, total_ms, retry_count=retry_count)
        return build_claude_error_response(502, "api_error", "Upstream connection failed before any response was returned.")
    except (httpx.ReadError, httpx.RemoteProtocolError) as e:
        total_ms = int((time.time() - t_start) * 1000)
        msg = f"transport error: {e}"
        await asyncio.to_thread(db.finish_error, request_id, msg, None, total_ms, retry_count=retry_count)
        return build_claude_error_response(502, "api_error", "Upstream transport failed before any response was returned.")
    except Exception as e:
        total_ms = int((time.time() - t_start) * 1000)
        await asyncio.to_thread(db.finish_error, request_id, str(e), None, total_ms, retry_count=retry_count)
        return build_claude_error_response(502, "api_error", str(e))
    except BaseException as e:
        total_ms = int((time.time() - t_start) * 1000)
        await asyncio.to_thread(
            db.finish_error,
            request_id,
            f"request {type(e).__name__}: {e}",
            None,
            total_ms,
            retry_count=retry_count,
        )
        raise


# ─── 啓動 ───

def main():
    uvicorn.run(
        app,
        host=LISTEN_HOST,
        port=LISTEN_PORT,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
