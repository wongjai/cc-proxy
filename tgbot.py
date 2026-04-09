"""Telegram Bot 模塊 — 管理 API Key、OAuth、查看統計和日誌"""

import json
import os
import time
import secrets
import hashlib
import base64
import threading
import traceback
from datetime import datetime, timezone, timedelta

_BJT = timezone(timedelta(hours=8))  # 北京時間 UTC+8
from urllib.request import Request, urlopen
from urllib.error import URLError

import httpx

import db

# ─── OAuth 常量 ───

OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
OAUTH_AUTHORIZE_URL = "https://claude.com/cai/oauth/authorize"
OAUTH_TOKEN_URL = "https://api.anthropic.com/v1/oauth/token"
OAUTH_MANUAL_REDIRECT = "https://platform.claude.com/oauth/code/callback"
OAUTH_PROFILE_URL = "https://api.anthropic.com/api/oauth/profile"
OAUTH_USAGE_URL = "https://api.anthropic.com/api/oauth/usage"
OAUTH_SCOPES = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"

_bot_token = None
_admin_ids = set()
_config_path = None
_get_access_token = None  # 由 server.py 注入
_refresh_fn = None         # 由 server.py 注入
_load_oauth = None
_save_oauth = None
_offset = 0
_user_states = {}          # chat_id -> {"action": ..., "data": ..., "ts": time.time()}
_USER_STATE_TTL = 600      # 10 分鐘過期
_tg_session = None         # httpx 持久連接


def init(bot_token, admin_ids, config_path, get_token_fn, refresh_fn, load_oauth_fn, save_oauth_fn):
    global _bot_token, _admin_ids, _config_path, _get_access_token, _refresh_fn, _load_oauth, _save_oauth
    _bot_token = bot_token
    _admin_ids = set(admin_ids)
    _config_path = config_path
    _get_access_token = get_token_fn
    _refresh_fn = refresh_fn
    _load_oauth = load_oauth_fn
    _save_oauth = save_oauth_fn


def start():
    if not _bot_token:
        return
    global _tg_session
    _tg_session = httpx.Client(
        timeout=httpx.Timeout(connect=10.0, read=50.0, write=10.0, pool=10.0),
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=2, keepalive_expiry=30),
        http2=False,
    )
    # 註冊 Bot 命令菜單
    _api("setMyCommands", {
        "commands": [
            {"command": "start", "description": "打開管理面板"},
            {"command": "menu", "description": "打開管理面板"},
            {"command": "keys", "description": "管理 API Key"},
            {"command": "oauth", "description": "管理 OAuth Token"},
            {"command": "stats", "description": "統計彙總"},
            {"command": "logs", "description": "最近調用日誌"},
        ]
    })
    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    print(f"[TG Bot] Started polling, commands registered")


# ─── Telegram API（httpx 持久連接）───

def _api(method, data=None):
    url = f"https://api.telegram.org/bot{_bot_token}/{method}"
    try:
        if data:
            resp = _tg_session.post(url, json=data)
        else:
            resp = _tg_session.get(url)
        return resp.json()
    except Exception as e:
        print(f"[TG Bot] API error: {e}")
        return None


def notify_admins(text):
    """向所有管理員發送通知"""
    for admin_id in _admin_ids:
        _send(admin_id, text)


def _send(chat_id, text, reply_markup=None, parse_mode="HTML"):
    data = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
    if reply_markup:
        data["reply_markup"] = reply_markup
    return _api("sendMessage", data)


def _edit(chat_id, message_id, text, reply_markup=None):
    data = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        data["reply_markup"] = reply_markup
    return _api("editMessageText", data)


def _answer_cb(callback_query_id, text=None):
    data = {"callback_query_id": callback_query_id}
    if text is not None:
        data["text"] = text
    _api("answerCallbackQuery", data)


def _inline_kb(buttons):
    """buttons: [[{"text":..., "callback_data":...}, ...], ...]"""
    return {"inline_keyboard": buttons}


# ─── Config helpers ───

def _load_config():
    with open(_config_path) as f:
        return json.load(f)


def _save_config(cfg):
    tmp = _config_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, _config_path)


# ─── Main menu ───

def _show_menu(chat_id):
    _send(chat_id, "<b>CC Proxy 管理面板</b>", _inline_kb([
        [{"text": "🔐 管理 OAuth", "callback_data": "menu_oauth"}],
        [{"text": "🔑 管理 API Key", "callback_data": "menu_apikey"}],
        [{"text": "📊 統計彙總", "callback_data": "menu_stats"}],
        [{"text": "📋 最近日誌", "callback_data": "menu_logs"}],
    ]))


# ─── API Key management ───

def _handle_apikey_menu(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    cfg = _load_config()
    keys = cfg.get("api_keys", {})
    text = f"<b>API Key 管理</b>\n當前: {len(keys)} 個\n"
    for name in keys:
        text += f"  • <code>{name}</code>\n"
    _edit(chat_id, msg_id, text, _inline_kb([
        [{"text": "➕ 添加", "callback_data": "ak_add"}, {"text": "🗑 刪除", "callback_data": "ak_del"}],
        [{"text": "◀ 返回", "callback_data": "back_menu"}],
    ]))


def _handle_ak_add(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    _user_states[chat_id] = {"action": "ak_add_name", "ts": time.time()}
    _edit(chat_id, msg_id, "請輸入新 API Key 的名稱（如: my-app）：")


def _handle_ak_add_name(chat_id, text):
    name = text.strip()
    if not name or " " in name:
        _send(chat_id, "名稱無效，不能含空格，請重新輸入：")
        return
    cfg = _load_config()
    if name in cfg.get("api_keys", {}):
        _send(chat_id, f"名稱 <code>{name}</code> 已存在，請換一個：")
        return
    apikey = f"ccp-{secrets.token_hex(24)}"
    cfg.setdefault("api_keys", {})[name] = apikey
    _save_config(cfg)
    _user_states.pop(chat_id, None)
    _send(chat_id, f"✅ API Key 已創建\n\n名稱: <code>{name}</code>\nKey: <code>{apikey}</code>\n\n請妥善保存，不會再次顯示。")
    _show_menu(chat_id)


def _handle_ak_del(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    cfg = _load_config()
    keys = list(cfg.get("api_keys", {}).keys())
    if not keys:
        _edit(chat_id, msg_id, "沒有任何 API Key。", _inline_kb([[{"text": "◀ 返回", "callback_data": "back_menu"}]]))
        return
    buttons = [[{"text": f"🗑 {name}", "callback_data": f"ak_del_confirm:{name}"}] for name in keys]
    buttons.append([{"text": "◀ 返回", "callback_data": "menu_apikey"}])
    _edit(chat_id, msg_id, "選擇要刪除的 Key：", _inline_kb(buttons))


def _handle_ak_del_confirm(chat_id, msg_id, cb_id, name):
    _answer_cb(cb_id)
    _edit(chat_id, msg_id, f"確認刪除 <code>{name}</code>？", _inline_kb([
        [{"text": "✅ 確認刪除", "callback_data": f"ak_del_exec:{name}"},
         {"text": "❌ 取消", "callback_data": "menu_apikey"}],
    ]))


def _handle_ak_del_exec(chat_id, msg_id, cb_id, name):
    _answer_cb(cb_id, "已刪除")
    cfg = _load_config()
    cfg.get("api_keys", {}).pop(name, None)
    _save_config(cfg)
    _edit(chat_id, msg_id, f"✅ 已刪除 <code>{name}</code>")
    _show_menu(chat_id)


# ─── OAuth management ───

def _handle_oauth_menu(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    try:
        oauth = _load_oauth()
        email = oauth.get("email", "?")
        expired = _utc_to_bjt(oauth.get("expired", ""))

        # 獲取使用量（token 過期會自動刷新）
        usage_text = ""
        try:
            access_token = _get_access_token()
            usage_data = _fetch_oauth_usage(access_token)
            usage_text = _format_usage(usage_data)
        except Exception as e:
            usage_text = f"⚠️ 獲取使用量失敗: {e}"

        text = (
            f"<b>OAuth 管理</b>\n"
            f"Email: <code>{email}</code>\n"
            f"過期: <code>{expired}</code>\n\n"
            f"<b>📊 使用量</b>\n{usage_text}"
        )
    except Exception:
        text = "<b>OAuth 管理</b>\n⚠️ 未配置 OAuth"
    _edit(chat_id, msg_id, text, _inline_kb([
        [{"text": "🔑 登錄獲取 Token", "callback_data": "oa_login"}],
        [{"text": "📝 設置 OAuth", "callback_data": "oa_set"}],
        [{"text": "🔄 刷新 Token", "callback_data": "oa_refresh"}],
        [{"text": "◀ 返回", "callback_data": "back_menu"}],
    ]))


def _pkce_generate():
    """生成 PKCE code_verifier 和 code_challenge (S256)"""
    verifier_bytes = secrets.token_bytes(32)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode()
    challenge_hash = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_hash).rstrip(b"=").decode()
    return code_verifier, code_challenge


def _build_oauth_login_url(code_challenge, state):
    """構建 OAuth 手動登錄 URL"""
    params = {
        "code": "true",
        "client_id": OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": OAUTH_MANUAL_REDIRECT,
        "scope": OAUTH_SCOPES,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    from urllib.parse import urlencode
    return f"{OAUTH_AUTHORIZE_URL}?{urlencode(params)}"


_OAUTH_UA = "claude-cli/2.1.92 (external, cli)"


def _exchange_code_for_tokens(code, code_verifier, state):
    """用 authorization code 換取 token"""
    data = json.dumps({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OAUTH_MANUAL_REDIRECT,
        "client_id": OAUTH_CLIENT_ID,
        "code_verifier": code_verifier,
        "state": state,
    }).encode()
    req = Request(OAUTH_TOKEN_URL, data=data, headers={
        "Content-Type": "application/json",
        "User-Agent": _OAUTH_UA,
    })
    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _fetch_oauth_profile(access_token):
    """獲取用戶 profile 信息"""
    req = Request(OAUTH_PROFILE_URL, headers={
        "Authorization": f"Bearer {access_token}",
        "anthropic-beta": "oauth-2025-04-20",
        "User-Agent": _OAUTH_UA,
    })
    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _fetch_oauth_usage(access_token):
    """獲取 OAuth 賬戶使用量"""
    req = Request(OAUTH_USAGE_URL, headers={
        "Authorization": f"Bearer {access_token}",
        "anthropic-beta": "oauth-2025-04-20",
        "User-Agent": _OAUTH_UA,
    })
    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _format_usage(usage_data):
    """格式化使用量信息爲可讀文本"""
    if not usage_data:
        return "❓ 無法獲取使用量"

    lines = []

    # 5-hour window
    fh = usage_data.get("five_hour")
    if fh and fh.get("utilization") is not None:
        util = fh["utilization"]
        reset = fh.get("resets_at")
        line = f"⏱ 5h: {util:.0f}%"
        if reset:
            line += f" (重置: {_utc_to_bjt(reset)})"
        lines.append(line)

    # 7-day window
    sd = usage_data.get("seven_day")
    if sd and sd.get("utilization") is not None:
        util = sd["utilization"]
        reset = sd.get("resets_at")
        line = f"📅 7d: {util:.0f}%"
        if reset:
            line += f" (重置: {_utc_to_bjt(reset)})"
        lines.append(line)

    # 7-day sonnet
    sds = usage_data.get("seven_day_sonnet")
    if sds and sds.get("utilization") is not None:
        util = sds["utilization"]
        reset = sds.get("resets_at")
        line = f"🤖 Sonnet 7d: {util:.0f}%"
        if reset:
            line += f" (重置: {_utc_to_bjt(reset)})"
        lines.append(line)

    # 7-day opus
    sdo = usage_data.get("seven_day_opus")
    if sdo and sdo.get("utilization") is not None:
        util = sdo["utilization"]
        reset = sdo.get("resets_at")
        line = f"🧠 Opus 7d: {util:.0f}%"
        if reset:
            line += f" (重置: {_utc_to_bjt(reset)})"
        lines.append(line)

    # Extra usage credits
    extra = usage_data.get("extra_usage")
    if extra and extra.get("is_enabled"):
        used = extra.get("used_credits", 0)
        limit = extra.get("monthly_limit", 0)
        util = extra.get("utilization", 0)
        line = f"💰 額外額度: ${used:.2f} / ${limit:.2f} ({util:.1f}%)"
        lines.append(line)

    return "\n".join(lines) if lines else "✅ 無使用量數據"


def _handle_oa_login(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    code_verifier, code_challenge = _pkce_generate()
    state = secrets.token_urlsafe(32)
    url = _build_oauth_login_url(code_challenge, state)
    _user_states[chat_id] = {
        "action": "oa_login_code",
        "data": {"code_verifier": code_verifier, "state": state},
        "ts": time.time(),
    }
    _edit(chat_id, msg_id,
          "請在瀏覽器中打開以下鏈接並登錄：\n\n"
          f"<code>{url}</code>\n\n"
          "登錄完成後，頁面會顯示一個 <b>authorization code</b>，請將其複製併發送給我。")


def _handle_oa_login_code(chat_id, text):
    state_data = _user_states.pop(chat_id, {}).get("data", {})
    if "code_verifier" not in state_data:
        _send(chat_id, "❌ 登錄會話已過期，請重新點擊「登錄獲取 Token」。")
        _show_menu(chat_id)
        return
    raw = text.strip()
    if not raw:
        _send(chat_id, "❌ code 不能爲空，請重新操作。")
        _show_menu(chat_id)
        return
    # 頁面返回的格式是 code#state，需要拆分
    if "#" in raw:
        code = raw.split("#", 1)[0]
    else:
        code = raw
    try:
        token_resp = _exchange_code_for_tokens(
            code, state_data["code_verifier"], state_data["state"])
    except Exception as e:
        detail = ""
        if hasattr(e, "read"):
            try:
                detail = "\n" + e.read().decode()
            except Exception:
                pass
        _send(chat_id, f"❌ Token 交換失敗: {e}{detail}")
        _show_menu(chat_id)
        return
    # 獲取 profile
    email = ""
    try:
        profile = _fetch_oauth_profile(token_resp["access_token"])
        email = profile.get("account", {}).get("email", "")
    except Exception:
        pass
    # 計算過期時間
    expires_in = token_resp.get("expires_in", 28800)
    expired_dt = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    oauth_data = {
        "access_token": token_resp["access_token"],
        "refresh_token": token_resp.get("refresh_token", ""),
        "expired": expired_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_refresh": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "email": email,
        "type": "claude",
    }
    _save_oauth(oauth_data)
    _send(chat_id,
          f"✅ OAuth 登錄成功！\n\n"
          f"Email: <code>{email or '未知'}</code>\n"
          f"過期: <code>{_utc_to_bjt(oauth_data['expired'])}</code>")
    _show_menu(chat_id)


def _handle_oa_set(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    _user_states[chat_id] = {"action": "oa_set_json", "ts": time.time()}
    _edit(chat_id, msg_id, "請輸入 OAuth JSON（含 access_token, refresh_token, expired, email）：")


def _handle_oa_set_json(chat_id, text):
    _user_states.pop(chat_id, None)
    try:
        data = json.loads(text.strip())
        for key in ("access_token", "refresh_token"):
            if key not in data:
                _send(chat_id, f"❌ 缺少字段: {key}")
                return
        _save_oauth(data)
        _send(chat_id, f"✅ OAuth 已保存\nEmail: <code>{data.get('email', '?')}</code>")
    except json.JSONDecodeError:
        _send(chat_id, "❌ JSON 格式錯誤")
    _show_menu(chat_id)


def _handle_oa_refresh(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    try:
        oauth = _load_oauth()
        expired_str = oauth.get("expired", "")
        if expired_str:
            from datetime import datetime as dt
            expired_dt = dt.fromisoformat(expired_str.replace("Z", "+00:00"))
            remaining = (expired_dt - dt.now(timezone.utc)).total_seconds()
            if remaining > 300:
                _edit(chat_id, msg_id,
                      f"Token 仍有效，剩餘 {int(remaining//60)} 分鐘\n過期: <code>{_utc_to_bjt(expired_str)}</code>",
                      _inline_kb([
                          [{"text": "🔄 強制刷新", "callback_data": "oa_force_refresh"}],
                          [{"text": "◀ 返回", "callback_data": "menu_oauth"}],
                      ]))
                return
        _refresh_fn(oauth)
        oauth = _load_oauth()
        _edit(chat_id, msg_id, f"✅ Token 已刷新\n新過期: <code>{_utc_to_bjt(oauth.get('expired', ''))}</code>")
    except Exception as e:
        _edit(chat_id, msg_id, f"❌ 刷新失敗: {e}")
    _show_menu(chat_id)


def _handle_oa_force_refresh(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    try:
        oauth = _load_oauth()
        _refresh_fn(oauth)
        oauth = _load_oauth()  # 重新讀取刷新後的數據
        _edit(chat_id, msg_id, f"✅ 強制刷新成功\n新過期: <code>{_utc_to_bjt(oauth.get('expired', ''))}</code>")
    except Exception as e:
        _edit(chat_id, msg_id, f"❌ 刷新失敗: {e}")
    _show_menu(chat_id)


# ─── Stats ───

def _handle_stats_menu(chat_id, msg_id, cb_id):
    _handle_stats(chat_id, msg_id, cb_id, "0")


def _handle_stats(chat_id, msg_id, cb_id, period):
    _answer_cb(cb_id)
    now = time.time()
    if period == "month":
        month_start = datetime.now(_BJT).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        since = month_start.timestamp()
        label = "本月"
    elif period == "0":
        today = datetime.now(_BJT).replace(hour=0, minute=0, second=0, microsecond=0)
        since = today.timestamp()
        label = "今天"
    else:
        since = now - int(period) * 86400
        label = f"最近 {period} 天"

    row, _errors, recent_calls = db.stats_summary(since)
    total = row["total"] or 0
    text = f"<b>📊 統計 — {label}</b>\n\n"
    raw_inp = (row['total_input_tokens'] or 0)
    raw_out = (row['total_output_tokens'] or 0)
    raw_cr = (row['total_cache_read'] or 0)
    total_retries = row['total_retries'] or 0
    retried_requests = row['retried_requests'] or 0
    total_inp = raw_inp + (row['total_cache_creation'] or 0) + raw_cr
    cache_hit_rate = (raw_cr / total_inp * 100) if total_inp > 0 else 0
    success_count = row['success_count'] or 0
    error_count = row['error_count'] or 0
    pending_count = row['pending_count'] or 0
    success_rate = (success_count / total * 100) if total > 0 else 0

    text += "Tokens:\n"
    text += f"↑ {_fmt_tokens(total_inp)} | ↓ {_fmt_tokens(raw_out)} | cache {_fmt_tokens(raw_cr)} ({cache_hit_rate:.1f}%)\n\n"
    text += "請求:\n"
    text += f"共 {total} 次 | ✅ {success_count} | ❌ {error_count} | ⏳ {pending_count}\n"
    text += f"成功率 {success_rate:.1f}%\n\n"
    text += "耗時（平均）:\n"
    conn_avg = f"{row['avg_connect_ms']:.0f}ms" if row["avg_connect_ms"] is not None else "-"
    first_avg = f"{row['avg_first_token_ms']:.0f}ms" if row["avg_first_token_ms"] is not None else "-"
    total_avg = f"{row['avg_total_ms']:.0f}ms" if row["avg_total_ms"] is not None else "-"
    text += f"連接 {conn_avg} | 首字 {first_avg} | 總 {total_avg}\n"
    if total > 0:
        text += "\n重試:\n"
        text += f"共 {total_retries} 次 | 命中 {retried_requests} 個請求 ({retried_requests / total * 100:.1f}%)\n"

    if recent_calls:
        text += "\n<b>最近調用:</b>\n"
        for r in recent_calls:
            ts = datetime.fromtimestamp(r["created_at"], tz=_BJT).strftime("%m-%d %H:%M:%S")
            status_icon = {"success": "✅", "error": "❌", "pending": "⏳"}.get(r["status"], "?")
            text += f"\n<code>[{ts}]</code> {status_icon} {r['model'] or '?'}\n"
            details = []
            if r["status"] == "success":
                inp = (r["input_tokens"] or 0) + (r["cache_creation_tokens"] or 0) + (r["cache_read_tokens"] or 0)
                details.append(f"Tokens: ↑{_fmt_tokens(inp)} | ↓{_fmt_tokens(r['output_tokens'] or 0)} | cache {_fmt_tokens(r['cache_read_tokens'] or 0)}")
            timing = []
            if r["connect_time_ms"] is not None:
                timing.append(f"連接 {r['connect_time_ms'] / 1000:.1f}s")
            if r["is_stream"] and r["first_token_time_ms"] is not None:
                timing.append(f"首字 {r['first_token_time_ms'] / 1000:.1f}s")
            if r["total_time_ms"] is not None:
                timing.append(f"總 {r['total_time_ms'] / 1000:.1f}s")
            if (r["retry_count"] or 0) > 0:
                timing.append(f"重試 {r['retry_count']} 次")
            if timing:
                details.append("耗時: " + " | ".join(timing))
            if r["status"] == "error" and r["error_message"]:
                details.append("錯誤: " + _escape_html(_extract_error_summary(r["error_message"])[:120]))
            for line in details:
                text += f"  {line}\n"

    period_buttons = [
        {"text": "今天", "callback_data": "stats:0"},
        {"text": "3天", "callback_data": "stats:3"},
        {"text": "7天", "callback_data": "stats:7"},
        {"text": "本月", "callback_data": "stats:month"},
    ]
    if len(text) > 3900:
        text = text[:3900] + "\n\n... (已截斷)"
    _edit(chat_id, msg_id, text, _inline_kb([
        period_buttons,
        [{"text": "🔄 刷新", "callback_data": f"stats:{period}"}],
        [{"text": "◀ 返回", "callback_data": "back_menu"}],
    ]))


# ─── Recent logs ───

def _handle_logs(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    rows = db.recent_logs(10)
    if not rows:
        _edit(chat_id, msg_id, "暫無日誌。", _inline_kb([[{"text": "◀ 返回", "callback_data": "back_menu"}]]))
        return

    lines = ["<b>📋 最近 10 條日誌</b>"]
    for r in rows:
        ts = datetime.fromtimestamp(r["created_at"], tz=_BJT).strftime("%m-%d %H:%M")
        status_icon = {"success": "✅", "error": "❌", "pending": "⏳"}.get(r["status"], "?")
        line = "\n<code>%s</code> %s %s" % (ts, status_icon, r["model"] or "?")
        detail_parts = []
        if r["status"] == "success":
            inp = (r["input_tokens"] or 0) + (r["cache_creation_tokens"] or 0) + (r["cache_read_tokens"] or 0)
            cr = r["cache_read_tokens"] or 0
            tok_str = "↑%s ↓%s" % (_fmt_tokens(inp), _fmt_tokens(r["output_tokens"] or 0))
            if cr > 0:
                tok_str += " 緩存%s" % _fmt_tokens(cr)
            detail_parts.append(tok_str)
        if r["connect_time_ms"] is not None:
            detail_parts.append("連接%.1fs" % (r["connect_time_ms"] / 1000))
        if r["is_stream"] and r["first_token_time_ms"] is not None:
            detail_parts.append("首字%.1fs" % (r["first_token_time_ms"] / 1000))
        if r["total_time_ms"] is not None:
            detail_parts.append("總%.1fs" % (r["total_time_ms"] / 1000))
        if (r["retry_count"] or 0) > 0:
            detail_parts.append("重試%d次" % (r["retry_count"] or 0))
        if detail_parts:
            line += "\n  %s" % " | ".join(detail_parts)
        if r["status"] == "error" and r["error_message"]:
            summary = _extract_error_summary(r["error_message"])
            line += "\n  %s" % _escape_html(summary)
        lines.append(line)

    # 安全拼接，不超過 Telegram 限制，避免截斷 HTML 標籤
    text = ""
    for line in lines:
        candidate = text + line
        if len(candidate) > 3900:
            break
        text = candidate
    if text != "".join(lines):
        text += "\n\n... (已截斷)"

    _edit(chat_id, msg_id, text, _inline_kb([
        [{"text": "🔄 刷新", "callback_data": "menu_logs"}],
        [{"text": "◀ 返回", "callback_data": "back_menu"}],
    ]))


# ─── Utils ───

def _utc_to_bjt(utc_str):
    """將 UTC 時間字符串轉爲北京時間顯示"""
    if not utc_str:
        return "?"
    try:
        return datetime.fromisoformat(utc_str.replace("Z", "+00:00")).astimezone(_BJT).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return utc_str

def _escape_html(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _fmt_tokens(n):
    """格式化 token 數量爲可讀形式"""
    n = n or 0
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _extract_error_summary(raw):
    """從錯誤消息中提取可讀摘要"""
    if not raw:
        return "未知錯誤"
    # 格式: "HTTP 500: {json}" 或 "stream ...: ..." 或純文本
    prefix = ""
    json_part = raw
    if raw.startswith("HTTP "):
        # 提取 HTTP 狀態碼
        colon_idx = raw.find(": ")
        if colon_idx > 0:
            prefix = raw[:colon_idx]
            json_part = raw[colon_idx + 2:]
        else:
            return raw[:200]
    try:
        obj = json.loads(json_part)
        err = obj.get("error", {})
        if isinstance(err, dict):
            err_type = err.get("type", "")
            err_msg = err.get("message", "")
            if err_msg:
                summary = f"{err_type}: {err_msg}" if err_type else err_msg
                return f"{prefix} — {summary}" if prefix else summary
        return f"{prefix} — {json_part[:150]}" if prefix else json_part[:200]
    except (json.JSONDecodeError, TypeError):
        return raw[:200]


def _is_admin(chat_id):
    return not _admin_ids or chat_id in _admin_ids


# ─── Polling ───

def _cleanup_stale_states():
    """清理超過 TTL 的 user states"""
    now = time.time()
    expired = [cid for cid, s in _user_states.items()
               if now - s.get("ts", 0) > _USER_STATE_TTL]
    for cid in expired:
        _user_states.pop(cid, None)


def _rebuild_tg_session():
    """重建 httpx 持久連接，用於連續失敗後恢復"""
    global _tg_session
    try:
        if _tg_session:
            _tg_session.close()
    except Exception:
        pass
    _tg_session = httpx.Client(
        timeout=httpx.Timeout(connect=10.0, read=50.0, write=10.0, pool=10.0),
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=2, keepalive_expiry=30),
        http2=False,
    )
    print("[TG Bot] Session rebuilt")


def _poll_loop():
    global _offset
    fail_count = 0
    cleanup_counter = 0
    while True:
        try:
            result = _api("getUpdates", {"offset": _offset, "timeout": 30})
            if not result or not result.get("ok"):
                fail_count += 1
                if fail_count >= 10 and fail_count % 10 == 0:
                    print(f"[TG Bot] {fail_count} consecutive failures, rebuilding session")
                    _rebuild_tg_session()
                time.sleep(min(5 * fail_count, 60))
                continue
            fail_count = 0
            for update in result.get("result", []):
                _offset = update["update_id"] + 1
                try:
                    _handle_update(update)
                except Exception:
                    traceback.print_exc()
            # 每 50 次 poll 清理一次過期 states
            cleanup_counter += 1
            if cleanup_counter >= 50:
                cleanup_counter = 0
                _cleanup_stale_states()
        except Exception:
            fail_count += 1
            if fail_count >= 10 and fail_count % 10 == 0:
                print(f"[TG Bot] {fail_count} consecutive failures (exception), rebuilding session")
                _rebuild_tg_session()
            time.sleep(min(5 * fail_count, 60))


def _handle_update(update):
    # Callback query (button press)
    cb = update.get("callback_query")
    if cb:
        chat_id = cb["message"]["chat"]["id"]
        msg_id = cb["message"]["message_id"]
        cb_id = cb["id"]
        data = cb.get("data", "")
        if not _is_admin(chat_id):
            _answer_cb(cb_id, "無權限")
            return
        if data == "back_menu":
            _answer_cb(cb_id)
            _edit(chat_id, msg_id, "<b>CC Proxy 管理面板</b>", _inline_kb([
                [{"text": "🔐 管理 OAuth", "callback_data": "menu_oauth"}],
                [{"text": "🔑 管理 API Key", "callback_data": "menu_apikey"}],
                [{"text": "📊 統計彙總", "callback_data": "menu_stats"}],
                [{"text": "📋 最近日誌", "callback_data": "menu_logs"}],
            ]))
        elif data == "menu_apikey": _handle_apikey_menu(chat_id, msg_id, cb_id)
        elif data == "ak_add": _handle_ak_add(chat_id, msg_id, cb_id)
        elif data == "ak_del": _handle_ak_del(chat_id, msg_id, cb_id)
        elif data.startswith("ak_del_confirm:"): _handle_ak_del_confirm(chat_id, msg_id, cb_id, data.split(":", 1)[1])
        elif data.startswith("ak_del_exec:"): _handle_ak_del_exec(chat_id, msg_id, cb_id, data.split(":", 1)[1])
        elif data == "menu_oauth": _handle_oauth_menu(chat_id, msg_id, cb_id)
        elif data == "oa_login": _handle_oa_login(chat_id, msg_id, cb_id)
        elif data == "oa_set": _handle_oa_set(chat_id, msg_id, cb_id)
        elif data == "oa_refresh": _handle_oa_refresh(chat_id, msg_id, cb_id)
        elif data == "oa_force_refresh": _handle_oa_force_refresh(chat_id, msg_id, cb_id)
        elif data == "menu_stats": _handle_stats_menu(chat_id, msg_id, cb_id)
        elif data.startswith("stats:"): _handle_stats(chat_id, msg_id, cb_id, data.split(":", 1)[1])
        elif data == "menu_logs": _handle_logs(chat_id, msg_id, cb_id)
        return

    # Text message
    msg = update.get("message")
    if not msg:
        return
    chat_id = msg["chat"]["id"]
    text = msg.get("text", "")

    if not _is_admin(chat_id):
        _send(chat_id, "⛔ 無權限。你的 Chat ID: <code>" + str(chat_id) + "</code>")
        return

    # 處理等待輸入的狀態
    state = _user_states.get(chat_id)
    if state:
        action = state.get("action")
        if action == "ak_add_name":
            _handle_ak_add_name(chat_id, text)
            return
        elif action == "oa_set_json":
            _handle_oa_set_json(chat_id, text)
            return
        elif action == "oa_login_code":
            _handle_oa_login_code(chat_id, text)
            return

    # 命令
    if text.startswith("/start"):
        cfg = _load_config()
        host = cfg.get("listen_host", "0.0.0.0")
        port = cfg.get("listen_port", 18081)
        _send(chat_id,
              "<b>👋 歡迎使用 CC Proxy 管理 Bot</b>\n\n"
              "<b>快速開始：</b>\n"
              "1️⃣ 點擊「🔐 管理 OAuth」→「🔑 登錄獲取 Token」，在瀏覽器登錄 Anthropic 賬號獲取 OAuth Token\n"
              "2️⃣ 點擊「🔑 管理 API Key」→「➕ 添加」，創建一個代理 API Key\n"
              "3️⃣ 使用該 Key 通過代理訪問 Claude API\n\n"
              "<b>服務地址：</b>\n"
              f"<code>http://服務器IP:{port}/v1/messages</code>\n\n"
              "<b>請求示例：</b>\n"
              f"<code>curl http://服務器IP:{port}/v1/messages \\\n"
              "  -H 'x-api-key: ccp-你的Key' \\\n"
              "  -H 'Content-Type: application/json' \\\n"
              "  -d '{...}'</code>")
        _show_menu(chat_id)
        return
    if text.startswith("/menu"):
        _show_menu(chat_id)
    elif text.startswith("/keys"):
        _send(chat_id, "<b>API Key 管理</b>", _inline_kb([
            [{"text": "➕ 添加", "callback_data": "ak_add"}, {"text": "🗑 刪除", "callback_data": "ak_del"}],
            [{"text": "◀ 返回主菜單", "callback_data": "back_menu"}],
        ]))
    elif text.startswith("/oauth"):
        _send(chat_id, "<b>OAuth 管理</b>", _inline_kb([
            [{"text": "🔑 登錄獲取 Token", "callback_data": "oa_login"}],
            [{"text": "📝 設置 OAuth", "callback_data": "oa_set"}],
            [{"text": "🔄 刷新 Token", "callback_data": "oa_refresh"}],
            [{"text": "◀ 返回主菜單", "callback_data": "back_menu"}],
        ]))
    elif text.startswith("/stats"):
        _send(chat_id, "<b>統計彙總</b>\n選擇時間範圍：", _inline_kb([
            [{"text": "今天", "callback_data": "stats:0"},
             {"text": "3天", "callback_data": "stats:3"},
             {"text": "7天", "callback_data": "stats:7"}],
            [{"text": "本月", "callback_data": "stats:month"}],
            [{"text": "◀ 返回主菜單", "callback_data": "back_menu"}],
        ]))
    elif text.startswith("/logs"):
        rows = db.recent_logs(20)
        if not rows:
            _send(chat_id, "暫無日誌。")
            return
        txt = "<b>📋 最近 20 條日誌</b>\n"
        for r in rows:
            ts = datetime.fromtimestamp(r["created_at"], tz=_BJT).strftime("%m-%d %H:%M:%S")
            icon = {"success": "✅", "error": "❌", "pending": "⏳"}.get(r["status"], "?")
            line = f"\n<code>{ts}</code> {icon} <b>{r['api_key_name'] or '?'}</b> {r['model'] or '?'}"
            if r["connect_time_ms"] is not None:
                line += f"\n  連接:{r['connect_time_ms']}ms"
            if r["is_stream"] and r["first_token_time_ms"] is not None:
                line += f" 首字:{r['first_token_time_ms']}ms"
            if r["total_time_ms"] is not None:
                line += f" 總:{r['total_time_ms']}ms"
            if (r["retry_count"] or 0) > 0:
                line += f" 重試:{r['retry_count']}次"
            if r["status"] == "error" and r["error_message"]:
                line += f"\n  <pre>{_escape_html(r['error_message'][:200])}</pre>"
            txt += line
        if len(txt) > 4000:
            txt = txt[:4000] + "\n... (截斷)"
        _send(chat_id, txt)
