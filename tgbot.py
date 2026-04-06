"""Telegram Bot 模块 — 管理 API Key、OAuth、查看统计和日志"""

import json
import os
import time
import secrets
import threading
import traceback
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

import db

_bot_token = None
_admin_ids = set()
_config_path = None
_get_access_token = None  # 由 server.py 注入
_refresh_fn = None         # 由 server.py 注入
_load_oauth = None
_save_oauth = None
_offset = 0
_user_states = {}          # chat_id -> {"action": ..., "data": ...}


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
    # 注册 Bot 命令菜单
    _api("setMyCommands", {
        "commands": [
            {"command": "start", "description": "打开管理面板"},
            {"command": "menu", "description": "打开管理面板"},
            {"command": "keys", "description": "管理 API Key"},
            {"command": "oauth", "description": "管理 OAuth Token"},
            {"command": "stats", "description": "统计汇总"},
            {"command": "logs", "description": "最近调用日志"},
        ]
    })
    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    print(f"[TG Bot] Started polling, commands registered")


# ─── Telegram API ───

def _api(method, data=None):
    url = f"https://api.telegram.org/bot{_bot_token}/{method}"
    body = json.dumps(data).encode() if data else None
    req = Request(url, data=body, headers={"Content-Type": "application/json"} if body else {})
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except URLError as e:
        print(f"[TG Bot] API error: {e}")
        return None


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
    with open(_config_path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


# ─── Main menu ───

def _show_menu(chat_id):
    _send(chat_id, "<b>CC Proxy 管理面板</b>", _inline_kb([
        [{"text": "🔑 管理 API Key", "callback_data": "menu_apikey"}],
        [{"text": "🔐 管理 OAuth", "callback_data": "menu_oauth"}],
        [{"text": "📊 统计汇总", "callback_data": "menu_stats"}],
        [{"text": "📋 最近日志", "callback_data": "menu_logs"}],
    ]))


# ─── API Key management ───

def _handle_apikey_menu(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    cfg = _load_config()
    keys = cfg.get("api_keys", {})
    text = f"<b>API Key 管理</b>\n当前: {len(keys)} 个\n"
    for name in keys:
        text += f"  • <code>{name}</code>\n"
    _edit(chat_id, msg_id, text, _inline_kb([
        [{"text": "➕ 添加", "callback_data": "ak_add"}, {"text": "🗑 删除", "callback_data": "ak_del"}],
        [{"text": "◀ 返回", "callback_data": "back_menu"}],
    ]))


def _handle_ak_add(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    _user_states[chat_id] = {"action": "ak_add_name"}
    _edit(chat_id, msg_id, "请输入新 API Key 的名称（如: my-app）：")


def _handle_ak_add_name(chat_id, text):
    name = text.strip()
    if not name or " " in name:
        _send(chat_id, "名称无效，不能含空格，请重新输入：")
        return
    cfg = _load_config()
    if name in cfg.get("api_keys", {}):
        _send(chat_id, f"名称 <code>{name}</code> 已存在，请换一个：")
        return
    apikey = f"ccp-{secrets.token_hex(24)}"
    cfg.setdefault("api_keys", {})[name] = apikey
    _save_config(cfg)
    _user_states.pop(chat_id, None)
    _send(chat_id, f"✅ API Key 已创建\n\n名称: <code>{name}</code>\nKey: <code>{apikey}</code>\n\n请妥善保存，不会再次显示。")
    _show_menu(chat_id)


def _handle_ak_del(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    cfg = _load_config()
    keys = list(cfg.get("api_keys", {}).keys())
    if not keys:
        _edit(chat_id, msg_id, "没有任何 API Key。", _inline_kb([[{"text": "◀ 返回", "callback_data": "back_menu"}]]))
        return
    buttons = [[{"text": f"🗑 {name}", "callback_data": f"ak_del_confirm:{name}"}] for name in keys]
    buttons.append([{"text": "◀ 返回", "callback_data": "menu_apikey"}])
    _edit(chat_id, msg_id, "选择要删除的 Key：", _inline_kb(buttons))


def _handle_ak_del_confirm(chat_id, msg_id, cb_id, name):
    _answer_cb(cb_id)
    _edit(chat_id, msg_id, f"确认删除 <code>{name}</code>？", _inline_kb([
        [{"text": "✅ 确认删除", "callback_data": f"ak_del_exec:{name}"},
         {"text": "❌ 取消", "callback_data": "menu_apikey"}],
    ]))


def _handle_ak_del_exec(chat_id, msg_id, cb_id, name):
    _answer_cb(cb_id, "已删除")
    cfg = _load_config()
    cfg.get("api_keys", {}).pop(name, None)
    _save_config(cfg)
    _edit(chat_id, msg_id, f"✅ 已删除 <code>{name}</code>")
    _show_menu(chat_id)


# ─── OAuth management ───

def _handle_oauth_menu(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    try:
        oauth = _load_oauth()
        email = oauth.get("email", "?")
        expired = oauth.get("expired", "?")
        text = f"<b>OAuth 管理</b>\nEmail: <code>{email}</code>\n过期: <code>{expired}</code>"
    except Exception:
        text = "<b>OAuth 管理</b>\n⚠️ 未配置 OAuth"
    _edit(chat_id, msg_id, text, _inline_kb([
        [{"text": "📝 设置 OAuth", "callback_data": "oa_set"}],
        [{"text": "🔄 刷新 Token", "callback_data": "oa_refresh"}],
        [{"text": "◀ 返回", "callback_data": "back_menu"}],
    ]))


def _handle_oa_set(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    _user_states[chat_id] = {"action": "oa_set_json"}
    _edit(chat_id, msg_id, "请输入 OAuth JSON（含 access_token, refresh_token, expired, email）：")


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
        _send(chat_id, "❌ JSON 格式错误")
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
                      f"Token 仍有效，剩余 {int(remaining//60)} 分钟\n过期: <code>{expired_str}</code>",
                      _inline_kb([
                          [{"text": "🔄 强制刷新", "callback_data": "oa_force_refresh"}],
                          [{"text": "◀ 返回", "callback_data": "menu_oauth"}],
                      ]))
                return
        token = _refresh_fn(oauth)
        _edit(chat_id, msg_id, f"✅ Token 已刷新\n新过期: <code>{oauth.get('expired', '?')}</code>")
    except Exception as e:
        _edit(chat_id, msg_id, f"❌ 刷新失败: {e}")
    _show_menu(chat_id)


def _handle_oa_force_refresh(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    try:
        oauth = _load_oauth()
        _refresh_fn(oauth)
        _edit(chat_id, msg_id, f"✅ 强制刷新成功\n新过期: <code>{oauth.get('expired', '?')}</code>")
    except Exception as e:
        _edit(chat_id, msg_id, f"❌ 刷新失败: {e}")
    _show_menu(chat_id)


# ─── Stats ───

def _handle_stats_menu(chat_id, msg_id, cb_id):
    _handle_stats(chat_id, msg_id, cb_id, "0")


def _handle_stats(chat_id, msg_id, cb_id, period):
    _answer_cb(cb_id)
    now = time.time()
    if period == "all":
        since = 0
        label = "所有时间"
    elif period == "0":
        # 今天 00:00 UTC
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        since = today.timestamp()
        label = "今天"
    else:
        since = now - int(period) * 86400
        label = f"最近 {period} 天"

    row, errors = db.stats_summary(since)
    total = row["total"] or 0
    text = f"<b>📊 统计 — {label}</b>\n\n"
    text += f"请求总数: {total}\n"
    text += f"  ✅ 成功: {row['success_count'] or 0}\n"
    text += f"  ❌ 失败: {row['error_count'] or 0}\n"
    text += f"  ⏳ 进行中: {row['pending_count'] or 0}\n\n"
    if row["avg_connect_ms"] is not None:
        text += f"平均连接耗时: {row['avg_connect_ms']:.0f}ms\n"
    if row["avg_first_token_ms"] is not None:
        text += f"平均首字耗时: {row['avg_first_token_ms']:.0f}ms\n"
    if row["avg_total_ms"] is not None:
        text += f"平均总耗时: {row['avg_total_ms']:.0f}ms\n"
    text += f"\nTokens:\n"
    text += f"  输入: {row['total_input_tokens'] or 0}\n"
    text += f"  输出: {row['total_output_tokens'] or 0}\n"
    text += f"  缓存写入: {row['total_cache_creation'] or 0}\n"
    text += f"  缓存读取: {row['total_cache_read'] or 0}\n"

    if errors:
        text += f"\n<b>最近失败 ({len(errors)} 条):</b>\n"
        for e in errors:
            ts = datetime.fromtimestamp(e["created_at"], tz=timezone.utc).strftime("%m-%d %H:%M")
            text += f"\n<code>[{ts}]</code> {e['api_key_name'] or '?'} / {e['model'] or '?'}\n"
            err = (e["error_message"] or "")[:300]
            text += f"<pre>{_escape_html(err)}</pre>\n"

    period_buttons = [
        {"text": "今天", "callback_data": "stats:0"},
        {"text": "3天", "callback_data": "stats:3"},
        {"text": "7天", "callback_data": "stats:7"},
        {"text": "30天", "callback_data": "stats:30"},
        {"text": "所有", "callback_data": "stats:all"},
    ]
    _edit(chat_id, msg_id, text, _inline_kb([
        period_buttons,
        [{"text": "🔄 刷新", "callback_data": f"stats:{period}"}],
        [{"text": "◀ 返回", "callback_data": "back_menu"}],
    ]))


# ─── Recent logs ───

def _handle_logs(chat_id, msg_id, cb_id):
    _answer_cb(cb_id)
    rows = db.recent_logs(20)
    if not rows:
        _edit(chat_id, msg_id, "暂无日志。", _inline_kb([[{"text": "◀ 返回", "callback_data": "back_menu"}]]))
        return

    text = "<b>📋 最近 20 条日志</b>\n"
    for r in rows:
        ts = datetime.fromtimestamp(r["created_at"], tz=timezone.utc).strftime("%m-%d %H:%M:%S")
        status_icon = {"success": "✅", "error": "❌", "pending": "⏳"}.get(r["status"], "?")
        line = f"\n<code>{ts}</code> {status_icon} <b>{r['api_key_name'] or '?'}</b> {r['model'] or '?'}"
        if r["connect_time_ms"] is not None:
            line += f"\n  连接:{r['connect_time_ms']}ms"
        if r["is_stream"] and r["first_token_time_ms"] is not None:
            line += f" 首字:{r['first_token_time_ms']}ms"
        if r["total_time_ms"] is not None:
            line += f" 总:{r['total_time_ms']}ms"
        if r["status"] == "error" and r["error_message"]:
            err = r["error_message"][:200]
            line += f"\n  <pre>{_escape_html(err)}</pre>"
        text += line
    # Telegram 消息限制 4096 字符
    if len(text) > 4000:
        text = text[:4000] + "\n... (截断)"

    _edit(chat_id, msg_id, text, _inline_kb([
        [{"text": "🔄 刷新", "callback_data": "menu_logs"}],
        [{"text": "◀ 返回", "callback_data": "back_menu"}],
    ]))


# ─── Utils ───

def _escape_html(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _is_admin(chat_id):
    return not _admin_ids or chat_id in _admin_ids


# ─── Polling ───

def _poll_loop():
    global _offset
    while True:
        try:
            result = _api("getUpdates", {"offset": _offset, "timeout": 30})
            if not result or not result.get("ok"):
                time.sleep(5)
                continue
            for update in result.get("result", []):
                _offset = update["update_id"] + 1
                try:
                    _handle_update(update)
                except Exception:
                    traceback.print_exc()
        except Exception:
            time.sleep(5)


def _handle_update(update):
    # Callback query (button press)
    cb = update.get("callback_query")
    if cb:
        chat_id = cb["message"]["chat"]["id"]
        msg_id = cb["message"]["message_id"]
        cb_id = cb["id"]
        data = cb.get("data", "")
        if not _is_admin(chat_id):
            _answer_cb(cb_id, "无权限")
            return
        if data == "back_menu":
            _answer_cb(cb_id)
            _edit(chat_id, msg_id, "<b>CC Proxy 管理面板</b>", _inline_kb([
                [{"text": "🔑 管理 API Key", "callback_data": "menu_apikey"}],
                [{"text": "🔐 管理 OAuth", "callback_data": "menu_oauth"}],
                [{"text": "📊 统计汇总", "callback_data": "menu_stats"}],
                [{"text": "📋 最近日志", "callback_data": "menu_logs"}],
            ]))
        elif data == "menu_apikey": _handle_apikey_menu(chat_id, msg_id, cb_id)
        elif data == "ak_add": _handle_ak_add(chat_id, msg_id, cb_id)
        elif data == "ak_del": _handle_ak_del(chat_id, msg_id, cb_id)
        elif data.startswith("ak_del_confirm:"): _handle_ak_del_confirm(chat_id, msg_id, cb_id, data.split(":", 1)[1])
        elif data.startswith("ak_del_exec:"): _handle_ak_del_exec(chat_id, msg_id, cb_id, data.split(":", 1)[1])
        elif data == "menu_oauth": _handle_oauth_menu(chat_id, msg_id, cb_id)
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
        _send(chat_id, "⛔ 无权限。你的 Chat ID: <code>" + str(chat_id) + "</code>")
        return

    # 处理等待输入的状态
    state = _user_states.get(chat_id)
    if state:
        action = state.get("action")
        if action == "ak_add_name":
            _handle_ak_add_name(chat_id, text)
            return
        elif action == "oa_set_json":
            _handle_oa_set_json(chat_id, text)
            return

    # 命令
    if text.startswith("/start") or text.startswith("/menu"):
        _show_menu(chat_id)
    elif text.startswith("/keys"):
        _send(chat_id, "<b>API Key 管理</b>", _inline_kb([
            [{"text": "➕ 添加", "callback_data": "ak_add"}, {"text": "🗑 删除", "callback_data": "ak_del"}],
            [{"text": "◀ 返回主菜单", "callback_data": "back_menu"}],
        ]))
    elif text.startswith("/oauth"):
        _send(chat_id, "<b>OAuth 管理</b>", _inline_kb([
            [{"text": "📝 设置 OAuth", "callback_data": "oa_set"}],
            [{"text": "🔄 刷新 Token", "callback_data": "oa_refresh"}],
            [{"text": "◀ 返回主菜单", "callback_data": "back_menu"}],
        ]))
    elif text.startswith("/stats"):
        _send(chat_id, "<b>统计汇总</b>\n选择时间范围：", _inline_kb([
            [{"text": "今天", "callback_data": "stats:0"},
             {"text": "3天", "callback_data": "stats:3"},
             {"text": "7天", "callback_data": "stats:7"}],
            [{"text": "30天", "callback_data": "stats:30"},
             {"text": "所有", "callback_data": "stats:all"}],
            [{"text": "◀ 返回主菜单", "callback_data": "back_menu"}],
        ]))
    elif text.startswith("/logs"):
        rows = db.recent_logs(20)
        if not rows:
            _send(chat_id, "暂无日志。")
            return
        txt = "<b>📋 最近 20 条日志</b>\n"
        for r in rows:
            ts = datetime.fromtimestamp(r["created_at"], tz=timezone.utc).strftime("%m-%d %H:%M:%S")
            icon = {"success": "✅", "error": "❌", "pending": "⏳"}.get(r["status"], "?")
            line = f"\n<code>{ts}</code> {icon} <b>{r['api_key_name'] or '?'}</b> {r['model'] or '?'}"
            if r["connect_time_ms"] is not None:
                line += f"\n  连接:{r['connect_time_ms']}ms"
            if r["is_stream"] and r["first_token_time_ms"] is not None:
                line += f" 首字:{r['first_token_time_ms']}ms"
            if r["total_time_ms"] is not None:
                line += f" 总:{r['total_time_ms']}ms"
            if r["status"] == "error" and r["error_message"]:
                line += f"\n  <pre>{_escape_html(r['error_message'][:200])}</pre>"
            txt += line
        if len(txt) > 4000:
            txt = txt[:4000] + "\n... (截断)"
        _send(chat_id, txt)
