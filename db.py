"""SQLite 日志模块 — 两张表：request_log（轻量）+ request_detail（完整 body/响应）"""

import sqlite3
import threading
import json
import time
import os

_local = threading.local()
_db_path = None


def init(path):
    global _db_path
    _db_path = path
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            created_at REAL NOT NULL,
            finished_at REAL,
            client_ip TEXT,
            api_key_name TEXT,
            model TEXT,
            status TEXT DEFAULT 'pending',
            is_stream INTEGER DEFAULT 1,
            msg_count INTEGER DEFAULT 0,
            tool_count INTEGER DEFAULT 0,
            error_message TEXT,
            input_tokens INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            cache_creation_tokens INTEGER DEFAULT 0,
            cache_read_tokens INTEGER DEFAULT 0,
            connect_time_ms INTEGER,
            first_token_time_ms INTEGER,
            total_time_ms INTEGER
        );

        CREATE TABLE IF NOT EXISTS request_detail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            request_headers TEXT,
            request_body TEXT,
            response_body TEXT,
            FOREIGN KEY (request_id) REFERENCES request_log(request_id)
        );

        CREATE INDEX IF NOT EXISTS idx_log_created ON request_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_log_status ON request_log(status);
        CREATE INDEX IF NOT EXISTS idx_log_apikey ON request_log(api_key_name);
    """)
    conn.commit()


def _get_conn():
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(_db_path, timeout=10)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA busy_timeout=5000")
    return _local.conn


def insert_pending(request_id, client_ip, api_key_name, model, is_stream,
                   msg_count, tool_count, request_headers, request_body):
    """请求发起时立即记录（状态 pending）"""
    conn = _get_conn()
    now = time.time()
    conn.execute(
        """INSERT INTO request_log
           (request_id, created_at, client_ip, api_key_name, model, status,
            is_stream, msg_count, tool_count)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (request_id, now, client_ip, api_key_name, model, "pending",
         1 if is_stream else 0, msg_count, tool_count),
    )
    conn.execute(
        """INSERT INTO request_detail (request_id, request_headers, request_body)
           VALUES (?,?,?)""",
        (request_id,
         json.dumps(request_headers, ensure_ascii=False) if request_headers else None,
         json.dumps(request_body, ensure_ascii=False) if request_body else None),
    )
    conn.commit()


def finish_success(request_id, input_tokens, output_tokens, cache_creation,
                   cache_read, connect_ms, first_token_ms, total_ms, response_body):
    """请求成功完成"""
    conn = _get_conn()
    now = time.time()
    conn.execute(
        """UPDATE request_log SET
           status='success', finished_at=?, input_tokens=?, output_tokens=?,
           cache_creation_tokens=?, cache_read_tokens=?,
           connect_time_ms=?, first_token_time_ms=?, total_time_ms=?
           WHERE request_id=?""",
        (now, input_tokens, output_tokens, cache_creation, cache_read,
         connect_ms, first_token_ms, total_ms, request_id),
    )
    conn.execute(
        "UPDATE request_detail SET response_body=? WHERE request_id=?",
        (response_body, request_id),
    )
    conn.commit()


def finish_error(request_id, error_message, connect_ms, total_ms, response_body=None):
    """请求失败"""
    conn = _get_conn()
    now = time.time()
    conn.execute(
        """UPDATE request_log SET
           status='error', finished_at=?, error_message=?,
           connect_time_ms=?, total_time_ms=?
           WHERE request_id=?""",
        (now, error_message[:4000] if error_message else None, connect_ms, total_ms, request_id),
    )
    if response_body:
        conn.execute(
            "UPDATE request_detail SET response_body=? WHERE request_id=?",
            (response_body, request_id),
        )
    conn.commit()


# ─── 查询 ───

def recent_logs(limit=20):
    conn = _get_conn()
    return conn.execute(
        """SELECT request_id, created_at, client_ip, api_key_name, model, status,
                  is_stream, error_message, input_tokens, output_tokens,
                  cache_creation_tokens, cache_read_tokens,
                  connect_time_ms, first_token_time_ms, total_time_ms
           FROM request_log ORDER BY created_at DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def stats_summary(since_ts):
    """统计汇总"""
    conn = _get_conn()
    row = conn.execute(
        """SELECT
             COUNT(*) as total,
             SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) as success_count,
             SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as error_count,
             SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending_count,
             AVG(CASE WHEN status='success' THEN connect_time_ms END) as avg_connect_ms,
             AVG(CASE WHEN status='success' AND is_stream=1 THEN first_token_time_ms END) as avg_first_token_ms,
             AVG(CASE WHEN status='success' THEN total_time_ms END) as avg_total_ms,
             SUM(input_tokens) as total_input_tokens,
             SUM(output_tokens) as total_output_tokens,
             SUM(cache_creation_tokens) as total_cache_creation,
             SUM(cache_read_tokens) as total_cache_read
           FROM request_log WHERE created_at >= ?""",
        (since_ts,),
    ).fetchone()

    recent_errors = conn.execute(
        """SELECT created_at, api_key_name, model, error_message
           FROM request_log WHERE status='error' AND created_at >= ?
           ORDER BY created_at DESC LIMIT 5""",
        (since_ts,),
    ).fetchall()

    return row, recent_errors
