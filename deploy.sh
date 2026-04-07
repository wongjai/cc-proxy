#!/bin/bash
# CC Proxy 一键部署脚本
# 用法: 先把整个 cc-proxy 目录上传到服务器，然后执行此脚本
# scp -P 27920 -r cc-proxy/ root@18.140.198.13:/opt/
# ssh -p 27920 root@18.140.198.13 'bash /opt/cc-proxy/deploy.sh'

set -e

INSTALL_DIR="/opt/cc-proxy"
SERVICE_NAME="cc-proxy"

echo "=== CC Proxy 部署 ==="

# 1. 安装依赖
echo "[1/5] 安装系统依赖..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv > /dev/null 2>&1

# 2. 创建虚拟环境
echo "[2/5] 创建 Python 虚拟环境..."
cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install -q fastapi uvicorn httpx xxhash

# 3. 写入配置（如果不存在）
echo "[3/5] 检查配置..."
if [ ! -f "$INSTALL_DIR/config.json" ]; then
    cat > "$INSTALL_DIR/config.json" << 'CONF'
{
  "listen_host": "0.0.0.0",
  "listen_port": 18081,
  "api_keys": {},
  "oauth_file": "oauth.json",
  "telegram_bot_token": "",
  "telegram_admin_ids": [],
  "db_path": "cc-proxy.db",
  "log_dir": "logs"
}
CONF
    echo "  已创建默认 config.json，请手动编辑填入 oauth 和 telegram 配置"
fi

if [ ! -f "$INSTALL_DIR/oauth.json" ]; then
    cat > "$INSTALL_DIR/oauth.json" << 'OAUTH'
{
  "access_token": "",
  "refresh_token": "",
  "expired": "",
  "email": "",
  "type": "claude"
}
OAUTH
    echo "  已创建空 oauth.json，请填入有效的 OAuth token"
fi

# 4. 创建 systemd 服务
echo "[4/5] 配置 systemd 服务..."
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=CC Proxy - Claude Code API Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 -u ${INSTALL_DIR}/server.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}

# 5. 启动
echo "[5/5] 启动服务..."
systemctl restart ${SERVICE_NAME}
sleep 2

if systemctl is-active --quiet ${SERVICE_NAME}; then
    echo ""
    echo "=== 部署完成 ==="
    echo "  状态: $(systemctl is-active ${SERVICE_NAME})"
    echo "  端口: $(grep listen_port ${INSTALL_DIR}/config.json | grep -o '[0-9]*')"
    echo "  日志: journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo "下一步:"
    echo "  1. 编辑 ${INSTALL_DIR}/oauth.json 填入 OAuth token"
    echo "  2. 编辑 ${INSTALL_DIR}/config.json 填入 telegram_bot_token 和 admin_ids"
    echo "  3. systemctl restart ${SERVICE_NAME}"
else
    echo "启动失败！查看日志:"
    journalctl -u ${SERVICE_NAME} -n 30 --no-pager
fi
