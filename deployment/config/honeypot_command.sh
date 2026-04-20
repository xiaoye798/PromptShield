#!/bin/bash
# PromptShield Honeypot — ForceCommand 脚本

# 导入容器环境变量（entrypoint.sh 写入 /app/.env）
if [ -f /app/.env ]; then
    set -a
    . /app/.env
    set +a
fi

# 获取攻击者 IP
ATTACKER_IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
ATTACKER_IP=${ATTACKER_IP:-unknown}

# 生成会话 ID
SESSION_ID=$(openssl rand -hex 8 2>/dev/null || echo "$(date +%Y%m%d_%H%M%S)_$$")

# 记录连接日志
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] New connection from ${ATTACKER_IP} (session: ${SESSION_ID})" \
    >> /app/logs/connections.log || true

# 切换到应用目录
cd /app || exit 1

# 启动蜜罐主程序
exec python3 LinuxSSHbot_mcp.py \
    2>> "/app/logs/errors_${SESSION_ID}.log"
