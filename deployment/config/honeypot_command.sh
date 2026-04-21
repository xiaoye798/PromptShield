#!/bin/bash
# PromptShield Honeypot — ForceCommand script

# Import container environment variables (written by entrypoint.sh to /app/.env)
if [ -f /app/.env ]; then
    set -a
    . /app/.env
    set +a
fi

# Get attacker IP
ATTACKER_IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
ATTACKER_IP=${ATTACKER_IP:-unknown}

# Generate session ID
SESSION_ID=$(openssl rand -hex 8 2>/dev/null || echo "$(date +%Y%m%d_%H%M%S)_$$")

# Log connection
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] New connection from ${ATTACKER_IP} (session: ${SESSION_ID})" \
    >> /app/logs/connections.log || true

# Switch to application directory
cd /app || exit 1

# Start honeypot main program
exec python3 LinuxSSHbot_mcp.py \
    2>> "/app/logs/errors_${SESSION_ID}.log"
