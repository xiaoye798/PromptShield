#!/bin/bash
# PromptShield Honeypot - 宿主机直接部署脚本（非 Docker）
# 适用于：Ubuntu 20.04/22.04 LTS
# 用法：sudo bash setup.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[setup]${NC} $1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; }
err()  { echo -e "${RED}[error]${NC} $1"; exit 1; }

# 必须以 root 运行
[ "${EUID}" -eq 0 ] || err "Please run as root: sudo bash setup.sh"

APP_DIR="/opt/promptshield"
APP_USER="promptshield"
SSH_PORT=2222
REPO_URL="https://anonymous.4open.science/r/PromptShield-DDA4"

log "=== PromptShield Honeypot Setup ==="
log "Install dir: ${APP_DIR}"
log "SSH port:     ${SSH_PORT}"

# 检查必要工具
for cmd in git python3 openssl; do
    command -v "${cmd}" &>/dev/null || err "Required command not found: ${cmd}. Please install it first."
done

# 1. 安装系统依赖
log "Installing system dependencies..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv openssh-server openssl

# 2. 创建蜜罐用户
if ! id "${APP_USER}" &>/dev/null; then
    log "Creating user: ${APP_USER}"
    useradd -r -m -s /bin/bash "${APP_USER}"
fi

# 3. 创建目录
log "Creating app directory: ${APP_DIR}"
mkdir -p "${APP_DIR}"
mkdir -p "${APP_DIR}/honeypot_memory/states"
mkdir -p "${APP_DIR}/honeypot_memory/graphs"
mkdir -p "${APP_DIR}/logs"
mkdir -p "${APP_DIR}/config"

# 4. 克隆代码（失败则报错退出，不吞掉错误）
if [ -d "${APP_DIR}/repo" ]; then
    log "Updating existing repo..."
    git -C "${APP_DIR}/repo" pull || err "git pull failed. Check network and repo URL."
else
    log "Cloning PromptShield repo..."
    git clone "${REPO_URL}" "${APP_DIR}/repo" || err "git clone failed. Check network and repo URL: ${REPO_URL}"
fi

# 复制代码到 APP_DIR（包含隐藏文件）
log "Copying repo files to ${APP_DIR}..."
cp -r "${APP_DIR}/repo/." "${APP_DIR}/"

# 5. Python 虚拟环境
log "Setting up Python virtualenv..."
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip || err "pip upgrade failed"
"${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt" || err "pip install failed"

# 6. 配置环境变量
if [ ! -f "${APP_DIR}/.env" ]; then
    if [ -f "${APP_DIR}/.env.example" ]; then
        cp "${APP_DIR}/.env.example" "${APP_DIR}/.env"
    else
        touch "${APP_DIR}/.env"
    fi
    chmod 600 "${APP_DIR}/.env"
    warn ".env created from template. Edit ${APP_DIR}/.env and set API keys before starting!"
fi
# 确保权限正确（即使文件已存在）
chmod 600 "${APP_DIR}/.env"

# 7. 配置 OpenSSH（完整独立配置，不依赖系统 sshd_config）
SSHD_HONEYPOT_CONF="/etc/ssh/sshd_config_promptshield"
SSHD_HONEYPOT_KEYS_DIR="/etc/ssh/promptshield_keys"
mkdir -p "${SSHD_HONEYPOT_KEYS_DIR}"

# 生成独立 host keys
if [ ! -f "${SSHD_HONEYPOT_KEYS_DIR}/ssh_host_rsa_key" ]; then
    log "Generating SSH host keys for honeypot..."
    ssh-keygen -t rsa -b 4096 -f "${SSHD_HONEYPOT_KEYS_DIR}/ssh_host_rsa_key" -N "" -q
    ssh-keygen -t ed25519 -f "${SSHD_HONEYPOT_KEYS_DIR}/ssh_host_ed25519_key" -N "" -q
fi

log "Configuring OpenSSH honeypot instance on port ${SSH_PORT}..."
cat > "${SSHD_HONEYPOT_CONF}" << EOF
# PromptShield Honeypot - Complete sshd_config
Port ${SSH_PORT}
ListenAddress 0.0.0.0

# Host Keys（独立于系统 sshd）
HostKey ${SSHD_HONEYPOT_KEYS_DIR}/ssh_host_rsa_key
HostKey ${SSHD_HONEYPOT_KEYS_DIR}/ssh_host_ed25519_key

PidFile /run/sshd-promptshield.pid

# 认证
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PAMServiceName sshd-honeypot

# 强制路由到蜜罐
ForceCommand ${APP_DIR}/config/honeypot_command.sh
PermitRootLogin no
AllowUsers ${APP_USER}

# 安全限制
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
AllowAgentForwarding no
PermitUserEnvironment no

# 超时
ClientAliveInterval 120
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 20
MaxStartups 10:30:60

# 日志
SyslogFacility AUTH
LogLevel VERBOSE
EOF

# 8. PAM 配置（允许任意密码，使用独立 PAM 服务名）
log "Configuring PAM for honeypot (any password accepted)..."
cat > /etc/pam.d/sshd-honeypot << 'EOF'
auth       sufficient   pam_permit.so
account    required     pam_permit.so
session    optional     pam_loginuid.so
EOF

# 9. 部署 ForceCommand 脚本
log "Deploying honeypot_command.sh..."
mkdir -p "${APP_DIR}/config"
cat > "${APP_DIR}/config/honeypot_command.sh" << SCRIPT
#!/bin/bash
# PromptShield ForceCommand
ATTACKER_IP=\$(echo "\${SSH_CONNECTION:-}" | awk '{print \$1}')
ATTACKER_IP=\${ATTACKER_IP:-unknown}
SESSION_ID=\$(openssl rand -hex 8 2>/dev/null || echo "\$(date +%s)_\$\$")
echo "[\$(date -u +%Y-%m-%dT%H:%M:%SZ)] New connection from \${ATTACKER_IP} (session: \${SESSION_ID})" \\
    >> "${APP_DIR}/logs/connections.log" || true
cd "${APP_DIR}" || exit 1
exec "${APP_DIR}/venv/bin/python3" LinuxSSHbot_mcp.py \\
    2>> "${APP_DIR}/logs/errors_\${SESSION_ID}.log"
SCRIPT
chmod +x "${APP_DIR}/config/honeypot_command.sh"

# 10. 权限设置
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"
chmod 600 "${APP_DIR}/.env"

# 11. 校验 sshd 配置
log "Validating sshd config..."
/usr/sbin/sshd -t -f "${SSHD_HONEYPOT_CONF}" || err "sshd config validation failed! Check ${SSHD_HONEYPOT_CONF}"

# 12. 检查端口占用
if ss -tlnp | grep -q ":${SSH_PORT} "; then
    err "Port ${SSH_PORT} is already in use. Stop the existing service first."
fi

# 13. Systemd 服务
log "Installing systemd service..."
cat > /etc/systemd/system/promptshield-sshd.service << EOF
[Unit]
Description=PromptShield Honeypot SSH Server
After=network.target

[Service]
Type=forking
PIDFile=/run/sshd-promptshield.pid
ExecStart=/usr/sbin/sshd -f ${SSHD_HONEYPOT_CONF}
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable promptshield-sshd
systemctl start promptshield-sshd

log "=== Setup Complete ==="
log "Honeypot listening on port: ${SSH_PORT}"
log "Edit API keys:  ${APP_DIR}/.env"
log "View logs:      ${APP_DIR}/logs/"
log "Service status: systemctl status promptshield-sshd"
