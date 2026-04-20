#!/bin/bash
set -e
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[entrypoint]${NC} $1"; }
err() { echo "[ERROR] $1" >&2; exit 1; }

# === 校验 API Key ===
if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${DEEPSEEK_API_KEY:-}" ]; then
    err "Neither OPENAI_API_KEY nor DEEPSEEK_API_KEY is set!"
fi

# === 生成 SSH Host Keys（每次容器启动时重新生成，避免密钥固化）===
log "Generating SSH host keys..."
ssh-keygen -A -q

# === 创建 Banner 文件（伪装为老旧系统，吸引更多 botnet）===
cat > /etc/ssh/honeypot_banner << BANNER
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of $(date -u '+%a %b %d %H:%M:%S UTC %Y')

  System load:  0.08              Processes:           142
  Usage of /:   34.2% of 49.12GB  Users logged in:     1
  Memory usage: 23%               IP address for eth0: 192.168.1.$(shuf -i 10-250 -n 1)
  Swap usage:   0%

Last login: $(date -u -d '-2 hours' '+%a %b %d %H:%M:%S %Y') from 192.168.1.$(shuf -i 10-250 -n 1)
BANNER

# === 随机生成蜜罐用户密码（不硬编码）===
RANDOM_PASS=$(openssl rand -base64 16)
echo "honeypot:${RANDOM_PASS}" | chpasswd

# === 创建常见攻击目标用户名（蜜罐需要接受各种用户名登录）===
log "Creating common honeypot usernames..."
for user in admin test user ubuntu debian guest ftpuser www-data mysql postgres oracle pi nagios jenkins git deploy app service operator maintenance backup administrator sysadmin webmaster info support contact sales marketing demo trial temp manager supervisor staff employee visitor anonymous ftp mail postmaster abuse security audit scanner scanner1 default system nobody bin daemon www http apache nginx redis mongodb docker kube ansible terraform vagrant dev developer devops sre qa engineer analyst data api web node java python php ruby go rust svn hg ci cd build release staging production prod stage preprod testing pentest audit2 readonly viewer editor publisher hacker123 attacker pentest1; do
    useradd -M -s /bin/bash "$user" 2>/dev/null || true
done
log "Honeypot usernames created"

# === PAM：允许任意密码 + 自动创建用户（蜜罐核心，仅在容器内生效）===
cat > /etc/pam.d/sshd << 'EOF'
auth       sufficient   pam_permit.so
account    required     pam_exec.so /app/pam_autocreate.sh
account    sufficient   pam_permit.so
session    optional     pam_loginuid.so
session    optional     pam_unix.so
EOF

# === 初始化状态目录 ===
mkdir -p /app/honeypot_memory/states /app/honeypot_memory/graphs /app/logs
chmod 777 /app/logs /app/honeypot_memory /app/honeypot_memory/states /app/honeypot_memory/graphs
touch /app/logs/connections.log /app/history.txt /app/api_errors.log
chmod 666 /app/logs/connections.log /app/history.txt /app/api_errors.log

if [ ! -f /app/honeypot_memory/states/global_default.json ]; then
    echo '{"filesystem":{"files":{},"directories":["/root","/home","/tmp","/etc","/var"]},"users":{},"cron_jobs":[],"services":{},"version":1}' \
        > /app/honeypot_memory/states/global_default.json
fi
if [ ! -f /app/honeypot_memory/graphs/global_default.json ]; then
    echo '{"nodes":[],"edges":[],"version":1}' \
        > /app/honeypot_memory/graphs/global_default.json
fi

# === API Key 不落盘，直接通过环境变量传递给应用 ===
# 应用（LinuxSSHbot_mcp.py）应从 os.environ 读取，不依赖 .env 文件
# 确认关键变量已注入
log "API_PROVIDER=${API_PROVIDER:-deepseek}"
if [ -z "${DEEPSEEK_API_KEY:-}" ] && [ -z "${OPENAI_API_KEY:-}" ]; then
    err "No API key available in environment!"
fi

# === 验证 sshd 配置 ===
log "Validating sshd config..."
for key in /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_ed25519_key; do
    [ -f "$key" ] || err "Host key missing: $key"
done
sshd -t || err "sshd config validation failed!"

log "Starting OpenSSH on port 2222..."

# === 启动 Telnet 蜜罐（后台，端口 2323）===
log "Starting Telnet honeypot on port 2323..."
socat TCP-LISTEN:2323,reuseaddr,fork EXEC:"python3 /app/telnet_honeypot.py",pty,stderr &
log "Telnet honeypot started"

# === 将 API 配置写入文件（ForceCommand 环境无法继承容器环境变量）===
cat > /app/.env << ENVFILE
API_PROVIDER=${API_PROVIDER:-deepseek}
DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY:-}
DEEPSEEK_BASE_URL=${DEEPSEEK_BASE_URL:-https://api.deepseek.com}
DEEPSEEK_MODEL=${DEEPSEEK_MODEL:-deepseek-chat}
OPENAI_API_KEY=${OPENAI_API_KEY:-}
KIMI_API_KEY=${KIMI_API_KEY:-}
KIMI_BASE_URL=${KIMI_BASE_URL:-https://api.kimi.com/coding/v1}
KIMI_MODEL=${KIMI_MODEL:-k2p5}
DEBUG_MODE=${DEBUG_MODE:-false}
TRACE_MODE=${TRACE_MODE:-false}
STORAGE_PATH=${STORAGE_PATH:-/app/honeypot_memory}
GLOBAL_SINGLETON_MODE=${GLOBAL_SINGLETON_MODE:-true}
ENVFILE
chown honeypot:honeypot /app/.env || true
chmod 640 /app/.env || true
log "API config written to /app/.env"

exec /usr/sbin/sshd -D -e -p 2222
