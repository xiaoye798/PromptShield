# PromptShield Honeypot - Dockerfile
# 基于 Python 3.11 slim，包含 OpenSSH 服务器
# 架构：OpenSSH (ForceCommand) → LinuxSSHbot_mcp.py (stdin/stdout)

FROM python:3.11-slim

LABEL maintainer="PromptShield Research"
LABEL description="Stateful LLM-powered SSH Honeypot"

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    curl \
    netcat-openbsd \
    openssl \
    socat \
    && rm -rf /var/lib/apt/lists/*

# 创建蜜罐用户（密码在运行时由 entrypoint.sh 随机生成）
RUN useradd -m -s /bin/bash honeypot \
    && mkdir -p /home/honeypot/.ssh

# 创建工作目录
WORKDIR /app

# 先复制 requirements.txt，利用 Docker layer 缓存（依赖不变时跳过 pip install）
COPY repo/requirements.txt /app/requirements.txt

# 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt

# 再复制完整项目代码
COPY repo/ /app/

# 创建日志和状态目录、监控脚本目录（必须先于 COPY 到子路径之前）
RUN mkdir -p /app/honeypot_memory/states \
    && mkdir -p /app/honeypot_memory/graphs \
    && mkdir -p /app/logs \
    && mkdir -p /app/monitoring \
    && mkdir -p /run/sshd

# 复制监控脚本（目录已在上一步创建）
COPY monitoring/stats.py /app/monitoring/stats.py

# 配置 OpenSSH
COPY config/sshd_config /etc/ssh/sshd_config
COPY config/honeypot_command.sh /app/honeypot_command.sh
COPY config/pam_autocreate.sh /app/pam_autocreate.sh
COPY config/honeypot_users.txt /app/honeypot_users.txt
RUN chmod +x /app/honeypot_command.sh /app/pam_autocreate.sh

# 批量创建蜜罐用户名（SSH 要求用户存在于 /etc/passwd）
RUN while IFS= read -r username; do \
      username=$(echo "$username" | tr -d '[:space:]'); \
      [ -n "$username" ] && useradd -M -s /bin/bash "$username" 2>/dev/null || true; \
    done < /app/honeypot_users.txt

# 创建 SSH Banner 文件（伪装为老旧系统）
RUN echo 'Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)' \
    > /etc/ssh/honeypot_banner

# 注意：SSH Host Keys 在运行时由 entrypoint.sh 生成（避免每次构建密钥相同）

# 权限设置：代码属 root，运行时目录允许所有蜜罐用户写入
RUN chown -R root:root /app \
    && chmod 755 /app \
    && chmod 777 /app/logs /app/honeypot_memory /app/honeypot_memory/states /app/honeypot_memory/graphs \
    && touch /app/history.txt /app/api_errors.log \
    && chmod 666 /app/history.txt /app/api_errors.log

# 暴露 SSH + Telnet 端口
EXPOSE 2222 2323

# 启动脚本
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
