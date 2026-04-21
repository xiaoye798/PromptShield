# PromptShield Honeypot - Dockerfile
# Based on Python 3.11 slim, includes OpenSSH server
# Architecture: OpenSSH (ForceCommand) -> LinuxSSHbot_mcp.py (stdin/stdout)

FROM python:3.11-slim

LABEL maintainer="PromptShield Research"
LABEL description="Stateful LLM-powered SSH Honeypot"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    curl \
    netcat-openbsd \
    openssl \
    socat \
    && rm -rf /var/lib/apt/lists/*

# Create honeypot user (password randomly generated at runtime by entrypoint.sh)
RUN useradd -m -s /bin/bash honeypot \
    && mkdir -p /home/honeypot/.ssh

# Create working directory
WORKDIR /app

# Copy requirements.txt first to leverage Docker layer cache (skip pip install if unchanged)
COPY repo/requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy full project code
COPY repo/ /app/

# Create log, state, and monitoring directories (must precede COPY to sub-paths)
RUN mkdir -p /app/honeypot_memory/states \
    && mkdir -p /app/honeypot_memory/graphs \
    && mkdir -p /app/logs \
    && mkdir -p /app/monitoring \
    && mkdir -p /run/sshd

# Copy monitoring scripts (directory created in previous step)
COPY monitoring/stats.py /app/monitoring/stats.py

# Configure OpenSSH
COPY config/sshd_config /etc/ssh/sshd_config
COPY config/honeypot_command.sh /app/honeypot_command.sh
COPY config/pam_autocreate.sh /app/pam_autocreate.sh
COPY config/honeypot_users.txt /app/honeypot_users.txt
RUN chmod +x /app/honeypot_command.sh /app/pam_autocreate.sh

# Batch-create honeypot usernames (SSH requires users in /etc/passwd)
RUN while IFS= read -r username; do \
      username=$(echo "$username" | tr -d '[:space:]'); \
      [ -n "$username" ] && useradd -M -s /bin/bash "$username" 2>/dev/null || true; \
    done < /app/honeypot_users.txt

# Create SSH Banner file (disguise as legacy system)
RUN echo 'Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)' \
    > /etc/ssh/honeypot_banner

# Note: SSH Host Keys generated at runtime by entrypoint.sh (avoids identical keys per build)

# Permissions: code owned by root, runtime directories writable by all honeypot users
RUN chown -R root:root /app \
    && chmod 755 /app \
    && chmod 777 /app/logs /app/honeypot_memory /app/honeypot_memory/states /app/honeypot_memory/graphs \
    && touch /app/history.txt /app/api_errors.log \
    && chmod 666 /app/history.txt /app/api_errors.log

# Expose SSH + Telnet ports
EXPOSE 2222 2323

# Entrypoint script
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
