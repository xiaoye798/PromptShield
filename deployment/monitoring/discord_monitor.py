#!/usr/bin/env python3
"""
PromptShield 蜜罐实时日志监控 → Discord 推送
每分钟由 cron 调用，检查新连接和新命令，推送到 Discord
"""
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

DISCORD_CHANNEL = "1489155195882704996"
STATE_DIR = Path("/root/honeypot_logs/.monitor_state")
STATE_DIR.mkdir(parents=True, exist_ok=True)

CONN_STATE = STATE_DIR / "connections_lines"
HIST_STATE = STATE_DIR / "history_lines"
LAST_MSG_TIME = STATE_DIR / "last_msg_time"

def read_state(path, default=0):
    try:
        return int(path.read_text().strip())
    except:
        return default

def write_state(path, val):
    path.write_text(str(val))

def docker_exec(cmd):
    try:
        result = subprocess.run(
            ["docker", "exec", "promptshield-honeypot"] + cmd.split(),
            capture_output=True, text=True, timeout=10
        )
        return result.stdout
    except:
        return ""

def send_discord(message):
    """Send message via openclaw CLI"""
    try:
        subprocess.run(
            ["openclaw", "message", "send",
             "--channel", "discord",
             "--target", DISCORD_CHANNEL,
             "--message", message],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        print(f"Discord send failed: {e}", file=sys.stderr)

def main():
    messages = []
    
    # === 1. Check new connections ===
    conn_log = docker_exec("cat /app/logs/connections.log")
    if conn_log:
        lines = conn_log.strip().split('\n')
        total = len(lines)
        last = read_state(CONN_STATE)
        
        if total > last:
            new_lines = lines[last:]
            write_state(CONN_STATE, total)
            
            for line in new_lines:
                # Skip internal docker network connections
                if "172.18.0.1" in line or "127.0.0.1" in line:
                    continue
                # Parse: [timestamp] New connection from IP (session: xxx)
                import re
                m = re.search(r'\[([^\]]+)\].*from\s+(\S+).*session:\s+(\w+)', line)
                if m:
                    ts, ip, session = m.groups()
                    messages.append(f"🔴 **新连接** `{ts}`\n> IP: `{ip}`\n> Session: `{session[:12]}...`")
    
    # === 2. Check new commands (history.txt) ===
    history = docker_exec("cat /app/history.txt")
    if history:
        lines = history.strip().split('\n') if history.strip() else []
        total = len(lines)
        last = read_state(HIST_STATE)
        
        if total > last:
            new_lines = lines[last:]
            write_state(HIST_STATE, total)
            
            # Filter meaningful lines (skip session markers and empty)
            cmd_lines = []
            for line in new_lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('---'):
                    continue
                # Truncate long lines
                if len(stripped) > 200:
                    stripped = stripped[:200] + "..."
                # Sanitize backticks to prevent markdown breaking
                stripped = stripped.replace('`', '\'')
                cmd_lines.append(stripped)
            
            if cmd_lines:
                # Group into chunks of max 10 lines
                for i in range(0, len(cmd_lines), 10):
                    chunk = cmd_lines[i:i+10]
                    block = '\n'.join(chunk)
                    messages.append(f"⌨️ **攻击者命令**\n```\n{block}\n```")
    
    # === 3. Check API errors ===
    errors = docker_exec("cat /app/api_errors.log")
    if errors and errors.strip():
        err_lines = errors.strip().split('\n')
        err_state = STATE_DIR / "errors_lines"
        last_err = read_state(err_state)
        total_err = len(err_lines)
        
        if total_err > last_err:
            write_state(err_state, total_err)
            messages.append(f"⚠️ **API 错误** ({total_err - last_err} 条新错误)")
    
    # === Send messages ===
    for msg in messages[:5]:  # Max 5 messages per check to avoid spam
        send_discord(msg)
    
    # === Periodic status (every 6 hours) ===
    last_status = read_state(LAST_MSG_TIME, 0)
    now = int(datetime.utcnow().timestamp())
    if now - last_status > 6 * 3600:  # 6 hours
        write_state(LAST_MSG_TIME, now)
        
        # Get container stats
        status = subprocess.run(
            ["docker", "ps", "--filter", "name=promptshield",
             "--format", "{{.Status}}"],
            capture_output=True, text=True
        ).stdout.strip()
        
        conn_count = read_state(CONN_STATE)
        
        send_discord(
            f"📊 **蜜罐状态报告** `{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}`\n"
            f"> 容器: `{status}`\n"
            f"> 总连接数: `{conn_count}`\n"
            f"> 模型: `DeepSeek Chat`"
        )

if __name__ == "__main__":
    main()
