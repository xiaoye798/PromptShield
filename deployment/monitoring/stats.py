# PromptShield Honeypot — 会话日志分析脚本
# 用于从 connections.log 和状态目录中提取攻击者行为统计

import re
import os
import sys
import ipaddress
from pathlib import Path

# 支持环境变量覆盖路径
LOG_DIR = Path(os.environ.get("PROMPTSHIELD_LOG_DIR", "/app/logs"))
MEMORY_DIR = Path(os.environ.get("PROMPTSHIELD_MEMORY_DIR", "/app/honeypot_memory/states"))

# 可选 IP 脱敏（export REDACT_IPS=true 启用）
REDACT_IPS = os.environ.get("REDACT_IPS", "false").lower() == "true"


def display_ip(ip: str) -> str:
    """根据 REDACT_IPS 决定是否脱敏 IP。"""
    if not REDACT_IPS:
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    return "***"


def _is_valid_ip(s: str) -> bool:
    """校验字符串是否为合法 IPv4/IPv6 地址。"""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse_connections():
    """流式解析 connections.log，返回会话列表。"""
    conn_log = LOG_DIR / "connections.log"
    if not conn_log.exists():
        return []
    sessions = []
    pattern = re.compile(r'\[(.+?)\] New connection from (\S+) \(session: (\S+)\)')
    try:
        with conn_log.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                m = pattern.match(line)
                if m:
                    ip = m.group(2)
                    if not _is_valid_ip(ip):
                        continue  # 跳过非法 IP，防止注入
                    sessions.append({
                        "time": m.group(1),
                        "ip": ip,
                        "session": m.group(3)
                    })
    except OSError as e:
        print(f"[警告] 无法读取日志文件: {e}", file=sys.stderr)
        return []
    return sessions


def get_tracked_ips():
    """返回 MEMORY_DIR 中有效 IP 状态文件的列表（排除 global_default）。"""
    if not MEMORY_DIR.exists():
        return []
    files = list(MEMORY_DIR.glob("*.json"))
    ips = [
        f.stem for f in files
        if f.stem != "global_default" and _is_valid_ip(f.stem)
    ]
    return ips


def main():
    sessions = parse_connections()
    total_sessions = len(sessions)
    unique_ips = len(set(s["ip"] for s in sessions))
    tracked_ips = get_tracked_ips()
    state_count = len(tracked_ips)

    print(f"\n=== PromptShield Honeypot Stats ===")
    print(f"Total sessions : {total_sessions}")
    print(f"Unique IPs     : {unique_ips}")
    print(f"Tracked states : {state_count}")
    if tracked_ips:
        display_ips = [display_ip(ip) for ip in tracked_ips[:10]]
        suffix = "..." if len(tracked_ips) > 10 else ""
        print(f"Tracked IPs    : {', '.join(display_ips)}{suffix}")

    if sessions:
        print(f"\nLast 10 connections:")
        for s in sessions[-10:]:
            print(f"  [{s['time']}] {display_ip(s['ip'])}")


if __name__ == "__main__":
    main()
