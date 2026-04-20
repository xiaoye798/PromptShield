#!/usr/bin/env python3
"""
Simple Telnet honeypot — 模拟路由器/IoT 设备登录
Mirai botnet 的主要目标
"""
import sys
import os
import time
from datetime import datetime

LOG_DIR = "/app/logs"

def main():
    # 获取连接 IP（由 xinetd/socat 传入）
    remote_ip = os.environ.get("SOCAT_PEERADDR", os.environ.get("REMOTE_HOST", "unknown"))
    session_id = f"telnet_{int(time.time())}_{os.getpid()}"
    
    # 记录连接
    try:
        with open(f"{LOG_DIR}/connections.log", "a") as f:
            f.write(f"[{datetime.utcnow().isoformat()}Z] Telnet connection from {remote_ip} (session: {session_id})\n")
    except:
        pass
    
    log_file = f"{LOG_DIR}/telnet_{session_id}.log"
    
    def log(msg):
        try:
            with open(log_file, "a") as f:
                f.write(f"[{datetime.utcnow().isoformat()}] {msg}\n")
        except:
            pass
    
    # 模拟路由器登录提示
    sys.stdout.write("\r\n\r\n")
    sys.stdout.write("BusyBox v1.22.1 (2018-03-09 14:19:45 UTC) built-in shell\r\n")
    sys.stdout.write("Enter 'help' for a list of built-in commands.\r\n\r\n")
    sys.stdout.flush()
    
    # 登录交互
    sys.stdout.write("(none) login: ")
    sys.stdout.flush()
    try:
        username = input().strip()
    except:
        return
    log(f"Username: {username}")
    
    sys.stdout.write("Password: ")
    sys.stdout.flush()
    try:
        password = input().strip()
    except:
        return
    log(f"Password: {password}")
    
    # 接受任意凭据
    sys.stdout.write(f"\r\n\r\nWelcome to {username}!\r\n")
    sys.stdout.write("# ")
    sys.stdout.flush()
    
    # 命令循环
    while True:
        try:
            cmd = input().strip()
            if not cmd:
                sys.stdout.write("# ")
                sys.stdout.flush()
                continue
            
            log(f"Command: {cmd}")
            
            # 模拟常见 Mirai 命令响应
            if cmd in ("exit", "quit", "logout"):
                break
            elif cmd == "sh" or cmd == "/bin/sh" or cmd == "/bin/bash":
                sys.stdout.write("# ")
            elif cmd == "enable":
                sys.stdout.write("# ")
            elif cmd.startswith("cat /proc"):
                sys.stdout.write("1\r\n# ")
            elif "wget" in cmd or "curl" in cmd or "tftp" in cmd:
                sys.stdout.write("Connecting... done.\r\n# ")
                log(f"DOWNLOAD_ATTEMPT: {cmd}")
            elif cmd == "uname -a":
                sys.stdout.write("Linux (none) 4.15.0-213-generic #224-Ubuntu SMP Mon Jun 19 13:30:12 UTC 2023 x86_64 GNU/Linux\r\n# ")
            elif cmd.startswith("chmod"):
                sys.stdout.write("# ")
            elif cmd.startswith("./") or cmd.startswith("/tmp/") or cmd.startswith("/var/"):
                sys.stdout.write("# ")
                log(f"EXECUTION_ATTEMPT: {cmd}")
            elif cmd == "id":
                sys.stdout.write("uid=0(root) gid=0(root)\r\n# ")
            elif cmd == "whoami":
                sys.stdout.write("root\r\n# ")
            elif cmd == "cat /etc/passwd":
                sys.stdout.write("root:x:0:0:root:/root:/bin/sh\r\n# ")
            else:
                sys.stdout.write(f"# ")
            
            sys.stdout.flush()
            
        except (EOFError, KeyboardInterrupt):
            break
        except:
            break
    
    log("Session ended")

if __name__ == "__main__":
    main()
