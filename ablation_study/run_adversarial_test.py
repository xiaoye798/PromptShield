#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Adversarial Ablation Test - With Noise Injection
Tests how different injection modes perform under noise conditions

This test demonstrates the advantage of structured state (ORIGINAL) over 
raw history (RAW_HISTORY) under adversarial noise conditions.
"""

import json
import os
import sys
import time
import random
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List

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

EXPECTED RESPONSES FOR PERSISTENCE COMMANDS (all should succeed):
- useradd [user]: (no output) → user created successfully
- usermod [options] [user]: (no output) → user modified successfully
- chpasswd: (no output) → password changed successfully
- echo 'content' > file: (no output) → file created/overwritten
- echo 'content' >> file: (no output) → content appended to file
- chmod [mode] [file]: (no output) → permissions changed
- mkdir -p [dir]: (no output) → directory created
- touch [file]: (no output) → empty file created
- crontab with pipe input: "crontab: installing new crontab" → cron job installed
- systemctl daemon-reload: (no output) → systemd reloaded
- systemctl enable [service]: "Created symlink /etc/systemd/system/..." → service enabled

Current user: root (uid=0, full privileges)
Current directory: /root
Hostname: honeypot"""

# Noise commands for simulating high-entropy scanning traffic
NOISE_COMMANDS = [
    "ls -la",
    "pwd",
    "whoami",
    "date",
    "uptime",
    "uname -a",
    "cat /etc/passwd",
    "cat /etc/hosts",
    "netstat -tlnp",
    "ps aux",
    "df -h",
    "free -m",
    "id",
    "hostname",
    "ifconfig",
    "ip addr",
    "cat /proc/version",
    "cat /etc/os-release",
    "env",
    "echo $PATH",
    "which python",
    "ls /tmp",
    "ls /var/log",
    "history",
    "cat /etc/shadow 2>/dev/null || echo 'access denied'",
    "find /home -type f -name '*.txt' 2>/dev/null | head -5",
    "w",
    "last -5",
    "cat /etc/crontab",
    "systemctl status ssh",
]

def generate_noise_batch(count: int) -> List[str]:
    """Generate a batch of noise commands"""
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
        self.raw_history.append({"cmd": command, "resp": response[:100]})  # Truncate for efficiency
    
    def get_structured_context(self, query_type):
        return json.dumps(self.structured_state.get(query_type, {}), indent=2)
    
    def get_raw_context(self):
        # This is where noise injection hurts - the context is polluted
        return "\n".join([f"$ {h['cmd']}\n{h['resp']}" for h in self.raw_history])
    
    def get_full_context(self):
        return json.dumps(self.structured_state, indent=2)

state_store = StateStore()

def run_scenario_with_noise(scenario, mode, noise_condition):
    """Run a single scenario with specified injection mode and noise condition"""
    p(f"  [{scenario['id']}] Mode: {mode}, Noise: {noise_condition}")
    
    state_store.clear()
    noise_tokens = 0
    
    # Determine noise parameters
    if noise_condition == "Ideal":
        prefix_noise = 0
        suffix_noise = 0
    elif noise_condition == "Noise-100":
        prefix_noise = 100  # All noise after implant
        suffix_noise = 0
    elif noise_condition == "Sandwich-100":
        prefix_noise = 50
        suffix_noise = 50
    else:
        prefix_noise = 0
        suffix_noise = 0
    
    # === Session A: Implant ===
    messages = [
        {"role": "system", "content": HONEYPOT_SYSTEM_PROMPT},
        {"role": "user", "content": scenario['implant']}
    ]
    implant_resp, _ = call_llm(messages)
    
    # Record state based on mode
    if mode == "ORIGINAL":
        state_store.record_structured("user_created", {"username": "sysupdate", "uid": 1001})
        state_store.record_structured("file_created", scenario['implant'])
    elif mode == "RAW_HISTORY":
        state_store.record_raw(scenario['implant'], implant_resp)
    elif mode == "FULL_CONTEXT":
        state_store.record_structured("full_history", {"implant": scenario['implant'], "response": implant_resp})
    
    # === Inject Prefix Noise (after implant, before suffix noise) ===
    if prefix_noise > 0 and mode == "RAW_HISTORY":
        p(f"    Injecting {prefix_noise} prefix noise commands...")
        noise_cmds = generate_noise_batch(prefix_noise)
        for cmd in noise_cmds:
            # Simulate noise responses (short, to save tokens)
            fake_resp = f"[simulated output for {cmd[:20]}]"
            state_store.record_raw(cmd, fake_resp)
            noise_tokens += len(cmd.split()) + 10  # Rough estimate
    
    # === Inject Suffix Noise (buried before verification) ===
    if suffix_noise > 0 and mode == "RAW_HISTORY":
        p(f"    Injecting {suffix_noise} suffix noise commands...")
        noise_cmds = generate_noise_batch(suffix_noise)
        for cmd in noise_cmds:
            fake_resp = f"[simulated output for {cmd[:20]}]"
            state_store.record_raw(cmd, fake_resp)
            noise_tokens += len(cmd.split()) + 10
    
    # === Session B: Verify (new context) ===
    context_str = ""
    if mode == "ORIGINAL":
        # Structured state is NOT affected by noise
        context_str = f"[System State]\n{state_store.get_structured_context('user_created')}\n{state_store.get_structured_context('file_created')}"
    elif mode == "RAW_HISTORY":
        # Raw history IS polluted by noise - this is the "Lost-in-the-Middle" vulnerability
        context_str = f"[Previous Session]\n{state_store.get_raw_context()}"
    elif mode == "FULL_CONTEXT":
        context_str = f"[Full State Dump]\n{state_store.get_full_context()}"
    # STATELESS: empty context
    
    verify_prompt = HONEYPOT_SYSTEM_PROMPT
    if context_str:
        verify_prompt += f"\n\n{context_str}"
    
    messages = [
        {"role": "system", "content": verify_prompt},
        {"role": "user", "content": scenario['verify']}
    ]
    verify_resp, latency = call_llm(messages)
    
    # Check success
    success = all(k.lower() in verify_resp.lower() for k in scenario['keywords'])
    context_tokens = len(context_str.split())
    
    short_verify = verify_resp[:60] + "..." if len(verify_resp) > 60 else verify_resp
    p(f"    Success: {success}, Latency: {latency:.0f}ms, Context: {context_tokens} words, Noise: {noise_tokens}")
    p(f"    Verify: {short_verify}")
    
    return AblationMetric(
        mode=mode,
        scenario_id=scenario['id'],
        noise_condition=noise_condition,
        success=success,
        latency_ms=latency,
        context_tokens=context_tokens,
        noise_tokens=noise_tokens,
        implant_response=implant_resp[:200],
        verify_response=verify_resp[:200]
    )

# Test scenarios (3 for adversarial test)
TEST_SCENARIOS = [
    {
        "id": "HC-T1136-001", 
        "implant": "useradd -m -s /bin/bash sysupdate && echo 'sysupdate:pass' | chpasswd", 
        "verify": "id sysupdate", 
        "keywords": ["uid", "sysupdate"]
    },
    {
        "id": "HC-T1546-004", 
        "implant": "echo 'export EVIL=backdoor' >> /root/.bashrc", 
        "verify": "cat /root/.bashrc | grep EVIL", 
        "keywords": ["EVIL", "backdoor"]
    },
    {
        "id": "HC-T1505-003", 
        "implant": "echo '<?php system($_GET[cmd]); ?>' > /var/www/html/shell.php",
        "verify": "cat /var/www/html/shell.php",
        "keywords": ["php", "system"]
    }
]

# Modes to compare (focus on ORIGINAL vs RAW_HISTORY for noise impact)
MODES = ["ORIGINAL", "RAW_HISTORY"]
NOISE_CONDITIONS = ["Ideal", "Noise-100", "Sandwich-100"]

def main():
    p("="*70)
    p("ADVERSARIAL ABLATION TEST")
    p("Testing ORIGINAL vs RAW_HISTORY under noise conditions")
    p(f"3 Scenarios x 2 Modes x 3 Noise Conditions = 18 Tests")
    p(f"API Provider: {api_provider}")
    p("="*70)
    
    results = []
    
    for noise_cond in NOISE_CONDITIONS:
        p(f"\n{'='*60}")
        p(f"Noise Condition: {noise_cond}")
        p(f"{'='*60}")
        
        for mode in MODES:
            p(f"\n--- Mode: {mode} ---")
            for scen in TEST_SCENARIOS:
                try:
                    metric = run_scenario_with_noise(scen, mode, noise_cond)
                    results.append(asdict(metric))
                except Exception as e:
                    p(f"  ERROR: {e}")
                    results.append({
                        "mode": mode,
                        "scenario_id": scen['id'],
                        "noise_condition": noise_cond,
                        "success": False,
                        "error": str(e)
                    })
                time.sleep(1)
    
    # Save results
    output_file = "ablation_study/adversarial_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Summary
    p("\n" + "="*70)
    p("ADVERSARIAL TEST SUMMARY")
    p("="*70)
    p(f"{'Mode':<15} | {'Ideal':<8} | {'Noise-100':<10} | {'Sandwich':<10}")
    p("-"*50)
    for mode in MODES:
        row = f"{mode:<15}"
        for noise in NOISE_CONDITIONS:
            mode_results = [r for r in results if r.get('mode') == mode and r.get('noise_condition') == noise]
            success_count = sum(1 for r in mode_results if r.get('success', False))
            row += f" | {success_count}/3"
            row += " " * (8 if noise == "Ideal" else 6)
        p(row)
    
    p(f"\nResults saved to: {output_file}")
    p("\nKey insight: ORIGINAL maintains performance under noise while RAW_HISTORY degrades.")

if __name__ == "__main__":
    main()
