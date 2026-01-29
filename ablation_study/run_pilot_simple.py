#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Simplified Ablation Pilot Test - No MCP dependency
Tests the core ablation logic using direct LLM calls
"""

import json
import os
import sys
import time
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
    success: bool
    latency_ms: float
    context_tokens: int
    implant_response: str
    verify_response: str

# Simulated state storage for each mode
class StateStore:
    def __init__(self):
        self.structured_state = {}  # ORIGINAL mode
        self.raw_history = []       # RAW_HISTORY mode
    
    def clear(self):
        self.structured_state = {}
        self.raw_history = []
    
    def record_structured(self, key, value):
        self.structured_state[key] = value
    
    def record_raw(self, command, response):
        self.raw_history.append({"cmd": command, "resp": response})
    
    def get_structured_context(self, query_type):
        return json.dumps(self.structured_state.get(query_type, {}), indent=2)
    
    def get_raw_context(self):
        return "\n".join([f"$ {h['cmd']}\n{h['resp']}" for h in self.raw_history])
    
    def get_full_context(self):
        return json.dumps(self.structured_state, indent=2)

state_store = StateStore()

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

# Professional honeypot system prompt (from test_honeycomb_e2e_real.py)
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

def run_scenario(scenario, mode):
    """Run a single scenario with specified injection mode"""
    p(f"  [{scenario['id']}] Mode: {mode}")
    
    state_store.clear()
    
    # === Session A: Implant ===
    # Use professional honeypot prompt
    messages = [
        {"role": "system", "content": HONEYPOT_SYSTEM_PROMPT},
        {"role": "user", "content": scenario['implant']}
    ]
    implant_resp, _ = call_llm(messages)
    
    # Record state based on mode
    if mode == "ORIGINAL":
        # Structured: extract key information
        state_store.record_structured("user_created", {"username": "sysupdate", "uid": 1001})
        state_store.record_structured("file_created", scenario['implant'])
    elif mode == "RAW_HISTORY":
        state_store.record_raw(scenario['implant'], implant_resp)
    elif mode == "FULL_CONTEXT":
        state_store.record_structured("full_history", {"implant": scenario['implant'], "response": implant_resp})
    # STATELESS: no recording
    
    # === Session B: Verify (new context) ===
    context_str = ""
    if mode == "ORIGINAL":
        context_str = f"[System State]\n{state_store.get_structured_context('user_created')}\n{state_store.get_structured_context('file_created')}"
    elif mode == "RAW_HISTORY":
        context_str = f"[Previous Session]\n{state_store.get_raw_context()}"
    elif mode == "FULL_CONTEXT":
        context_str = f"[Full State Dump]\n{state_store.get_full_context()}"
    # STATELESS: empty context
    
    # Build verification prompt with injected context
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
    
    short_implant = implant_resp[:60] + "..." if len(implant_resp) > 60 else implant_resp
    short_verify = verify_resp[:60] + "..." if len(verify_resp) > 60 else verify_resp
    p(f"    Success: {success}, Latency: {latency:.0f}ms, Context: {context_tokens} words")
    p(f"    Verify: {short_verify}")
    
    return AblationMetric(
        mode=mode,
        scenario_id=scenario['id'],
        success=success,
        latency_ms=latency,
        context_tokens=context_tokens,
        implant_response=implant_resp[:200],
        verify_response=verify_resp[:200]
    )

# Test scenarios (3 for pilot)
PILOT_SCENARIOS = [
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

MODES = ["ORIGINAL", "RAW_HISTORY", "FULL_CONTEXT", "STATELESS"]

def main():
    p("="*60)
    p("ABLATION PILOT TEST (Simplified)")
    p(f"3 Scenarios x 4 Modes = 12 Tests")
    p(f"API Provider: {api_provider}")
    p("="*60)
    
    results = []
    
    for mode in MODES:
        p(f"\n{'='*50}")
        p(f"Testing Mode: {mode}")
        p(f"{'='*50}")
        for scen in PILOT_SCENARIOS:
            try:
                metric = run_scenario(scen, mode)
                results.append(asdict(metric))
            except Exception as e:
                p(f"  ERROR: {e}")
                results.append({
                    "mode": mode,
                    "scenario_id": scen['id'],
                    "success": False,
                    "error": str(e)
                })
            time.sleep(1)
    
    # Save results
    output_file = "ablation_study/pilot_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Summary
    p("\n" + "="*60)
    p("PILOT TEST SUMMARY")
    p("="*60)
    for mode in MODES:
        mode_results = [r for r in results if r.get('mode') == mode]
        success_count = sum(1 for r in mode_results if r.get('success', False))
        p(f"{mode:15} | SFR: {success_count}/3")
    
    p(f"\nResults saved to: {output_file}")

if __name__ == "__main__":
    main()
