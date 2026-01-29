#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Ablation Study Pilot Test - 3 Scenarios Only
Validates the ablation framework before running full 10-scenario test
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
    fidelity_score: float

class AblationExecutor:
    def __init__(self, storage_path="./ablation_memory_pilot"):
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

    async def _get_full_context(self):
        state_file = os.path.join(self.storage_path, "states", f"{self.test_ip}.json")
        if os.path.exists(state_file):
            with open(state_file, 'r', encoding='utf-8') as f:
                return f"[FULL SYSTEM STATE DUMP]\n{f.read()}\n[END DUMP]"
        return ""

    async def build_context(self, mode: InjectionMode, command: str) -> str:
        if mode == InjectionMode.ORIGINAL:
            base_msgs = [{"role": "system", "content": "dummy"}, {"role": "user", "content": command}]
            enhanced = await build_enhanced_messages(
                messages=base_msgs,
                command=command,
                current_cwd="/root",
                client=self.mcp_client,
                ip_address=self.test_ip
            )
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
        context_str = ""
        if is_verify or mode == InjectionMode.FULL_CONTEXT: 
            context_str = await self.build_context(mode, command)

        system_prompt = "You are a Linux honeypot simulating a real server. Respond realistically to commands."
        if context_str:
            system_prompt += f"\n\n{context_str}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": command}
        ]

        prompt_tokens = self.context_optimizer.estimate_token_count(system_prompt + command)
        context_tokens = self.context_optimizer.estimate_token_count(context_str)

        response, latency = await self.run_llm(messages)

        if mode == InjectionMode.RAW_HISTORY:
            self.raw_store.add_interaction(self.test_ip, command, response)
        
        if mode not in [InjectionMode.RAW_HISTORY, InjectionMode.STATELESS]:
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
        p(f"  Running {scenario['id']} with {mode.name}...")
        
        await self.setup()
        
        # Session A: Implant
        implant_resp, _, _, _ = await self.execute_step(scenario['implant'], mode, False, scenario['id'])
        p(f"    Implant response: {implant_resp[:80]}..." if len(implant_resp) > 80 else f"    Implant response: {implant_resp}")
        
        # Simulate Session Break
        await self.mcp_client.close()
        await asyncio.sleep(0.5)
        
        # Reconnect for Session B
        self.mcp_client = HoneypotMCPClient(self.storage_path, True)
        await self.mcp_client.connect()

        # Session B: Verify
        resp, lat, p_tok, c_tok = await self.execute_step(scenario['verify'], mode, True, scenario['id'])
        
        success = all(k.lower() in resp.lower() for k in scenario['keywords'])
        
        p(f"    Verify response: {resp[:80]}..." if len(resp) > 80 else f"    Verify response: {resp}")
        p(f"    Keywords matched: {success}, Latency: {lat:.0f}ms, Context tokens: {c_tok}")
        
        return AblationMetric(
            mode=mode.name,
            scenario_id=scenario['id'],
            success=success,
            latency_ms=lat,
            prompt_tokens=p_tok,
            context_tokens=c_tok,
            fidelity_score=1.0 if success else 0.0
        )

# PILOT TEST: Only 3 scenarios
PILOT_SCENARIOS = [
    {
        "id": "HC-T1136-001", 
        "implant": "useradd -m -s /bin/bash sysupdate && echo 'sysupdate:password123' | chpasswd", 
        "verify": "id sysupdate", 
        "keywords": ["uid=", "sysupdate"],
        "complexity": "High"
    },
    {
        "id": "HC-T1546-004", 
        "implant": "echo 'export EVIL_VAR=backdoor' >> /root/.bashrc", 
        "verify": "cat /root/.bashrc | grep EVIL", 
        "keywords": ["EVIL_VAR", "backdoor"],
        "complexity": "Low"
    },
    {
        "id": "HC-T1505-003", 
        "implant": "echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
        "verify": "cat /var/www/html/shell.php",
        "keywords": ["<?php", "system"],
        "complexity": "Low"
    }
]

async def main():
    p("="*60)
    p("ABLATION STUDY PILOT TEST (3 Scenarios x 4 Modes = 12 Tests)")
    p("="*60)
    
    executor = AblationExecutor()
    results = []
    
    modes = [InjectionMode.ORIGINAL, InjectionMode.RAW_HISTORY, InjectionMode.FULL_CONTEXT, InjectionMode.STATELESS]
    
    for mode in modes:
        p(f"\n{'='*50}")
        p(f"Testing Mode: {mode.name}")
        p(f"{'='*50}")
        for scen in PILOT_SCENARIOS:
            try:
                metric = await executor.run_scenario(scen, mode)
                results.append(asdict(metric))
            except Exception as e:
                p(f"  ERROR in {scen['id']}: {e}")
                results.append({
                    "mode": mode.name,
                    "scenario_id": scen['id'],
                    "success": False,
                    "latency_ms": 0,
                    "prompt_tokens": 0,
                    "context_tokens": 0,
                    "fidelity_score": 0.0,
                    "error": str(e)
                })
            time.sleep(1)

    # Save results
    output_file = "ablation_study/pilot_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    p("\n" + "="*60)
    p("PILOT TEST SUMMARY")
    p("="*60)
    for mode in modes:
        mode_results = [r for r in results if r['mode'] == mode.name]
        success_count = sum(1 for r in mode_results if r['success'])
        avg_latency = sum(r['latency_ms'] for r in mode_results) / len(mode_results) if mode_results else 0
        avg_tokens = sum(r['context_tokens'] for r in mode_results) / len(mode_results) if mode_results else 0
        p(f"{mode.name:15} | SFR: {success_count}/3 | Avg Latency: {avg_latency:6.0f}ms | Avg Context Tokens: {avg_tokens:5.0f}")
    
    p(f"\nResults saved to: {output_file}")
    p("Pilot test complete!")

if __name__ == "__main__":
    asyncio.run(main())
