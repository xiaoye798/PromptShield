#!/usr/bin/env python3
"""
PromptShield State Accumulation Experiment

Addresses Reviewer 55A's core concern:
  "It would have been good to include an experiment with a growing amount of
   accumulated stateful effects, and a plot to show how the effectiveness of
   the approach scales with respect to the amount of accumulated effects."

Experiment design:
  Implant N different persistence operations in a single Session A (N = 5, 10, 20, 30, 50)
  Disconnect (destroy conversation history)
  Verify all N states are preserved in Session B
  Record: SFR (State Fidelity Rate), SPR (State Persistence Rate), Token usage, Latency
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

ai_client = openai.AsyncOpenAI(api_key=_cfg("DEEPSEEK_API_KEY"), base_url="https://api.deepseek.com")
AI_MODEL = "deepseek-chat"

SYSTEM_PROMPT = """You are Linux OS terminal. You act and respond exactly as a Linux terminal would.
You only reply with the CLI output, and nothing else.
Do not explain your output. Do not repeat commands user inputs.
Your every output MUST end with a prompt like root@host:path$
Current user: root (uid=0). Hostname: prod-server-01."""


# ==================== State Operation Templates ====================

def generate_operations(n: int) -> List[Dict]:
    """Generate N unique stateful operations with verification commands"""
    ops = []
    
    # Mix of different persistence types
    templates = [
        # File creation (echo > file)
        lambda i: {
            "implant": f'echo "payload_{i}_content" > /tmp/.state_test_{i}.txt',
            "verify": f'cat /tmp/.state_test_{i}.txt',
            "keyword": f'payload_{i}_content',
            "type": "FILE_CREATE",
        },
        # User creation
        lambda i: {
            "implant": f'useradd -m -s /bin/bash testuser_{i}',
            "verify": f'id testuser_{i}',
            "keyword": f'testuser_{i}',
            "type": "USER_CREATE",
        },
        # Cron job
        lambda i: {
            "implant": f'(crontab -l 2>/dev/null; echo "*/{i+1} * * * * /tmp/job_{i}.sh") | crontab -',
            "verify": f'crontab -l',
            "keyword": f'job_{i}.sh',
            "type": "CRON_ADD",
        },
        # File append
        lambda i: {
            "implant": f'echo "config_line_{i}" >> /etc/custom_config.conf',
            "verify": f'cat /etc/custom_config.conf',
            "keyword": f'config_line_{i}',
            "type": "FILE_APPEND",
        },
        # Systemd service
        lambda i: {
            "implant": f"""cat > /etc/systemd/system/svc_{i}.service << 'EOF'
[Unit]
Description=Service {i}
[Service]
ExecStart=/bin/bash -c 'echo svc_{i} running'
[Install]
WantedBy=multi-user.target
EOF""",
            "verify": f'cat /etc/systemd/system/svc_{i}.service',
            "keyword": f'svc_{i}',
            "type": "SERVICE_CREATE",
        },
    ]
    
    for i in range(n):
        template_fn = templates[i % len(templates)]
        ops.append(template_fn(i))
    
    return ops


# ==================== LLM Call ====================

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


# ==================== Experiment Runner ====================

@dataclass
class AccumulationResult:
    n_operations: int
    implant_count: int
    verify_count: int
    spr: float  # State Persistence Rate (state exists)
    sfr: float  # State Fidelity Rate (content correct)
    implant_tokens: int
    verify_tokens: int
    total_tokens: int
    implant_latency_ms: float
    verify_latency_ms: float
    per_operation_details: List[Dict] = field(default_factory=list)


async def run_accumulation_test(n: int, storage_base: str) -> AccumulationResult:
    """Run accumulation test with N stateful operations"""
    print(f"\n{'='*60}")
    print(f"  State Accumulation Test: N = {n}")
    print(f"{'='*60}")
    
    storage_path = os.path.join(storage_base, f"N_{n}")
    if os.path.exists(storage_path):
        shutil.rmtree(storage_path)
    os.makedirs(os.path.join(storage_path, "states"), exist_ok=True)
    os.makedirs(os.path.join(storage_path, "graphs"), exist_ok=True)
    
    ops = generate_operations(n)
    analyzer = CommandAnalyzer()
    ip = f"accum_test_{n}"
    
    implant_tokens = 0
    verify_tokens = 0
    implant_latency = 0.0
    verify_latency = 0.0
    
    # ==================== Session A: Implant N operations ====================
    print(f"\n  [Session A] Implanting {n} stateful operations...")
    client_a = HoneypotMCPClient(storage_path=storage_path, global_singleton_mode=True)
    await client_a.connect()
    
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    cwd = "/root"
    
    for i, op in enumerate(ops):
        cmd = op["implant"]
        messages.append({"role": "user", "content": f" {cmd}\t<{datetime.now()}>\n"})
        filtered = [m for m in messages if not (m["role"] == "assistant" and not m.get("content", "").strip())]
        enhanced = await build_enhanced_messages(filtered, cmd, cwd, client=client_a, ip_address=ip)
        
        resp, tok, lat = await call_llm(enhanced)
        resp_content = resp if resp.strip() else "[no output]"
        messages.append({"role": "assistant", "content": resp_content})
        
        implant_tokens += tok
        implant_latency += lat
        
        # Record to MCP
        et = analyzer.determine_event_type(cmd)
        st = analyzer.determine_status(cmd, resp)
        sc = analyzer.analyze_state_changes(cmd, resp, cwd=cwd)
        await client_a.record_event(
            ip_address=ip, session_id=f"session_a_N{n}",
            command=cmd, user_context="root",
            event_type=et.value if hasattr(et, 'value') else str(et),
            status=st.value if hasattr(st, 'value') else str(st),
            stdout=resp,
            state_changes=[{"target": s.target, "change_type": s.change_type,
                           "old_value": s.old_value, "new_value": s.new_value,
                           "metadata": s.metadata} for s in sc] if sc else []
        )
        
        if (i + 1) % 10 == 0 or i == n - 1:
            print(f"    Implanted {i+1}/{n} ({tok}tok, {lat:.0f}ms)")
        
        await asyncio.sleep(0.5)
    
    await client_a.close()
    print(f"  [Session A] ✓ Disconnected ({implant_tokens} tokens, {implant_latency/1000:.1f}s)")
    
    # ==================== Session B: Verify all N operations ====================
    await asyncio.sleep(1)
    print(f"\n  [Session B] Verifying {n} states...")
    client_b = HoneypotMCPClient(storage_path=storage_path, global_singleton_mode=True)
    await client_b.connect()
    
    messages_b = [{"role": "system", "content": SYSTEM_PROMPT}]
    details = []
    spr_count = 0
    sfr_count = 0
    
    for i, op in enumerate(ops):
        cmd = op["verify"]
        keyword = op["keyword"]
        
        messages_b.append({"role": "user", "content": f" {cmd}\t<{datetime.now()}>\n"})
        filtered_b = [m for m in messages_b if not (m["role"] == "assistant" and not m.get("content", "").strip())]
        enhanced_b = await build_enhanced_messages(filtered_b, cmd, "/root", client=client_b, ip_address=ip)
        
        resp, tok, lat = await call_llm(enhanced_b)
        resp_content = resp if resp.strip() else "[no output]"
        messages_b.append({"role": "assistant", "content": resp_content})
        
        verify_tokens += tok
        verify_latency += lat
        
        # Check SPR: no error patterns
        error_patterns = ["no such", "not found", "does not exist", "no crontab", "command not found"]
        has_error = any(p in resp.lower() for p in error_patterns)
        spr_pass = not has_error and len(resp.strip()) > 2
        
        # Check SFR: keyword present
        sfr_pass = keyword.lower() in resp.lower()
        
        if spr_pass:
            spr_count += 1
        if sfr_pass:
            sfr_count += 1
        
        detail = {
            "op_index": i,
            "type": op["type"],
            "keyword": keyword,
            "spr": spr_pass,
            "sfr": sfr_pass,
            "response_preview": resp[:80],
        }
        details.append(detail)
        
        # Record
        et = analyzer.determine_event_type(cmd)
        await client_b.record_event(
            ip_address=ip, session_id=f"session_b_N{n}",
            command=cmd, user_context="root",
            event_type=et.value if hasattr(et, 'value') else str(et),
            status="SUCCESS", stdout=resp, state_changes=[]
        )
        
        if (i + 1) % 10 == 0 or i == n - 1:
            print(f"    Verified {i+1}/{n} (SPR: {spr_count}/{i+1}, SFR: {sfr_count}/{i+1})")
        
        await asyncio.sleep(0.5)
    
    await client_b.close()
    
    spr = spr_count / n if n > 0 else 0
    sfr = sfr_count / n if n > 0 else 0
    total_tokens = implant_tokens + verify_tokens
    
    print(f"\n  Results: SPR={spr:.0%} ({spr_count}/{n}), SFR={sfr:.0%} ({sfr_count}/{n})")
    print(f"  Tokens: implant={implant_tokens}, verify={verify_tokens}, total={total_tokens}")
    print(f"  Latency: implant={implant_latency/1000:.1f}s, verify={verify_latency/1000:.1f}s")
    
    return AccumulationResult(
        n_operations=n,
        implant_count=n,
        verify_count=n,
        spr=spr,
        sfr=sfr,
        implant_tokens=implant_tokens,
        verify_tokens=verify_tokens,
        total_tokens=total_tokens,
        implant_latency_ms=implant_latency,
        verify_latency_ms=verify_latency,
        per_operation_details=details,
    )


async def main():
    print(f"{'#'*60}")
    print(f"  State Accumulation Experiment")
    print(f"  Addressing Reviewer 55A: stateful effects scalability")
    print(f"  Model: {AI_MODEL}")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'#'*60}")
    
    storage_base = "./accumulation_test_memory"
    if os.path.exists(storage_base):
        shutil.rmtree(storage_base)
    
    # Test with increasing N
    N_VALUES = [5, 10, 20, 30, 50]
    results = []
    
    for n in N_VALUES:
        r = await run_accumulation_test(n, storage_base)
        results.append(r)
    
    # Summary Table
    print(f"\n{'='*70}")
    print(f"  STATE ACCUMULATION EXPERIMENT — SUMMARY")
    print(f"{'='*70}")
    print(f"{'N':>5} {'SPR':>8} {'SFR':>8} {'Tokens':>10} {'Latency(s)':>12}")
    print(f"{'-'*5} {'-'*8} {'-'*8} {'-'*10} {'-'*12}")
    for r in results:
        print(f"{r.n_operations:>5} {r.spr:>7.0%} {r.sfr:>7.0%} {r.total_tokens:>10,} {(r.implant_latency_ms+r.verify_latency_ms)/1000:>11.1f}")
    
    # Save report
    report = {
        "meta": {
            "experiment": "State Accumulation",
            "description": "Scalability of PromptShield with growing stateful effects",
            "reviewer_response": "55A: accumulated stateful effects experiment",
            "model": AI_MODEL,
            "test_time": datetime.now().isoformat(),
            "n_values": N_VALUES,
        },
        "results": [asdict(r) for r in results],
    }
    fname = f"accumulation_experiment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  📄 Report: {fname}")


if __name__ == "__main__":
    asyncio.run(main())
