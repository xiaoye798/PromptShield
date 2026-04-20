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

from attack_replay_test import (
    ATTACK_SCENARIOS, AttackResult, call_llm, run_attack_scenario,
    SYSTEM_PROMPT, check_semantic_verification,
    ai_client, AI_MODEL,
)
from attack_replay_extended import EXTENDED_SCENARIOS
from command_mutator import (
    generate_k_variants, mutate_command_list,
    MutationRecord, SCENARIO_MUTATION_CLASS,
)
from mcp_client import HoneypotMCPClient
from mcp_state_manager.command_analyzer import CommandAnalyzer
from LinuxSSHbot_mcp import build_enhanced_messages


@dataclass
class MutatedAttackResult:
    """Result of running a single mutated variant of a scenario."""
    scenario_id: str
    name: str
    variant_index: int
    mutations_applied: List[Dict] = field(default_factory=list)
    original_commands: List[str] = field(default_factory=list)
    mutated_commands: List[str] = field(default_factory=list)
    session_a_responses: List[Dict] = field(default_factory=list)
    session_b_responses: List[Dict] = field(default_factory=list)
    # Keyword verification (original)
    keyword_passed: Optional[bool] = None
    keywords_found: List[str] = field(default_factory=list)
    keywords_missing: List[str] = field(default_factory=list)
    # Semantic verification (mutation-tolerant)
    semantic_passed: Optional[bool] = None
    semantic_checks_detail: List[Dict] = field(default_factory=list)
    total_tokens: int = 0
    total_latency_ms: float = 0
    error: Optional[str] = None


async def run_mutated_scenario(
    scenario: dict,
    mutated_cmds: List[str],
    mutations: List[MutationRecord],
    variant_index: int,
    storage_base: str,
) -> MutatedAttackResult:
    """Run a scenario with mutated Session_A commands."""
    sid = scenario["id"]
    print(f"\n{'='*60}")
    print(f"  [{sid}] Variant {variant_index+1}: {scenario['name']}")
    print(f"  Mutations: {len(mutations)}")
    for m in mutations:
        print(f"    [{m.operator}] {m.description}")
    print(f"{'='*60}")

    result = MutatedAttackResult(
        scenario_id=sid, name=scenario["name"], variant_index=variant_index,
        mutations_applied=[asdict(m) for m in mutations],
        original_commands=scenario["session_a_commands"],
        mutated_commands=mutated_cmds,
    )

    storage_path = os.path.join(storage_base, f"{sid}_v{variant_index}")
    if os.path.exists(storage_path):
        shutil.rmtree(storage_path)
    os.makedirs(os.path.join(storage_path, "states"), exist_ok=True)
    os.makedirs(os.path.join(storage_path, "graphs"), exist_ok=True)

    analyzer = CommandAnalyzer()
    ip = f"attacker_{sid}_v{variant_index}"

    try:
        # Session A: Execute MUTATED commands
        print(f"\n  [Session A] Executing MUTATED commands...")
        client_a = HoneypotMCPClient(storage_path=storage_path, global_singleton_mode=True)
        await client_a.connect()

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        cwd = "/root"

        for cmd in mutated_cmds:
            messages.append({"role": "user", "content": f" {cmd}\t<{datetime.now()}>\n"})
            filtered = [m for m in messages if not (m["role"] == "assistant" and not m.get("content", "").strip())]
            enhanced = await build_enhanced_messages(filtered, cmd, cwd, client=client_a, ip_address=ip)
            resp, tok, lat = await call_llm(enhanced)
            resp_content = resp if resp.strip() else "[no output]"
            messages.append({"role": "assistant", "content": resp_content})

            result.session_a_responses.append({
                "cmd": cmd[:80], "response": resp[:200],
                "tokens": tok, "latency_ms": lat,
            })
            result.total_tokens += tok
            result.total_latency_ms += lat

            # Record to MCP
            et = analyzer.determine_event_type(cmd)
            st = analyzer.determine_status(cmd, resp)
            sc = analyzer.analyze_state_changes(cmd, resp, cwd=cwd)
            await client_a.record_event(
                ip_address=ip, session_id=f"session_a_{sid}_v{variant_index}",
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

            print(f"    A> {cmd[:60]}... → ({tok}tok, {lat:.0f}ms)")
            await asyncio.sleep(1)

        await client_a.close()
        print(f"  [Session A] OK Disconnected")

        # Session B: Verify with ORIGINAL commands
        if scenario.get("persistence_check") and scenario["session_b_commands"]:
            await asyncio.sleep(1)
            print(f"\n  [Session B] Verifying persistence (original commands)...")
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

                result.session_b_responses.append({
                    "cmd": cmd[:80], "response": resp[:200],
                    "tokens": tok, "latency_ms": lat,
                })
                result.total_tokens += tok
                result.total_latency_ms += lat

                await client_b.record_event(
                    ip_address=ip, session_id=f"session_b_{sid}_v{variant_index}",
                    command=cmd, user_context="root",
                    event_type=analyzer.determine_event_type(cmd).value
                        if hasattr(analyzer.determine_event_type(cmd), 'value')
                        else str(analyzer.determine_event_type(cmd)),
                    status="success", stdout=resp, state_changes=[],
                )

                print(f"    B> {cmd[:60]}... → ({tok}tok, {lat:.0f}ms)")
                await asyncio.sleep(1)

            await client_b.close()

            # Keyword verification (original strict check)
            verify_kw = scenario.get("verify_keywords", [])
            all_b_text = " ".join([r["response"] for r in result.session_b_responses]).lower()
            for kw in verify_kw:
                if kw.lower() in all_b_text:
                    result.keywords_found.append(kw)
                else:
                    result.keywords_missing.append(kw)
            result.keyword_passed = len(result.keywords_missing) == 0

            # Semantic verification (mutation-tolerant)
            verify_sem = scenario.get("verify_semantic")
            if verify_sem:
                all_b_raw = " ".join([r["response"] for r in result.session_b_responses])
                sem_passed, sem_details = check_semantic_verification(all_b_raw, verify_sem)
                result.semantic_passed = sem_passed
                result.semantic_checks_detail = sem_details

            kw_status = "PASS" if result.keyword_passed else "FAIL"
            sem_status = "PASS" if result.semantic_passed else ("FAIL" if result.semantic_passed is not None else "N/A")
            print(f"\n  Keyword: {kw_status}  |  Semantic: {sem_status}")
            if result.keywords_missing:
                print(f"    Missing keywords: {result.keywords_missing}")

    except Exception as e:
        result.error = str(e)
        print(f"  ERROR: {e}")
        import traceback; traceback.print_exc()

    return result


async def main():
    K = 3  # Number of variants per scenario
    SEED = 42

    all_scenarios = ATTACK_SCENARIOS + EXTENDED_SCENARIOS
    # Filter to persistence-eligible scenarios only
    persistence_scenarios = [
        s for s in all_scenarios if s.get("persistence_check", False)
    ]

    print(f"{'#'*60}")
    print(f"  PromptShield Mutated Attack Replay Test")
    print(f"  Persistence Scenarios: {len(persistence_scenarios)}")
    print(f"  Variants per scenario: K={K}")
    print(f"  Total test runs: {len(persistence_scenarios) * K}")
    print(f"  Model: {AI_MODEL}")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'#'*60}")

    storage_base = "./mutated_replay_memory"
    if os.path.exists(storage_base):
        shutil.rmtree(storage_base)

    all_results = []

    for scenario in persistence_scenarios:
        sid = scenario["id"]
        cmds = scenario["session_a_commands"]

        # Generate K variants
        variants = generate_k_variants(cmds, sid, k=K, base_seed=SEED)

        for i, (mutated_cmds, mutations) in enumerate(variants):
            r = await run_mutated_scenario(
                scenario, mutated_cmds, mutations, i, storage_base
            )
            all_results.append(r)

    # ==================== Summary ====================
    print(f"\n{'='*60}")
    print(f"  MUTATED REPLAY SUMMARY")
    print(f"{'='*60}")

    # Group by scenario
    from collections import defaultdict
    by_scenario = defaultdict(list)
    for r in all_results:
        by_scenario[r.scenario_id].append(r)

    total_kw_pass = 0
    total_sem_pass = 0
    total_runs = 0

    for sid, results in by_scenario.items():
        kw_pass = sum(1 for r in results if r.keyword_passed)
        sem_pass = sum(1 for r in results if r.semantic_passed)
        n = len(results)
        total_kw_pass += kw_pass
        total_sem_pass += sem_pass
        total_runs += n

        kw_rate = kw_pass / n if n else 0
        sem_rate = sem_pass / n if n else 0
        print(f"  {sid}: KW {kw_pass}/{n} ({kw_rate:.0%})  |  Semantic {sem_pass}/{n} ({sem_rate:.0%})  — {results[0].name}")

    print(f"\n  {'='*40}")
    print(f"  Overall Keyword Pass Rate:  {total_kw_pass}/{total_runs} ({total_kw_pass/total_runs:.1%})" if total_runs else "")
    print(f"  Overall Semantic Pass Rate: {total_sem_pass}/{total_runs} ({total_sem_pass/total_runs:.1%})" if total_runs else "")
    print(f"  Total Tokens: {sum(r.total_tokens for r in all_results):,}")
    print(f"  Total Latency: {sum(r.total_latency_ms for r in all_results)/1000:.1f}s")

    # Save report
    report = {
        "meta": {
            "test_time": datetime.now().isoformat(),
            "model": AI_MODEL,
            "k_variants": K,
            "seed": SEED,
            "total_scenarios": len(persistence_scenarios),
            "total_runs": total_runs,
            "keyword_pass_rate": total_kw_pass / total_runs if total_runs else 0,
            "semantic_pass_rate": total_sem_pass / total_runs if total_runs else 0,
            "total_tokens": sum(r.total_tokens for r in all_results),
        },
        "per_scenario_summary": {
            sid: {
                "keyword_pass": sum(1 for r in results if r.keyword_passed),
                "semantic_pass": sum(1 for r in results if r.semantic_passed),
                "total_variants": len(results),
                "mutations_per_variant": [len(r.mutations_applied) for r in results],
            }
            for sid, results in by_scenario.items()
        },
        "results": [asdict(r) for r in all_results],
    }
    fname = f"mutated_replay_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  Report saved: {fname}")


if __name__ == "__main__":
    asyncio.run(main())
