#!/usr/bin/env python3
"""
MemGPT Baseline Benchmark: 24 persistence scenarios using the open-source
MemGPT framework (https://github.com/deductive-ai/MemGPT) as a memory-augmented
baseline for comparison against shelLM, Beelzebub, and PromptShield.

MemGPT manages its own three-tier memory hierarchy:
  - Core memory (always in context): persona + human blocks
  - Recall memory (conversation history): searchable message database
  - Archival memory (infinite storage): vector-indexed long-term store

We configure MemGPT with DeepSeek as the LLM backend and a Linux terminal
persona matching the other baselines' system prompt.
"""

import json
import os
import re
import sys
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Prevent HuggingFace Hub network calls (model is cached locally)
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import dotenv_values

# Import shared scenarios and metrics from the existing benchmarks
from appendix_benchmark import SCENARIOS, SYSTEM_PROMPT, NOISE_COMMANDS, compute_kr, compute_sfs
from real_baseline_benchmark import (
    compute_spr,
    compute_implant_viability,
    generate_noise_commands,
    SPR_DENIAL_PATTERNS,
)

# ==================== Config ====================
_env = dotenv_values(os.path.join(os.path.dirname(__file__), "..", ".env"))
_secrets = dotenv_values(os.path.join(os.path.dirname(__file__), "..", ".env.secrets"))

def _cfg(k, d=""):
    return os.environ.get(k) or _secrets.get(k) or _env.get(k, d)

DEEPSEEK_API_KEY = _cfg("DEEPSEEK_API_KEY")
DEEPSEEK_BASE_URL = _cfg("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = _cfg("DEEPSEEK_MODEL", "deepseek-chat")
MEMGPT_CONTEXT_WINDOW = int(_cfg("MEMGPT_CONTEXT_WINDOW", "128000"))

# Set env vars for MemGPT's OpenAI-compatible client
os.environ["OPENAI_API_KEY"] = DEEPSEEK_API_KEY
os.environ["OPENAI_API_BASE"] = DEEPSEEK_BASE_URL.rstrip("/") + "/v1"

N_REPS = 3
TAU_SECONDS = 30  # SFS latency threshold

# ==================== MemGPT Persona & System ====================
MEMGPT_PERSONA_TEXT = (
    "I am a Linux OS terminal running Ubuntu 22.04.\n"
    "I act and respond exactly as a Linux terminal would.\n"
    "I respond to all commands just as a Linux terminal would.\n"
    "I only reply with the CLI output, and nothing else.\n"
    "I do not explain my output. I do not repeat commands the user inputs.\n"
    "My every output ends with a prompt like root@prod-server-01:~#\n"
    "Current user: root (uid=0, full privileges). Hostname: prod-server-01.\n"
    "This is a production server in an IT company."
)

MEMGPT_HUMAN_TEXT = (
    "The user is a system administrator connecting via SSH."
)

MEMGPT_SYSTEM_PROMPT = (
    "You are a Linux terminal simulator. When the user types commands, "
    "reply ONLY with terminal output using the send_message function. "
    "ALWAYS end output with root@prod-server-01:~# prompt. "
    "Never explain anything. Never chat conversationally.\n\n"
    "Memory instructions:\n"
    "Use core_memory_append to remember important state changes "
    "(e.g., users created, files written, services started, cron jobs added).\n"
    "Use archival_memory_insert to store detailed records of system changes.\n"
    "When the user queries something done previously, search your memories "
    "to provide accurate responses reflecting the actual system state."
)


# ==================== MemGPT Agent Wrapper ====================
class MemGPTBenchmarkAgent:
    """Wraps MemGPT LocalClient for benchmark usage."""

    def __init__(self, context_window: int = MEMGPT_CONTEXT_WINDOW):
        from memgpt.client.client import LocalClient
        self.client = LocalClient(auto_save=False, debug=False)
        self.agent_id = None
        self.agent_name = None
        self.total_tokens = 0
        self.total_latency_ms = 0.0
        self.context_window = context_window

    def create_agent(self):
        """Create a fresh MemGPT agent configured with DeepSeek backend."""
        from memgpt.memory import ChatMemory
        from memgpt.data_types import LLMConfig, EmbeddingConfig

        memory = ChatMemory(
            persona=MEMGPT_PERSONA_TEXT,
            human=MEMGPT_HUMAN_TEXT,
            limit=2000,
        )

        agent_name = f"bench-{uuid.uuid4().hex[:8]}"
        agent_state = self.client.create_agent(
            name=agent_name,
            memory=memory,
            system_prompt=MEMGPT_SYSTEM_PROMPT,
            llm_config=LLMConfig(
                model=DEEPSEEK_MODEL,
                model_endpoint_type="openai",
                model_endpoint=DEEPSEEK_BASE_URL.rstrip("/") + "/v1",
                context_window=self.context_window,
            ),
            embedding_config=EmbeddingConfig(
                embedding_endpoint_type="local",
                embedding_model="BAAI/bge-small-en-v1.5",
                embedding_dim=384,
                embedding_chunk_size=300,
            ),
        )
        self.agent_id = agent_state.id
        self.agent_name = agent_state.name
        self.total_tokens = 0
        self.total_latency_ms = 0.0

    def step(self, user_input: str, _retries: int = 1) -> str:
        """Send a command and get the terminal response. Retries once on timeout."""
        start = time.time()
        try:
            response = self.client.user_message(
                agent_id=self.agent_id,
                message=user_input,
            )
        except Exception as e:
            latency_ms = (time.time() - start) * 1000
            self.total_latency_ms += latency_ms
            err_str = str(e).lower()
            if _retries > 0 and ("timeout" in err_str or "timed out" in err_str):
                print(f" [timeout, retry]", end="", flush=True)
                time.sleep(2)
                return self.step(user_input, _retries=_retries - 1)
            raise RuntimeError(f"MemGPT user_message failed: {str(e)[:200]}") from e

        latency_ms = (time.time() - start) * 1000
        self.total_latency_ms += latency_ms

        # Extract tokens from usage stats
        if response.usage:
            self.total_tokens += response.usage.total_tokens

        # Extract the assistant_message from MemGPT's response messages
        return self._extract_response(response.messages)

    def _extract_response(self, messages: list) -> str:
        """Extract the terminal response from MemGPT's message list.

        MemGPT returns messages like:
          [{"internal_monologue": "..."}, {"function_call": "send_message(...)"},
           {"assistant_message": "root\\nroot@prod-server-01:~#"}, ...]
        The assistant_message field contains the actual output.
        """
        for msg in messages:
            if isinstance(msg, dict) and "assistant_message" in msg:
                return msg["assistant_message"]
        # Fallback: look for function_call with send_message
        for msg in messages:
            if isinstance(msg, dict):
                fc = msg.get("function_call", "")
                if "send_message" in str(fc):
                    try:
                        match = re.search(r"'message':\s*'(.*?)'", str(fc))
                        if match:
                            return match.group(1)
                    except Exception:
                        pass
        return ""

    def cleanup(self):
        """Delete the agent to free resources."""
        if self.agent_id:
            try:
                self.client.delete_agent(self.agent_id)
            except Exception:
                pass


# ==================== Benchmark Runner ====================
def run_memgpt_scenario(
    scenario: Dict,
    noise_level: int = 0,
    context_window: int = MEMGPT_CONTEXT_WINDOW,
) -> Tuple[List[Dict], List[Dict], int, float]:
    """Run a single scenario through MemGPT.

    Session A: implant commands (+ optional noise)
    Session B: verification commands (same agent, cross-session via MemGPT memory)
    """
    agent = MemGPTBenchmarkAgent(context_window=context_window)
    agent.create_agent()

    noise_injected = 0
    noise_failed = False
    try:
        a_responses = []

        # Session A: implant commands
        for command in scenario["session_a"]:
            response = agent.step(command)
            a_responses.append({
                "cmd": command[:120],
                "response": response[:500],
            })
            time.sleep(0.5)  # Rate limit

        # Optional noise injection between sessions
        if noise_level > 0:
            noise_cmds = generate_noise_commands(noise_level)
            for i, noise_cmd in enumerate(noise_cmds):
                try:
                    agent.step(noise_cmd)
                    noise_injected += 1
                except RuntimeError:
                    # Context overflow during noise — stop injecting but
                    # continue to Session B to test archival memory recall
                    noise_failed = True
                    print(
                        f"\n    [Noise overflow at cmd {i+1}/{len(noise_cmds)}, "
                        f"proceeding to Session B]"
                    )
                    break
                time.sleep(0.3)

        # Simulate session boundary
        try:
            agent.step(
                "[System: The previous SSH session has ended. A new SSH session "
                "has started from the same IP address. The user is reconnecting.]"
            )
        except RuntimeError:
            pass  # context still full — proceed to Session B anyway

        b_responses = []
        for command in scenario["session_b"]:
            try:
                response = agent.step(command)
            except RuntimeError:
                response = ""
            b_responses.append({
                "cmd": command[:120],
                "response": response[:500],
            })
            time.sleep(0.5)

        return a_responses, b_responses, agent.total_tokens, agent.total_latency_ms
    finally:
        agent.cleanup()


def run_benchmark(
    scenarios: List[Dict],
    n_reps: int = N_REPS,
    noise_level: int = 0,
    rows: Optional[List[int]] = None,
    context_window: int = MEMGPT_CONTEXT_WINDOW,
    checkpoint_callback=None,
) -> List[Dict]:
    """Run the full MemGPT benchmark across all scenarios."""
    noise_tag = f" [Noise-{noise_level}]" if noise_level > 0 else ""
    print("\n" + "#" * 60)
    print(f"  MemGPT Baseline{noise_tag} | Scenarios: {len(scenarios)} | Reps: {n_reps}")
    print("#" * 60)

    results = []
    for scenario in scenarios:
        if rows and scenario["row"] not in rows:
            continue

        row_results = []
        for rep in range(n_reps):
            print(
                f"  [MemGPT{noise_tag}] Row {scenario['row']:2d} "
                f"({scenario['label']}) rep {rep + 1}/{n_reps}...",
                end=" ",
                flush=True,
            )
            try:
                a_resp, b_resp, tokens, latency_ms = run_memgpt_scenario(
                    scenario,
                    noise_level=noise_level,
                    context_window=context_window,
                )
                kr = compute_kr(b_resp, scenario["keywords"])
                sfs = compute_sfs(kr, latency_ms)
                implant_viable = compute_implant_viability(a_resp)
                strict_kr = kr if implant_viable else 0.0
                strict_sfs = compute_sfs(strict_kr, latency_ms)
                spr = compute_spr(b_resp)

                row_results.append({
                    "rep": rep + 1,
                    "kr": round(kr, 4),
                    "sfs": round(sfs, 4),
                    "implant_viable": implant_viable,
                    "strict_kr": round(strict_kr, 4),
                    "strict_sfs": round(strict_sfs, 4),
                    "spr": round(spr, 4),
                    "tokens": tokens,
                    "latency_ms": round(latency_ms, 1),
                    "session_a_responses": a_resp,
                    "session_b_responses": b_resp,
                })
                print(
                    f"KR={kr:.2f} SFS={sfs:.2f} | StrictKR={strict_kr:.2f} "
                    f"({tokens}tok, {latency_ms:.0f}ms)"
                )
            except Exception as exc:
                import traceback
                traceback.print_exc()
                print(f"ERROR: {str(exc)[:120]}")
                row_results.append({
                    "rep": rep + 1,
                    "kr": 0.0,
                    "sfs": 0.0,
                    "implant_viable": False,
                    "strict_kr": 0.0,
                    "strict_sfs": 0.0,
                    "spr": 0.0,
                    "error": str(exc)[:200],
                })

        avg_kr = sum(r["kr"] for r in row_results) / max(len(row_results), 1)
        avg_sfs = sum(r["sfs"] for r in row_results) / max(len(row_results), 1)
        avg_strict_kr = sum(r["strict_kr"] for r in row_results) / max(len(row_results), 1)
        avg_strict_sfs = sum(r["strict_sfs"] for r in row_results) / max(len(row_results), 1)
        avg_spr = sum(r["spr"] for r in row_results) / max(len(row_results), 1)

        results.append({
            "row": scenario["row"],
            "label": scenario["label"],
            "avg_kr": round(avg_kr, 4),
            "avg_sfs": round(avg_sfs, 4),
            "avg_strict_kr": round(avg_strict_kr, 4),
            "avg_strict_sfs": round(avg_strict_sfs, 4),
            "avg_spr": round(avg_spr, 4),
            "reps": row_results,
        })
        print(
            f"  --> Row {scenario['row']} Avg KR={avg_kr:.2f}, "
            f"Avg StrictKR={avg_strict_kr:.2f}, Avg SFS={avg_sfs:.2f}"
        )
        if checkpoint_callback is not None:
            checkpoint_callback(results)

    return results


def save_report(report: Dict, noise_level: int = 0, filename: Optional[str] = None, announce: bool = True) -> str:
    """Save benchmark results to a JSON report file."""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        noise_tag = f"_noise{noise_level}" if noise_level > 0 else ""
        filename = f"memgpt_benchmark_report{noise_tag}_{timestamp}.json"
    filepath = os.path.join(os.path.dirname(__file__), filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    if announce:
        print(f"\nReport saved to: {filepath}")
    return filepath


def main():
    import argparse

    parser = argparse.ArgumentParser(description="MemGPT Baseline Benchmark")
    parser.add_argument("--noise", type=int, default=0, help="Noise level (0, 100)")
    parser.add_argument("--reps", type=int, default=N_REPS, help="Number of repetitions")
    parser.add_argument("--rows", type=str, default="", help="Comma-separated row numbers (default: all)")
    parser.add_argument("--dry-run", action="store_true", help="Test with first scenario only")
    parser.add_argument("--context-window", type=int, default=MEMGPT_CONTEXT_WINDOW, help="MemGPT/LLM context window")
    args = parser.parse_args()

    rows = [int(r.strip()) for r in args.rows.split(",") if r.strip()] if args.rows else None
    scenarios = SCENARIOS

    if args.dry_run:
        scenarios = scenarios[:1]
        args.reps = 1
        print("DRY RUN: Testing with first scenario only, 1 rep")

    print(f"MemGPT Baseline Benchmark")
    print(f"  Model: {DEEPSEEK_MODEL} via {DEEPSEEK_BASE_URL}")
    print(f"  Scenarios: {len(scenarios)}")
    print(f"  Noise level: {args.noise}")
    print(f"  Reps: {args.reps}")
    print(f"  Context window: {args.context_window}")

    partial_filename = (
        f"memgpt_benchmark_partial_noise{args.noise}.json"
        if args.noise > 0
        else "memgpt_benchmark_partial.json"
    )

    def checkpoint_callback(partial_results: List[Dict]) -> None:
        partial_report = {
            "system": "memgpt",
            "memgpt_version": "0.3.25",
            "model": DEEPSEEK_MODEL,
            "noise_level": args.noise,
            "n_reps": args.reps,
            "context_window": args.context_window,
            "timestamp": datetime.now().isoformat(),
            "partial": True,
            "completed_rows": [row_result["row"] for row_result in partial_results],
            "results": partial_results,
        }
        save_report(partial_report, noise_level=args.noise, filename=partial_filename, announce=False)

    results = run_benchmark(
        scenarios=scenarios,
        n_reps=args.reps,
        noise_level=args.noise,
        rows=rows,
        context_window=args.context_window,
        checkpoint_callback=checkpoint_callback,
    )

    report = {
        "system": "memgpt",
        "memgpt_version": "0.3.25",
        "model": DEEPSEEK_MODEL,
        "noise_level": args.noise,
        "n_reps": args.reps,
        "context_window": args.context_window,
        "timestamp": datetime.now().isoformat(),
        "results": results,
    }

    save_report(report, noise_level=args.noise)

    # Print summary
    if results:
        overall_kr = sum(r["avg_kr"] for r in results) / len(results)
        overall_strict_kr = sum(r["avg_strict_kr"] for r in results) / len(results)
        overall_sfs = sum(r["avg_sfs"] for r in results) / len(results)
        overall_spr = sum(r["avg_spr"] for r in results) / len(results)
        print(f"\n{'='*60}")
        print(f"  SUMMARY -- MemGPT Baseline (noise={args.noise})")
        print(f"  Avg KR:       {overall_kr:.4f}")
        print(f"  Avg StrictKR: {overall_strict_kr:.4f}")
        print(f"  Avg SFS:      {overall_sfs:.4f}")
        print(f"  Avg SPR:      {overall_spr:.4f}")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()
