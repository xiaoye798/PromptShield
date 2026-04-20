#!/usr/bin/env python3

import asyncio
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import openai
import yaml
from dotenv import dotenv_values

from appendix_benchmark import NOISE_COMMANDS, SCENARIOS, SYSTEM_PROMPT, compute_kr, compute_sfs, run_promptshield


_ENV = dotenv_values(os.path.join(os.path.dirname(__file__), "..", ".env"))
_SECRETS = dotenv_values(os.path.join(os.path.dirname(__file__), "..", ".env.secrets"))


def _cfg(key: str, default: str = "") -> str:
    return os.environ.get(key) or _SECRETS.get(key) or _ENV.get(key, default)


DEEPSEEK_API_KEY = _cfg("DEEPSEEK_API_KEY")
DEEPSEEK_BASE_URL = _cfg("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
AI_MODEL = _cfg("DEEPSEEK_MODEL", "deepseek-chat")
N_REPS = 3

BEELZEBUB_SYSTEM_PROMPT = (
    "You will act as an Ubuntu Linux terminal. The user will type commands, and you are to reply with what the terminal should show. "
    "Your responses must be contained within a single code block. Do not provide note. Do not provide explanations or type commands "
    "unless explicitly instructed by the user. Your entire response/output is going to consist of a simple text with \\n for new line, "
    "and you will NOT wrap it within string md markers"
)

SHELLM_RESUME_MARKER = (
    "\nHere the session stopped. Now you will start it again from the beginning with the same user. "
    "You must respond just with starting message and nothing more. Make sure you use same file and folder names. "
    "Ignore date-time in <>. This is not your concern.\n"
)

SHELLM_STARTER_SUFFIX = (
    "\nBased on these examples make something of your own (different username and hostname) to be a starting message. "
    "Always start the communication in this way and make sure your output ends with '$'. For the last login date use {today}\n"
    "Ignore date-time in <> after user input. This is not your concern.\n"
)

SPR_DENIAL_PATTERNS = [
    "no such user", "command not found", "not found",
    "no such file or directory", "does not exist",
    "permission denied", "cannot access",
    "error:", "unrecognized",
]

CODE_FENCE_RE = re.compile(r"```( *)?([a-zA-Z0-9_-]+)?(\\n)?")
IMPLANT_FAILURE_PATTERNS = [
    "permission denied",
    "no such user",
    "authentication token manipulation error",
    "error detected",
    "failed",
    "command not found",
    "not found",
]

ai_client = openai.AsyncOpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL)


def generate_noise_commands(n: int = 100) -> List[str]:
    commands: List[str] = []
    pool = list(NOISE_COMMANDS)
    while len(commands) < n:
        random.shuffle(pool)
        commands.extend(pool)
    return commands[:n]


async def call_llm(messages: List[Dict[str, str]], retries: int = 3) -> Tuple[str, int, float]:
    for attempt in range(retries):
        try:
            start = time.time()
            response = await ai_client.chat.completions.create(
                model=AI_MODEL,
                messages=messages,
                temperature=0.0,
                max_tokens=800,
            )
            latency_ms = (time.time() - start) * 1000
            text = response.choices[0].message.content or ""
            tokens = response.usage.total_tokens if response.usage else 0
            return text, tokens, latency_ms
        except Exception:
            if attempt == retries - 1:
                raise
            await asyncio.sleep(2 ** (attempt + 1))
    return "", 0, 0.0


def strip_beelzebub_output(content: str) -> str:
    cleaned = CODE_FENCE_RE.sub("", content)
    return cleaned.replace("```", "").strip()


# shelLM now uses the same root SYSTEM_PROMPT as PromptShield for fair comparison.
# Original shelLM personality (non-root brian@biolab) caused 54% implant failures.
SHELLM_SYSTEM_PROMPT = SYSTEM_PROMPT


@dataclass
class ShellMSessionState:
    history_text: str = ""
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    messages: List[Dict[str, str]] = field(default_factory=list)

    def build_system_prompt(self, prompt_body: str) -> str:
        return (
            prompt_body
            + SHELLM_STARTER_SUFFIX.format(today=datetime.now())
        )

    async def start_session(self) -> str:
        if not self.history_text:
            system_prompt = self.build_system_prompt(SHELLM_SYSTEM_PROMPT)
            self.history_text += system_prompt
        else:
            self.history_text += SHELLM_RESUME_MARKER
            system_prompt = self.build_system_prompt(self.history_text)
            self.history_text += "The session continues in following lines.\n\n"

        self.messages = [{"role": "system", "content": system_prompt}]
        text, tokens, latency_ms = await call_llm(self.messages)
        self.messages.append({"role": "assistant", "content": text})
        self.history_text += text
        self.total_tokens += tokens
        self.total_latency_ms += latency_ms
        return text

    async def run_command(self, command: str) -> Dict[str, object]:
        user_message = f" {command}\t<{datetime.now()}>\n"
        self.messages.append({"role": "user", "content": user_message})
        self.history_text += user_message

        text, tokens, latency_ms = await call_llm(self.messages)
        if "$cd" in text or "$ cd" in text:
            parts = text.split("\n")
            if len(parts) > 1:
                text = parts[1]

        self.messages.append({"role": "assistant", "content": text})
        self.history_text += text
        self.total_tokens += tokens
        self.total_latency_ms += latency_ms

        return {
            "cmd": command[:120],
            "response": text[:500],
            "tokens": tokens,
            "latency_ms": latency_ms,
        }


@dataclass
class HistoryEvent:
    last_seen: float
    messages: List[Dict[str, str]]


class BeelzebubHistoryStore:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self.sessions: Dict[str, HistoryEvent] = {}

    def _cleanup(self) -> None:
        now = time.time()
        expired = [key for key, event in self.sessions.items() if now - event.last_seen > self.ttl_seconds]
        for key in expired:
            del self.sessions[key]

    def has_key(self, key: str) -> bool:
        self._cleanup()
        return key in self.sessions

    def query(self, key: str) -> List[Dict[str, str]]:
        self._cleanup()
        event = self.sessions.get(key)
        return list(event.messages) if event else []

    def append(self, key: str, *messages: Dict[str, str]) -> None:
        self._cleanup()
        event = self.sessions.get(key)
        if event is None:
            event = HistoryEvent(last_seen=time.time(), messages=[])
        event.last_seen = time.time()
        event.messages.extend(messages)
        self.sessions[key] = event


def build_beelzebub_prompt(command: str, histories: List[Dict[str, str]]) -> List[Dict[str, str]]:
    messages = [
        {"role": "system", "content": BEELZEBUB_SYSTEM_PROMPT},
        {"role": "user", "content": "pwd"},
        {"role": "assistant", "content": "/home/user"},
    ]
    messages.extend(histories)
    messages.append({"role": "user", "content": command})
    return messages


async def run_shellm_real(scenario: Dict[str, object], noise_level: int = 0, sandwich: bool = False) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], int, float]:
    state = ShellMSessionState()

    await state.start_session()
    a_responses: List[Dict[str, object]] = []

    if sandwich and noise_level > 0:
        half = noise_level // 2
        for noise_command in generate_noise_commands(half):
            await state.run_command(noise_command)
            await asyncio.sleep(0.2)
        for command in scenario["session_a"]:
            a_responses.append(await state.run_command(command))
            await asyncio.sleep(0.4)
        for noise_command in generate_noise_commands(noise_level - half):
            await state.run_command(noise_command)
            await asyncio.sleep(0.2)
    else:
        for command in scenario["session_a"]:
            a_responses.append(await state.run_command(command))
            await asyncio.sleep(0.4)
        if noise_level > 0:
            for noise_command in generate_noise_commands(noise_level):
                await state.run_command(noise_command)
                await asyncio.sleep(0.2)

    await state.start_session()
    b_responses: List[Dict[str, object]] = []
    for command in scenario["session_b"]:
        b_responses.append(await state.run_command(command))
        await asyncio.sleep(0.4)

    return a_responses, b_responses, state.total_tokens, state.total_latency_ms


async def run_beelzebub_real(
    scenario: Dict[str, object],
    noise_level: int = 0,
    reset_between_sessions: bool = False,
    sandwich: bool = False,
    ttl_seconds: int = 3600,
    remote_host: str = "127.0.0.1",
    user: str = "root",
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], int, float]:
    store = BeelzebubHistoryStore(ttl_seconds=ttl_seconds)
    session_key = f"SSH{remote_host}{user}"
    total_tokens = 0
    total_latency_ms = 0.0

    async def execute_command(command: str) -> Dict[str, object]:
        histories = store.query(session_key) if store.has_key(session_key) else []
        prompt = build_beelzebub_prompt(command, histories)
        text, tokens, latency_ms = await call_llm(prompt)
        text = strip_beelzebub_output(text)
        store.append(
            session_key,
            {"role": "user", "content": command},
            {"role": "assistant", "content": text},
        )
        return {
            "cmd": command[:120],
            "response": text[:500],
            "tokens": tokens,
            "latency_ms": latency_ms,
        }

    a_responses: List[Dict[str, object]] = []

    if sandwich and noise_level > 0:
        half = noise_level // 2
        for noise_command in generate_noise_commands(half):
            result = await execute_command(noise_command)
            total_tokens += result["tokens"]
            total_latency_ms += result["latency_ms"]
            await asyncio.sleep(0.2)
        for command in scenario["session_a"]:
            result = await execute_command(command)
            a_responses.append(result)
            total_tokens += result["tokens"]
            total_latency_ms += result["latency_ms"]
            await asyncio.sleep(0.4)
        for noise_command in generate_noise_commands(noise_level - half):
            result = await execute_command(noise_command)
            total_tokens += result["tokens"]
            total_latency_ms += result["latency_ms"]
            await asyncio.sleep(0.2)
    else:
        for command in scenario["session_a"]:
            result = await execute_command(command)
            a_responses.append(result)
            total_tokens += result["tokens"]
            total_latency_ms += result["latency_ms"]
            await asyncio.sleep(0.4)
        if noise_level > 0:
            for noise_command in generate_noise_commands(noise_level):
                result = await execute_command(noise_command)
                total_tokens += result["tokens"]
                total_latency_ms += result["latency_ms"]
                await asyncio.sleep(0.2)

    if reset_between_sessions:
        store = BeelzebubHistoryStore(ttl_seconds=ttl_seconds)

    b_responses: List[Dict[str, object]] = []
    for command in scenario["session_b"]:
        result = await execute_command(command)
        b_responses.append(result)
        total_tokens += result["tokens"]
        total_latency_ms += result["latency_ms"]
        await asyncio.sleep(0.4)

    return a_responses, b_responses, total_tokens, total_latency_ms


def compute_implant_viability(a_responses: List[Dict[str, object]]) -> bool:
    combined = " ".join(str(response.get("response", "")).lower() for response in a_responses)
    return not any(pattern in combined for pattern in IMPLANT_FAILURE_PATTERNS)


def compute_spr(b_responses: List[Dict[str, object]]) -> float:
    """State Persistence Rate: fraction of Session B responses without denial patterns."""
    if not b_responses:
        return 0.0
    ok = 0
    for response in b_responses:
        text = str(response.get("response", "")).lower()
        if not any(pattern in text for pattern in SPR_DENIAL_PATTERNS):
            ok += 1
    return ok / len(b_responses)


async def run_system(
    system_name: str,
    system_fn,
    scenarios: List[Dict[str, object]],
    n_reps: int,
    noise_level: int = 0,
) -> List[Dict[str, object]]:
    noise_tag = f" [Noise-{noise_level}]" if noise_level > 0 else ""
    print("\n" + "#" * 60)
    print(f"  System: {system_name}{noise_tag} | Scenarios: {len(scenarios)} | Reps: {n_reps}")
    print("#" * 60)

    system_results: List[Dict[str, object]] = []
    for scenario in scenarios:
        row_results: List[Dict[str, object]] = []
        for rep in range(n_reps):
            print(
                f"  [{system_name}{noise_tag}] Row {scenario['row']:2d} ({scenario['label']}) rep {rep + 1}/{n_reps}...",
                end=" ",
                flush=True,
            )
            try:
                a_responses, b_responses, tokens, latency_ms = await system_fn(scenario, noise_level=noise_level)
                kr = compute_kr(b_responses, scenario["keywords"])
                sfs = compute_sfs(kr, latency_ms)
                implant_viable = compute_implant_viability(a_responses)
                strict_kr = kr if implant_viable else 0.0
                strict_sfs = compute_sfs(strict_kr, latency_ms)
                spr = compute_spr(b_responses)
                row_results.append(
                    {
                        "rep": rep + 1,
                        "kr": round(kr, 4),
                        "sfs": round(sfs, 4),
                        "implant_viable": implant_viable,
                        "strict_kr": round(strict_kr, 4),
                        "strict_sfs": round(strict_sfs, 4),
                        "spr": round(spr, 4),
                        "tokens": tokens,
                        "latency_ms": round(latency_ms, 1),
                        "session_a_responses": a_responses,
                        "session_b_responses": b_responses,
                    }
                )
                print(
                    f"KR={kr:.2f} SFS={sfs:.2f} | StrictKR={strict_kr:.2f} StrictSFS={strict_sfs:.2f} "
                    f"({tokens}tok, {latency_ms:.0f}ms)"
                )
            except Exception as exc:
                print(f"ERROR: {str(exc)[:100]}")
                row_results.append(
                    {
                        "rep": rep + 1,
                        "kr": 0.0,
                        "sfs": 0.0,
                        "implant_viable": False,
                        "strict_kr": 0.0,
                        "strict_sfs": 0.0,
                        "spr": 0.0,
                        "error": str(exc)[:200],
                    }
                )

        avg_kr = sum(row["kr"] for row in row_results) / max(len(row_results), 1)
        avg_sfs = sum(row["sfs"] for row in row_results) / max(len(row_results), 1)
        avg_strict_kr = sum(row["strict_kr"] for row in row_results) / max(len(row_results), 1)
        avg_strict_sfs = sum(row["strict_sfs"] for row in row_results) / max(len(row_results), 1)
        avg_spr = sum(row["spr"] for row in row_results) / max(len(row_results), 1)
        system_results.append(
            {
                "row": scenario["row"],
                "label": scenario["label"],
                "avg_kr": round(avg_kr, 4),
                "avg_sfs": round(avg_sfs, 4),
                "avg_strict_kr": round(avg_strict_kr, 4),
                "avg_strict_sfs": round(avg_strict_sfs, 4),
                "avg_spr": round(avg_spr, 4),
                "reps": row_results,
            }
        )
        print(
            f"  --> Row {scenario['row']} Avg KR={avg_kr:.2f}, Avg SFS={avg_sfs:.2f}, "
            f"Avg StrictKR={avg_strict_kr:.2f}, Avg StrictSFS={avg_strict_sfs:.2f}"
        )

    return system_results


def parse_rows(row_arg: Optional[str]) -> List[int]:
    if not row_arg:
        return []
    rows: List[int] = []
    for token in row_arg.split(","):
        token = token.strip()
        if not token:
            continue
        rows.append(int(token))
    return rows


async def main() -> None:
    args = sys.argv[1:]
    noise_level = 0
    n_reps = N_REPS
    row_arg: Optional[str] = None
    reset_beelzebub = False
    sandwich = False

    if "--noise" in args:
        index = args.index("--noise")
        noise_level = int(args[index + 1])
        args = args[:index] + args[index + 2:]

    if "--reps" in args:
        index = args.index("--reps")
        n_reps = int(args[index + 1])
        args = args[:index] + args[index + 2:]

    if "--rows" in args:
        index = args.index("--rows")
        row_arg = args[index + 1]
        args = args[:index] + args[index + 2:]

    if "--beelzebub-reset-between-sessions" in args:
        reset_beelzebub = True
        args = [arg for arg in args if arg != "--beelzebub-reset-between-sessions"]

    if "--sandwich" in args:
        sandwich = True
        args = [arg for arg in args if arg != "--sandwich"]

    scenarios = SCENARIOS
    selected_rows = parse_rows(row_arg)
    if selected_rows:
        scenarios = [scenario for scenario in SCENARIOS if scenario["row"] in selected_rows]

    systems = {
        "shelLM": (
            lambda scenario, noise_level=0: run_shellm_real(
                scenario,
                noise_level=noise_level,
                sandwich=sandwich,
            )
        ),
        "Beelzebub": (
            lambda scenario, noise_level=0: run_beelzebub_real(
                scenario,
                noise_level=noise_level,
                reset_between_sessions=reset_beelzebub,
                sandwich=sandwich,
            )
        ),
        "PromptShield": run_promptshield,
    }

    systems_to_run = list(systems.keys())
    if args:
        systems_to_run = [name for name in args if name in systems]
        if not systems_to_run:
            print(
                "Usage: python real_baseline_benchmark.py [shelLM] [Beelzebub] [PromptShield] "
                "[--noise N] [--reps N] [--rows 2,4] [--sandwich] [--beelzebub-reset-between-sessions]"
            )
            return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results: Dict[str, object] = {}
    for system_name in systems_to_run:
        results[system_name] = await run_system(system_name, systems[system_name], scenarios, n_reps, noise_level=noise_level)

    report = {
        "meta": {
            "timestamp": timestamp,
            "model": AI_MODEL,
            "noise_level": noise_level,
            "sandwich": sandwich,
            "rows": selected_rows or "all",
            "systems": systems_to_run,
            "n_reps": n_reps,
            "beelzebub_reset_between_sessions": reset_beelzebub,
            "notes": {
                "shelLM": "Uses PromptShield root SYSTEM_PROMPT and history.txt continuation semantics.",
                "Beelzebub": "Uses real Beelzebub buildPrompt/history-store semantics with DeepSeek backend.",
                "PromptShield": "Uses existing MCP-backed implementation from appendix_benchmark.py.",
            },
        },
        "results": results,
    }

    report_path = Path(__file__).resolve().parent / f"real_baseline_benchmark_report_{timestamp}.json"
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    print(f"\nReport saved: {report_path.name}")


if __name__ == "__main__":
    asyncio.run(main())