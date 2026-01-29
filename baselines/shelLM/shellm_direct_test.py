#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
shelLM Direct Test using wexpect

This script ACTUALLY RUNS LinuxSSHbot.py using wexpect for Windows.
It properly handles the interactive terminal and tests cross-session
state persistence via the history.txt mechanism.

Usage:
    python shellm_direct_test.py --rounds 5
"""

import os
import sys
import json
import csv
import time
import argparse
import statistics
import shutil
import re
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Dict, Any
from pathlib import Path

import subprocess
import threading
import queue

# 导入噪声生成器
try:
    from noise_generator import NoiseGenerator
    NOISE_GENERATOR = NoiseGenerator()
except ImportError:
    NOISE_GENERATOR = None

# Custom Process Interaction Class to replace wexpect
class ProcessSession:
    def __init__(self, cmd, cwd):
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            text=True,
            bufsize=0,  # Unbuffered
            shell=False
        )
        self.q_out = queue.Queue()
        self.output_buffer = ""
        self.alive = True
        
        self.t_out = threading.Thread(target=self._reader, args=(self.process.stdout,))
        self.t_out.daemon = True
        self.t_out.start()
        
    def _reader(self, stream):
        try:
            while True:
                char = stream.read(1)
                if not char: break
                self.q_out.put(char)
        except:
            pass
        self.alive = False

    def expect_prompt(self, timeout=60):
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                char = self.q_out.get(timeout=0.1)
                self.output_buffer += char
            except queue.Empty:
                if not self.alive and self.process.poll() is not None:
                    raise EOFError("Process died")
                continue
            
            # Check prompt (ends with $ or #, ignoring whitespace)
            # Use raw buffer to check for prompt character
            # But strict checking might be tricky if 'last login' appears after #
            # Just check if the LAST non-whitespace char is $ or #
            stripped = self.output_buffer.strip()
            if stripped and (stripped[-1] in ['$', '#']):
                return self.output_buffer
        
        raise TimeoutError(f"Timeout waiting for prompt. Buffer: {self.output_buffer[-200:]}")

    def send_line(self, lines):
        if not self.alive:
            raise EOFError("Process died")
        self.process.stdin.write(lines + "\n")
        self.process.stdin.flush()
        # Clear buffer to capture NEW output
        self.output_buffer = ""

    def close(self):
        try:
            self.process.terminate()
        except:
            pass

# Configuration
SHELLM_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SHELLM_DIR))
LINUXSSHBOT_SCRIPT = os.path.join(SHELLM_DIR, "LinuxSSHbot.py")
HISTORY_FILE = os.path.join(SHELLM_DIR, "history.txt")
HISTORY_BACKUP = os.path.join(SHELLM_DIR, "history_backup.txt")


# ============== Data Classes ==============

@dataclass
class TestScenario:
    scenario_id: str
    mitre_id: str
    technique: str
    implant_command: str
    verify_command: str
    expected_keywords: List[str]


@dataclass
class TestResult:
    scenario_id: str
    mitre_id: str
    technique: str
    implant_success: bool
    verify_success: bool
    state_persisted: bool
    state_fidelity: bool
    state_persistent: bool
    keywords_matched: bool
    implant_response: str
    verify_response: str
    implant_latency_ms: float = 0.0
    verify_latency_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class RoundMetrics:
    round_number: int
    spr: float
    sfr: float
    pdr_high: float
    pdr_medium: float
    pdr_low: float
    avg_latency_ms: float
    total_tokens: int
    total_scenarios: int
    passed_scenarios: int


# ============== Complexity Tiers ==============

COMPLEXITY_TIERS = {
    'high': ['HC-T1543-002', 'HC-T1098-004', 'HC-T1136-001', 'HC-T1078-003'],
    'medium': ['HC-T1053-003', 'HC-T1037-004', 'HC-T1574-006', 'HC-T1556-003'],
    'low': ['HC-T1546-004', 'HC-T1505-003']
}

NEGATIVE_PATTERNS = [
    "no such file", "cannot access", "not found", "no crontab",
    "does not exist", "permission denied", "command not found",
    "no such user", "not in the sudoers",
]


# ============== History Management ==============

def clear_history():
    """Clear history.txt to start fresh."""
    # Modified: Do NOT clear history to allow accumulated conversation testing
    # with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
    #     pass
    pass  # No-op: history will be preserved


def inject_noise_to_history(noise_count: int) -> int:
    """
    向 history.txt 注入高熵噪声命令。
    
    这是 Lost-in-the-Middle 实验的核心：通过在关键命令之间
    插入大量高熵噪声，测试 LLM 对中段信息的注意力衰减。
    
    Args:
        noise_count: 噪声命令数量
        
    Returns:
        实际注入的噪声数量
    """
    if NOISE_GENERATOR is None:
        print("  WARNING: NoiseGenerator not available, skipping noise injection")
        return 0
    
    noise_content = NOISE_GENERATOR.generate_noise_for_history(noise_count)
    
    with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
        f.write("\n" + noise_content + "\n")
    
    return noise_count


def backup_history():
    """Backup current history.txt."""
    if os.path.exists(HISTORY_FILE):
        shutil.copy(HISTORY_FILE, HISTORY_BACKUP)


def restore_history():
    """Restore history.txt from backup."""
    if os.path.exists(HISTORY_BACKUP):
        shutil.copy(HISTORY_BACKUP, HISTORY_FILE)


# ============== Token Management ==============

TOKENS_FILE = os.path.join(SHELLM_DIR, "tokens.json")

def clear_tokens():
    """Clear tokens.json to start fresh token tracking."""
    if os.path.exists(TOKENS_FILE):
        os.remove(TOKENS_FILE)

def read_token_consumption():
    """Read total token consumption from tokens.json."""
    if not os.path.exists(TOKENS_FILE):
        return 0
    
    try:
        with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
            tokens_history = json.load(f)
            return sum(entry.get('total_tokens', 0) for entry in tokens_history)
    except (json.JSONDecodeError, FileNotFoundError):
        return 0


# ============== wexpect Interaction ==============

def run_shellm_session(command: str, timeout: int = 120) -> Tuple[str, float]:
    """
    Run LinuxSSHbot.py using custom subprocess wrapper and send a command.
    """
    session = None
    try:
        start_time = time.time()
        
        # Start LinuxSSHbot.py
        # Use simple python command
        cmd = [sys.executable, "-u", LINUXSSHBOT_SCRIPT]
        session = ProcessSession(cmd, cwd=SHELLM_DIR)
        
        # Wait for initial prompt
        try:
            session.expect_prompt(timeout=60)
        except TimeoutError:
            return "Error: Timeout waiting for initial prompt", 0.0
        except EOFError:
            return "Error: Process died during startup", 0.0
            
        # Send command
        try:
            session.send_line(command)
        except EOFError:
            return "Error: Process died sending command", 0.0
            
        # Wait for response prompt
        try:
            output = session.expect_prompt(timeout=timeout)
        except TimeoutError:
            return f"Error: Timeout waiting for response", 0.0
        except EOFError:
            return "Error: Process terminated unexpectedly", 0.0
            
        latency_ms = (time.time() - start_time) * 1000
        
        # Clean up response
        # Output contains: input_echo + response + prompt
        # But we cleared buffer before sending.
        # So output starts with echo?
        # self.output_buffer accumulates chars AFTER send_line called? 
        # No, ProcessSession.send_line clears output_buffer.
        # So output contains: Echo of command (line 1) + Response + Prompt (last line)
        
        clean_response = output
        # Remove prompt at end
        clean_response = clean_response.strip()
        if clean_response.endswith('$') or clean_response.endswith('#'):
             clean_response = clean_response[:-1].strip()
        
        response_lines = clean_response.split('\n')
        # Remove echo if present (first line matching command)
        if response_lines and command.strip() in response_lines[0]:
            response_lines = response_lines[1:]
            
        final_response = '\n'.join(response_lines).strip()
        
        return final_response, latency_ms

    except Exception as e:
        return f"Error: {str(e)}", 0.0
    finally:
        if session:
            session.close()


# ============== Scenario Loading ==============

# Pre-defined keywords for each scenario (fixes regex extraction bug)
# These are the actual strings that should appear in verification responses
SCENARIO_KEYWORDS = {
    'HC-T1053-003': ['socket', '4444'],           # Cron job with reverse shell
    'HC-T1543-002': ['4444', 'enabled'],          # Systemd service
    'HC-T1098-004': ['ssh-rsa', 'c2server'],      # SSH authorized keys
    'HC-T1136-001': ['sysupdate', 'sudo'],        # Local account creation
    'HC-T1546-004': ['PROMPT_COMMAND', '4444'],   # Shell config modification
    'HC-T1037-004': ['socket', '4444'],           # RC scripts
    'HC-T1505-003': ['system', 'REQUEST'],        # Web shell (PHP)
    'HC-T1574-006': ['libsystem.so'],             # LD preload hijacking
    'HC-T1556-003': ['pam_permit.so'],            # PAM backdoor
    'HC-T1078-003': ['nobody', '/bin/bash'],      # Valid accounts manipulation
}

def load_scenarios_from_csv(csv_path: str) -> List[TestScenario]:
    """Load test scenarios from HoneyComb benchmark CSV."""
    scenarios = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get('Scenario_ID'):
                continue
            
            scenario_id = row['Scenario_ID']
            # Use pre-defined keywords instead of regex extraction
            keywords = SCENARIO_KEYWORDS.get(scenario_id, ['found', 'enabled'])
            
            scenarios.append(TestScenario(
                scenario_id=scenario_id,
                mitre_id=row['MITRE_ATT&CK_ID'],
                technique=row['ATT&CK_Technique'],
                implant_command=row['Session_A_植入(Implant)'],
                verify_command=row['Session_C_触发验证(Trigger)'],
                expected_keywords=keywords
            ))
    
    return scenarios


# ============== Single Test Execution ==============

def run_single_test(scenario: TestScenario, verbose: bool = False, noise_level: int = 0, noise_position: str = "suffix", cumulative: bool = False) -> TestResult:
    """
    Run a single HoneyComb test scenario.
    
    Session A: Clear history → [inject noise] → run LinuxSSHbot.py → send implant command → terminate
    Session B: [inject noise] → Run NEW LinuxSSHbot.py (reads history.txt) → send verify command → evaluate
    
    Args:
        scenario: 测试场景
        verbose: 是否输出详细日志
        noise_level: 噪声注入强度 (0=无噪声, 10/50/100 等)
        noise_position: 噪声位置 (prefix/suffix/sandwich)
            - prefix: 噪声在关键命令之前（关键信息在末尾）
            - suffix: 噪声在关键命令之后（关键信息在开头）- 当前默认
            - sandwich: 关键命令被夹在噪声中间（触发 Lost-in-the-Middle）
    """
    if verbose:
        print(f"  Testing: {scenario.scenario_id} - {scenario.technique[:40]}...")
    
    error = None
    
    # ========== Session A: Implant Phase ==========
    # Clear history for this scenario (skip in cumulative mode)
    if not cumulative:
        clear_history()
    
    # Sandwich mode: 在植入前先注入一半噪声
    if noise_level > 0 and noise_position == "sandwich":
        half_noise = noise_level // 2
        injected = inject_noise_to_history(half_noise)
        if verbose:
            print(f"    > [Sandwich] Injected {injected} noise commands BEFORE implant")
    # Prefix mode: 在植入前注入全部噪声
    elif noise_level > 0 and noise_position == "prefix":
        injected = inject_noise_to_history(noise_level)
        if verbose:
            print(f"    > [Prefix] Injected {injected} noise commands before implant")
    
    # Run LinuxSSHbot.py and send the implant command
    implant_response, implant_latency = run_shellm_session(scenario.implant_command)
    implant_success = not implant_response.startswith("Error:")
    
    # ========== Session B: Verification Phase ==========
    # Sandwich mode: 在植入后、验证前注入另一半噪声（关键命令被夹在中间）
    if noise_level > 0 and noise_position == "sandwich":
        half_noise = noise_level - (noise_level // 2)  # 剩余的噪声
        injected = inject_noise_to_history(half_noise)
        if verbose:
            print(f"    > [Sandwich] Injected {injected} noise commands AFTER implant (key buried in middle)")
    # Suffix mode: 在验证前注入全部噪声
    elif noise_level > 0 and noise_position == "suffix":
        injected = inject_noise_to_history(noise_level)
        if verbose:
            print(f"    > [Suffix] Injected {injected} noise commands before verify")
    
    # Run NEW LinuxSSHbot.py (it will read history.txt from Session A)
    verify_response, verify_latency = run_shellm_session(scenario.verify_command)
    verify_success = not verify_response.startswith("Error:")
    
    # ========== Evaluate Results ==========
    response_lower = verify_response.lower()
    has_negative_pattern = any(neg in response_lower for neg in NEGATIVE_PATTERNS)
    
    stripped_response = verify_response.strip()
    lines = stripped_response.split('\n')
    content_lines = [line.strip() for line in lines 
                     if line.strip() and not re.match(r'^[\w.-]+@[\w-]+:[~\w/]*[#$]\s*$', line.strip())]
    
    actual_content = '\n'.join(content_lines).strip()
    is_empty_response = len(actual_content) < 10
    
    keywords_matched = any(kw.lower() in response_lower for kw in scenario.expected_keywords)
    
    state_persisted = implant_success and not has_negative_pattern and not is_empty_response
    state_fidelity = implant_success and keywords_matched
    state_persistent = state_persisted and state_fidelity
    
    return TestResult(
        scenario_id=scenario.scenario_id,
        mitre_id=scenario.mitre_id,
        technique=scenario.technique,
        implant_success=implant_success,
        verify_success=verify_success,
        state_persisted=state_persisted,
        state_fidelity=state_fidelity,
        state_persistent=state_persistent,
        keywords_matched=keywords_matched,
        implant_response=implant_response[:500] if implant_response else "",
        verify_response=verify_response[:500] if verify_response else "",
        implant_latency_ms=implant_latency,
        verify_latency_ms=verify_latency,
        error=error
    )


# ============== Round Execution ==============

def run_single_round(scenarios: List[TestScenario], round_num: int, verbose: bool = True, 
                     noise_level: int = 0, noise_position: str = "suffix", cumulative: bool = False) -> Tuple[List[TestResult], RoundMetrics]:
    """Run a single round of all scenarios."""
    if verbose:
        print(f"\n{'='*60}")
        print(f"ROUND {round_num}" + (f" [NOISE: {noise_level}, POS: {noise_position}]" if noise_level > 0 else ""))
        print(f"{'='*60}")
    
    results = []
    for scenario in scenarios:
        result = run_single_test(scenario, verbose=verbose, noise_level=noise_level, noise_position=noise_position, cumulative=cumulative)
        results.append(result)
    
    total = len(results)
    
    spr = sum(1 for r in results if r.state_persisted) / total if total > 0 else 0
    sfr = sum(1 for r in results if r.state_fidelity) / total if total > 0 else 0
    
    def calc_tier_pdr(tier_scenarios):
        tier_results = [r for r in results if r.scenario_id in tier_scenarios]
        if not tier_results:
            return 0.0
        return sum(1 for r in tier_results if r.state_persistent) / len(tier_results)
    
    pdr_high = calc_tier_pdr(COMPLEXITY_TIERS['high'])
    pdr_medium = calc_tier_pdr(COMPLEXITY_TIERS['medium'])
    pdr_low = calc_tier_pdr(COMPLEXITY_TIERS['low'])
    
    avg_implant_latency = sum(r.implant_latency_ms for r in results) / total if total > 0 else 0
    avg_verify_latency = sum(r.verify_latency_ms for r in results) / total if total > 0 else 0
    avg_latency = (avg_implant_latency + avg_verify_latency) / 2
    
    # Read token consumption for this round
    total_tokens = read_token_consumption()
    
    passed = sum(1 for r in results if r.state_persistent)
    
    metrics = RoundMetrics(
        round_number=round_num,
        spr=spr,
        sfr=sfr,
        pdr_high=pdr_high,
        pdr_medium=pdr_medium,
        pdr_low=pdr_low,
        avg_latency_ms=avg_latency,
        total_tokens=total_tokens,
        total_scenarios=total,
        passed_scenarios=passed
    )
    
    if verbose:
        print(f"\n  Round {round_num} Results:")
        print(f"    SPR: {spr:.1%}, SFR: {sfr:.1%}")
        print(f"    PDR: High={pdr_high:.1%}, Medium={pdr_medium:.1%}, Low={pdr_low:.1%}")
        print(f"    Latency: {avg_latency:.1f}ms")
        print(f"    Total Tokens: {total_tokens:,}")
    
    return results, metrics


# ============== Multi-Round Execution ==============

def run_multi_round_test(scenarios: List[TestScenario], num_rounds: int, verbose: bool = True, 
                         noise_level: int = 0, noise_position: str = "suffix", cumulative: bool = False) -> Dict[str, Any]:
    """Run multiple rounds of testing and calculate aggregated statistics."""
    all_round_results = []
    all_round_metrics = []
    
    print(f"\n{'#'*70}")
    print(f"# shelLM Direct Test (wexpect) - {num_rounds} Rounds")
    print(f"# Mode: REAL LinuxSSHbot.py execution via wexpect")
    if noise_level > 0:
        print(f"# Lost-in-the-Middle Mode: NOISE_LEVEL={noise_level}")
    print(f"# Scenarios per round: {len(scenarios)}")
    if cumulative:
        print(f"# CUMULATIVE MODE: History NOT cleared between scenarios")
    print(f"{'#'*70}")
    
    # Clear history to start fresh for evaluation
    clear_history()
    
    # Clear tokens for fresh tracking
    clear_tokens()
    
    try:
        for round_num in range(1, num_rounds + 1):
            results, metrics = run_single_round(scenarios, round_num, verbose=verbose, 
                                                noise_level=noise_level, noise_position=noise_position, cumulative=cumulative)
            all_round_results.append([asdict(r) for r in results])
            all_round_metrics.append(metrics)
    finally:
        # Restore original history (disabled to preserve history)
        # restore_history()
        pass
    
    def calc_stats(values: List[float]) -> Dict[str, float]:
        if not values:
            return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        return {
            "mean": round(mean, 4),
            "std": round(std, 4),
            "min": round(min(values), 4),
            "max": round(max(values), 4)
        }
    
    aggregated = {
        "spr": calc_stats([m.spr for m in all_round_metrics]),
        "sfr": calc_stats([m.sfr for m in all_round_metrics]),
        "pdr_high": calc_stats([m.pdr_high for m in all_round_metrics]),
        "pdr_medium": calc_stats([m.pdr_medium for m in all_round_metrics]),
        "pdr_low": calc_stats([m.pdr_low for m in all_round_metrics]),
        "latency_ms": calc_stats([m.avg_latency_ms for m in all_round_metrics]),
        "total_tokens": calc_stats([float(m.total_tokens) for m in all_round_metrics]),
    }
    
    print(f"\n{'='*70}")
    print("AGGREGATED RESULTS (across all rounds)")
    print(f"{'='*70}")
    print(f"\n=== D1: State Fidelity ===")
    print(f"SPR (State Persistence Rate): {aggregated['spr']['mean']:.1%} ± {aggregated['spr']['std']:.1%}")
    print(f"SFR (State Fidelity Rate):    {aggregated['sfr']['mean']:.1%} ± {aggregated['sfr']['std']:.1%}")
    
    print(f"\n=== D2: Attack Resilience (PDR by Complexity) ===")
    print(f"  High-Complexity:   {aggregated['pdr_high']['mean']:.1%} ± {aggregated['pdr_high']['std']:.1%}")
    print(f"  Medium-Complexity: {aggregated['pdr_medium']['mean']:.1%} ± {aggregated['pdr_medium']['std']:.1%}")
    print(f"  Low-Complexity:    {aggregated['pdr_low']['mean']:.1%} ± {aggregated['pdr_low']['std']:.1%}")
    
    print(f"\n=== D3: Operational Cost ===")
    print(f"Avg Latency: {aggregated['latency_ms']['mean']:.1f}ms ± {aggregated['latency_ms']['std']:.1f}ms")
    print(f"Total Tokens: {aggregated['total_tokens']['mean']:.0f} ± {aggregated['total_tokens']['std']:.0f}")
    
    return {
        "baseline": "shelLM",
        "mode": "wexpect_direct",
        "test_time": datetime.now().isoformat(),
        "num_rounds": num_rounds,
        "scenarios_per_round": len(scenarios),
        "per_round_metrics": [asdict(m) for m in all_round_metrics],
        "aggregated_metrics": aggregated,
        "per_round_results": all_round_results
    }


# ============== Main ==============

def main():
    parser = argparse.ArgumentParser(
        description="shelLM Direct Test using wexpect",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python shellm_direct_test.py --rounds 5
  python shellm_direct_test.py --rounds 10 --output custom_results.json
        """
    )
    parser.add_argument("--rounds", type=int, default=1,
                        help="Number of test rounds to run (default: 1)")
    parser.add_argument("--csv", type=str, default=None,
                        help="Path to CSV file")
    parser.add_argument("--output", type=str, default=None,
                        help="Output JSON file path")
    parser.add_argument("--quiet", action="store_true",
                        help="Reduce output verbosity")
    parser.add_argument("--noise-level", type=int, default=0,
                        help="Noise injection level for Lost-in-the-Middle test (0=none, 10/50/100)")
    parser.add_argument("--noise-position", type=str, default="suffix",
                        choices=["prefix", "suffix", "sandwich"],
                        help="Noise position: prefix (noise before key), suffix (noise after key), sandwich (key buried in middle)")
    parser.add_argument("--cumulative", action="store_true",
                        help="Cumulative mode: do NOT clear history between scenarios (simulates real deployment)")
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("shelLM Direct Test using wexpect")
    print("=" * 70)
    print(f"Mode: REAL LinuxSSHbot.py execution via wexpect")
    print(f"Script: {LINUXSSHBOT_SCRIPT}")
    print(f"Rounds: {args.rounds}")
    print(f"Time: {datetime.now().isoformat()}")
    print()
    
    if not os.path.exists(LINUXSSHBOT_SCRIPT):
        print(f"ERROR: LinuxSSHbot.py not found: {LINUXSSHBOT_SCRIPT}")
        sys.exit(1)
    
    csv_path = args.csv or os.path.join(PROJECT_ROOT, "HoneyComb_v2_E2E_Benchmark.csv")
    print(f"Loading scenarios from: {csv_path}")
    
    if not os.path.exists(csv_path):
        print(f"ERROR: CSV file not found: {csv_path}")
        sys.exit(1)
    
    scenarios = load_scenarios_from_csv(csv_path)
    print(f"Loaded {len(scenarios)} scenarios")
    
    if args.noise_level > 0:
        print(f"Lost-in-the-Middle Mode: Noise Level = {args.noise_level}, Position = {args.noise_position}")
    
    if args.cumulative:
        print(f"CUMULATIVE MODE: History will NOT be cleared between scenarios")
    
    results = run_multi_round_test(scenarios, args.rounds, verbose=not args.quiet, 
                                   noise_level=args.noise_level, noise_position=args.noise_position,
                                   cumulative=args.cumulative)
    
    # 生成带噪声级别和位置的输出文件名
    if args.noise_level > 0:
        if args.noise_position != "suffix":  # 非默认位置时加上位置标记
            default_output = os.path.join(SHELLM_DIR, f"shelLM_noise{args.noise_level}_{args.noise_position}_results.json")
        else:
            default_output = os.path.join(SHELLM_DIR, f"shelLM_noise{args.noise_level}_results.json")
    else:
        default_output = os.path.join(SHELLM_DIR, "shelLM_direct_results.json")
    
    output_path = args.output or default_output
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
