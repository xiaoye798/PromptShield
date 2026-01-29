#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Beelzebub Direct Launch Multi-Round Test

This script DIRECTLY LAUNCHES the Beelzebub server and interacts via SSH,
ensuring that the HistoryStore mechanism is properly tested.

Key difference from wrapper approach:
- Starts Beelzebub server with `go run main.go`
- Uses paramiko to connect via SSH on port 2222
- Tests cross-session state persistence

IMPORTANT NOTE:
Beelzebub's HistoryStore is keyed by session. When SSH disconnects,
the session key is lost. New connections get new session keys.
This means Session B CANNOT access Session A's history.

This script will demonstrate this limitation of stateless LLM honeypots.

Usage:
    python beelzebub_direct_test.py --rounds 5
"""

import os
import sys
import json
import csv
import time
import subprocess
import argparse
import statistics
import socket
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Dict, Any

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko not installed. Run: pip install paramiko")
    sys.exit(1)

# Configuration
BEELZEBUB_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BEELZEBUB_DIR))
SSH_HOST = "localhost"
SSH_PORT = 2222
SSH_USERNAME = "root"
SSH_PASSWORD = "root"


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


# ============== Token Management ==============

TOKENS_FILE = os.path.join(BEELZEBUB_DIR, "tokens.log")

def clear_tokens():
    """Clear tokens.log to start fresh token tracking."""
    if os.path.exists(TOKENS_FILE):
        os.remove(TOKENS_FILE)

def read_token_consumption():
    """Read total token consumption from tokens.log (CSV format: prompt,completion,total)."""
    if not os.path.exists(TOKENS_FILE):
        return 0
    
    try:
        total = 0
        with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 3:
                    total += int(parts[2])  # total_tokens is the third column
        return total
    except (ValueError, FileNotFoundError):
        return 0


# ============== Server Management ==============

beelzebub_process = None


def is_port_open(host: str, port: int) -> bool:
    """Check if a port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0


def start_beelzebub_server() -> subprocess.Popen:
    """Start Beelzebub server using go run main.go."""
    global beelzebub_process
    
    print("[*] Starting Beelzebub server...")
    
    # Check if Go is installed
    try:
        subprocess.run(["go", "version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: Go is not installed or not in PATH")
        sys.exit(1)
    
    # Start the server
    beelzebub_process = subprocess.Popen(
        ["go", "run", "main.go"],
        cwd=BEELZEBUB_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for server to start (check if port 2222 is open)
    for i in range(30):
        if is_port_open(SSH_HOST, SSH_PORT):
            print(f"[*] Beelzebub server started on port {SSH_PORT}")
            return beelzebub_process
        time.sleep(1)
        print(f"[*] Waiting for server to start... ({i+1}/30)")
    
    print("ERROR: Beelzebub server failed to start within 30 seconds")
    stop_beelzebub_server()
    sys.exit(1)


def stop_beelzebub_server():
    """Stop Beelzebub server."""
    global beelzebub_process
    if beelzebub_process:
        print("[*] Stopping Beelzebub server...")
        beelzebub_process.terminate()
        try:
            beelzebub_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            beelzebub_process.kill()
        beelzebub_process = None
        print("[*] Beelzebub server stopped")


# ============== SSH Execution ==============

def execute_ssh_command(command: str, username: str = SSH_USERNAME, timeout: int = 120) -> Tuple[str, float]:
    """
    Execute a command via SSH to Beelzebub.
    
    Each call creates a NEW SSH connection, simulating session disconnect/reconnect.
    
    Returns:
        (response_text, latency_ms)
    """
    try:
        start_time = time.time()
        
        # Create SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to Beelzebub
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username=username,
            password=SSH_PASSWORD,
            timeout=30,
            allow_agent=False,
            look_for_keys=False
        )
        
        # Get interactive shell
        shell = client.invoke_shell()
        time.sleep(1)  # Wait for initial prompt
        
        # Read initial output
        initial_output = ""
        while shell.recv_ready():
            initial_output += shell.recv(4096).decode('utf-8', errors='ignore')
        
        # Send command
        shell.send(command + '\n')
        time.sleep(2)  # Wait for response
        
        # Read response
        response = ""
        while shell.recv_ready():
            response += shell.recv(4096).decode('utf-8', errors='ignore')
        
        latency_ms = (time.time() - start_time) * 1000
        
        # Close connection
        shell.close()
        client.close()
        
        return response.strip(), latency_ms
        
    except paramiko.AuthenticationException:
        return "Error: SSH authentication failed", 0.0
    except paramiko.SSHException as e:
        return f"Error: SSH error - {str(e)}", 0.0
    except socket.timeout:
        return "Error: SSH connection timed out", 0.0
    except Exception as e:
        return f"Error: {str(e)}", 0.0


# ============== Scenario Loading ==============

def load_scenarios_from_csv(csv_path: str) -> List[TestScenario]:
    """Load test scenarios from HoneyComb benchmark CSV."""
    scenarios = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get('Scenario_ID'):
                continue
            
            verify_cmd = row.get('Session_C_触发验证(Trigger)', '')
            keywords = []
            
            if 'grep' in verify_cmd:
                import re
                patterns = re.findall(r"grep[^|]*'([^']+)'", verify_cmd)
                keywords.extend(patterns)
            
            scenarios.append(TestScenario(
                scenario_id=row['Scenario_ID'],
                mitre_id=row['MITRE_ATT&CK_ID'],
                technique=row['ATT&CK_Technique'],
                implant_command=row['Session_A_植入(Implant)'],
                verify_command=row['Session_C_触发验证(Trigger)'],
                expected_keywords=keywords if keywords else ['存在', 'found', 'enabled']
            ))
    
    return scenarios


# ============== Single Test Execution ==============

def run_single_test(scenario: TestScenario, verbose: bool = False) -> TestResult:
    """
    Run a single HoneyComb test scenario using DIRECT SSH.
    
    Session A: SSH connect as ROOT, send implant command, disconnect
    Session B: SSH connect as JENKINS (different user!), send verify command
    
    This ensures DIFFERENT session keys in Beelzebub (SessionKey = Protocol + IP + User).
    """
    if verbose:
        print(f"  Testing: {scenario.scenario_id} - {scenario.technique[:40]}...")
    
    error = None
    
    # ========== Session A: Implant Phase (User: root) ==========
    implant_response, implant_latency = execute_ssh_command(scenario.implant_command, username="root")
    implant_success = not implant_response.startswith("Error:")
    
    # ========== Session B: Verification Phase (User: jenkins) ==========
    # This guarantees a NEW session key: SSH + Localhost + jenkins
    # The HistoryStore will NOT find the history from 'root', forcing a pure stateless test.
    verify_response, verify_latency = execute_ssh_command(scenario.verify_command, username="jenkins")
    verify_success = not verify_response.startswith("Error:")
    
    # ========== Evaluate Results ==========
    response_lower = verify_response.lower()
    has_negative_pattern = any(neg in response_lower for neg in NEGATIVE_PATTERNS)
    
    import re
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

def run_single_round(scenarios: List[TestScenario], round_num: int, verbose: bool = True) -> Tuple[List[TestResult], RoundMetrics]:
    """Run a single round of all scenarios."""
    if verbose:
        print(f"\n{'='*60}")
        print(f"ROUND {round_num}")
        print(f"{'='*60}")
    
    results = []
    for scenario in scenarios:
        result = run_single_test(scenario, verbose=verbose)
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

def run_multi_round_test(scenarios: List[TestScenario], num_rounds: int, verbose: bool = True) -> Dict[str, Any]:
    """Run multiple rounds of testing and calculate aggregated statistics."""
    all_round_results = []
    all_round_metrics = []
    
    print(f"\n{'#'*70}")
    print(f"# Beelzebub Direct Launch Test - {num_rounds} Rounds")
    print(f"# Mode: SSH connection to Beelzebub server on port {SSH_PORT}")
    print(f"# Scenarios per round: {len(scenarios)}")
    print(f"# NOTE: Each SSH session has separate history (stateless)")
    print(f"{'#'*70}")
    
    # Clear tokens for fresh tracking
    clear_tokens()
    
    for round_num in range(1, num_rounds + 1):
        results, metrics = run_single_round(scenarios, round_num, verbose=verbose)
        all_round_results.append([asdict(r) for r in results])
        all_round_metrics.append(metrics)
    
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
        "baseline": "Beelzebub",
        "mode": "direct_ssh",
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
        description="Beelzebub Direct Launch Multi-Round Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python beelzebub_direct_test.py --rounds 5
  python beelzebub_direct_test.py --rounds 10 --output custom_results.json
  python beelzebub_direct_test.py --no-start  # Don't start server, assume already running
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
    parser.add_argument("--no-start", action="store_true",
                        help="Don't start Beelzebub server (assume already running)")
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("Beelzebub Direct Launch Multi-Round Test")
    print("=" * 70)
    print(f"Mode: SSH connection to Beelzebub server")
    print(f"SSH: {SSH_HOST}:{SSH_PORT} (user: {SSH_USERNAME})")
    print(f"Rounds: {args.rounds}")
    print(f"Time: {datetime.now().isoformat()}")
    print()
    
    csv_path = args.csv or os.path.join(PROJECT_ROOT, "HoneyComb_v2_E2E_Benchmark.csv")
    print(f"Loading scenarios from: {csv_path}")
    
    if not os.path.exists(csv_path):
        print(f"ERROR: CSV file not found: {csv_path}")
        sys.exit(1)
    
    scenarios = load_scenarios_from_csv(csv_path)
    print(f"Loaded {len(scenarios)} scenarios")
    
    # Start server if needed
    if not args.no_start:
        start_beelzebub_server()
    else:
        if not is_port_open(SSH_HOST, SSH_PORT):
            print(f"ERROR: Beelzebub server not running on port {SSH_PORT}")
            sys.exit(1)
        print(f"[*] Using existing Beelzebub server on port {SSH_PORT}")
    
    try:
        results = run_multi_round_test(scenarios, args.rounds, verbose=not args.quiet)
        
        output_path = args.output or os.path.join(BEELZEBUB_DIR, "beelzebub_direct_results.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\nResults saved to: {output_path}")
    finally:
        if not args.no_start:
            stop_beelzebub_server()


if __name__ == "__main__":
    main()
