#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Semantic Ambiguity Boundary Test
Tests PromptShield's failure modes when handling ambiguous shell semantics.
"""

import sys
import os
import asyncio
import json
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import dotenv_values
from mcp_client import HoneypotMCPClient
from mcp_state_manager.command_analyzer import CommandAnalyzer

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("AmbiguityTest")

@dataclass
class AmbiguityTestCase:
    id: str
    category: str
    command: str
    description: str
    expected_file_exists: Optional[List[str]] = None
    expected_file_absent: Optional[List[str]] = None
    expected_content_match: Optional[Dict[str, str]] = None
    
    # Simulates the "True" outcome that a real shell would produce
    # but our analyzer might miss
    notes: str = ""

# Define the boundary cases based on "Failure Case Analysis"
TEST_CASES = [
    # 1. Logic Operators (||) - Analyzer doesn't support ||, might treat it as args
    AmbiguityTestCase(
        id="AMB-001",
        category="Logic Operators",
        command="touch /root/amb_success || touch /root/amb_fail",
        description="Short-circuit OR operator",
        expected_file_exists=["/root/amb_success"],
        expected_file_absent=["/root/amb_fail", "/root/||"],
        notes="Analyzer might create '||' or 'amb_fail' if it doesn't parse ||"
    ),
    
    # 2. Logic Operators (&&) - Conditional failure
    AmbiguityTestCase(
        id="AMB-002",
        category="Logic Operators",
        command="ls /nonexistent && touch /root/amb_conditional",
        description="Conditional AND with failed first command",
        expected_file_absent=["/root/amb_conditional"],
        notes="Analyzer doesn't know 'ls' failed, so it might process 'touch'"
    ),
    
    # 3. Control Flow (if/then) - Analyzer likely ignores shell keywords
    AmbiguityTestCase(
        id="AMB-003",
        category="Control Flow",
        command="if [ -f /nonexistent ]; then touch /root/amb_if_fail; fi",
        description="Shell if-statement",
        expected_file_absent=["/root/amb_if_fail"],
        notes="Analyzer likely interprets 'touch ...' as a command despite being inside if block"
    ),

    # 4. Input Redirection overwrites
    AmbiguityTestCase(
        id="AMB-004",
        category="Redirection Complex",
        command="echo 'data' > /root/amb_temp && rm /root/amb_temp",
        description="Create and immediately delete",
        expected_file_absent=["/root/amb_temp"],
        notes="Analyzer processes sequentially, should handle this unless race condition or logic error"
    ),
    
    # 5. Output filters (grep) to file
    AmbiguityTestCase(
        id="AMB-005",
        category="Pipe Redirection",
        command="echo 'secret' | grep 'nothing' > /root/amb_empty",
        description="Pipe result to file (empty result)",
        expected_file_exists=["/root/amb_empty"], 
        expected_content_match={"/root/amb_empty": ""}, # Should be empty
        notes="Analyzer might capture 'secret' via echo or fail to handle grep logic"
    ),
    
    # 6. Sudo scope
    AmbiguityTestCase(
        id="AMB-006",
        category="Privilege Scope",
        command="sudo -u nobody touch /root/amb_perm_denied",
        description="Sudo as other user attempting root write",
        expected_file_absent=["/root/amb_perm_denied"],
        notes="Root honeypot might allow it, but technically 'nobody' can't write to /root. Analyzer typically assumes success."
    ),

    # 7. Variable Expansion (Simple)
    AmbiguityTestCase(
        id="AMB-007",
        category="Variable Expansion",
        command="FILE=amb_var_test; touch /root/$FILE",
        description="Variable expansion in single line",
        expected_file_exists=["/root/amb_var_test"],
        expected_file_absent=["/root/$FILE"],
        notes="Analyzer might not track variable assignments in same command"
    ),

    # 8. Brace Expansion
    AmbiguityTestCase(
        id="AMB-008",
        category="Brace Expansion",
        command="touch /root/amb_brace_{1,2}",
        description="Shell brace expansion",
        expected_file_exists=["/root/amb_brace_1", "/root/amb_brace_2"],
        expected_file_absent=["/root/amb_brace_{1,2}"],
        notes="Analyzer likely treats '{1,2}' as literal filename"
    ),
    
    # 9. Process Substitution
    AmbiguityTestCase(
        id="AMB-009",
        category="Process Substitution",
        command="cat <(echo 'proc') > /root/amb_proc",
        description="Process substitution syntax",
        expected_file_exists=["/root/amb_proc"],
        expected_file_absent=["/root/<(echo"],
        notes="Analyzer might misinterpret <("
    ),

    # 10. Background Jobs
    AmbiguityTestCase(
        id="AMB-010",
        category="Background Jobs",
        command="touch /root/amb_bg & pid=$!; wait $pid; rm /root/amb_bg",
        description="Background job and wait",
        expected_file_absent=["/root/amb_bg"],
        notes="Complex sequence"
    )
]

class AmbiguityTester:
    def __init__(self):
        self.mcp_client = HoneypotMCPClient(storage_path="./honeypot_memory", global_singleton_mode=True)
        self.analyzer = CommandAnalyzer()
        self.results = []

    async def run_test(self):
        print("="*60)
        print("Starting Semantic Ambiguity Boundary Test")
        print("="*60)
        
        try:
            await self.mcp_client.connect()
            
            # Reset state for a clean test
            # Note: We use a specific IP for this test to avoid polluting other stats
            test_ip = "192.168.1.100" 
            
            for test_case in TEST_CASES:
                print(f"\n[Test Case] {test_case.id}: {test_case.description}")
                print(f"  Command: {test_case.command}")
                
                # 1. Analyze command locally (to simulate what the bot does)
                # In the real bot, this happens inside record_event_to_mcp -> analyzer
                # logic is duplicated here to verifying the *Analyzer's* interpretation
                # We will actually run it through MCP to test the full E2E state persistence
                
                # Simulate "Success" response from LLM (since LLM usually hallucinates success for valid-looking cmds)
                # But for 'conditional failure' cases, the LLM might correctly say "No such file", 
                # however, the Analyzer ignores LLM output for state updates (per design).
                # This is the crux of the failure mode!
                mock_response = "Done." 
                
                # Execute via MCP recording (Simulate the bot loop)
                # We need to manually simulate the analyzer logic calling record_event
                # because record_event uses the analyzer internally.
                
                # Update: We will call mcp_client.record_event directly which mimics the bot
                # But currently record_event in mcp_client.py doesn't do analysis! 
                # The bot (LinuxSSHbot_mcp.py) does the analysis AND THEN calls record_event.
                # So we must reproduce the bot's logic here.
                
                # Step A: Analyze
                sys_state = None # We don't have easy access to full system state obj here without query
                # Simplification: The analyzer logic is stateless in its processing of *what changes to make*,
                # it blindly produces StateChanges.
                
                # To properly test "Blind Logic", we just need to use the Analyzer and see what it recommends,
                # then commit that to MCP, and check the result.
                
                state_changes = self.analyzer.analyze_state_changes(
                    test_case.command, mock_response, cwd="/root", system_state=sys_state
                )
                
                # Step B: Commit to MCP
                # We record it as if it happened
                mcp_changes = [{
                    "target": sc.target,
                    "change_type": sc.change_type,
                    "new_value": sc.new_value,
                    "metadata": sc.metadata
                } for sc in state_changes]
                
                await self.mcp_client.record_event(
                    ip_address=test_ip,
                    session_id="test_ambiguity_session",
                    command=test_case.command,
                    user_context="root",
                    event_type="command_execution",
                    status="success",
                    stdout=mock_response,
                    state_changes=mcp_changes
                )
                
                # Step C: Verification
                # Allow async write to propagate (mock DB is fast but good practice)
                await asyncio.sleep(0.1)
                
                failure_reasons = []
                
                # Check Exists
                if test_case.expected_file_exists:
                    for f in test_case.expected_file_exists:
                        exists = await self.mcp_client.check_file_exists(test_ip, f)
                        if not exists:
                            failure_reasons.append(f"Expected file {f} missing")
                
                # Check Absent
                if test_case.expected_file_absent:
                    for f in test_case.expected_file_absent:
                        exists = await self.mcp_client.check_file_exists(test_ip, f)
                        if exists:
                            failure_reasons.append(f"Unexpected file {f} exists")
                            
                # Check Content
                if test_case.expected_content_match:
                    for f, expected_content in test_case.expected_content_match.items():
                        content = await self.mcp_client.get_file_content(test_ip, f)
                        if content != expected_content:
                            failure_reasons.append(f"Content mismatch for {f}")

                # Result
                success = len(failure_reasons) == 0
                self.results.append({
                    "id": test_case.id,
                    "category": test_case.category,
                    "success": success,
                    "reasons": failure_reasons
                })
                
                status_symbol = "✓" if success else "✗"
                print(f"  Result: {status_symbol} {'Success' if success else 'Failed'}")
                if not success:
                    for r in failure_reasons:
                        print(f"    - {r}")

        finally:
            await self.mcp_client.close()
            
        self.print_summary()

    def print_summary(self):
        print("\n" + "="*60)
        print("Ambiguity Test Summary")
        print("="*60)
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r["success"])
        failed = total - passed
        rate = (passed / total) * 100
        
        print(f"Total Cases: {total}")
        print(f"Passed:      {passed}")
        print(f"Failed:      {failed}")
        print(f"Fidelity:    {rate:.1f}%")
        
        print("\nFailure Analysis by Category:")
        categories = {}
        for r in self.results:
            cat = r["category"]
            if cat not in categories: 
                categories[cat] = {"total": 0, "failed": 0}
            categories[cat]["total"] += 1
            if not r["success"]:
                categories[cat]["failed"] += 1
                
        for cat, stats in categories.items():
            fail_rate = (stats["failed"] / stats["total"]) * 100
            print(f"  - {cat:<20}: {stats['failed']}/{stats['total']} failed ({fail_rate:.0f}%)")

if __name__ == "__main__":
    tester = AmbiguityTester()
    asyncio.run(tester.run_test())
