#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
HoneyComb v2 End-to-End Real-Test Script
Tests the actual LLM interaction process and verifies the performance of persistence in the complete honeypot system

SPR, SFR, Latency, Token Consumption
"""

import asyncio
import shutil
import os
import sys
import time
import statistics
import argparse
import json
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

# Import noise generator (for Lost-in-the-Middle control group experiment)
try:
    from baselines.shelLM.noise_generator import NoiseGenerator
    NOISE_GENERATOR = NoiseGenerator()
except ImportError:
    NOISE_GENERATOR = None

# Force flush output
def p(msg):
    print(msg, flush=True)

p("="*70)
p("HoneyComb v2 End-to-End Real-Test - Starting...")
p("="*70)
p(f"Python: {sys.executable}")
p(f"Working Directory: {os.getcwd()}")
p("")

# Token tracking file
TOKENS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "promptshield_tokens.json")

# Complexity tiers (consistent with shelLM)
COMPLEXITY_TIERS = {
    'high': ['HC-T1543-002', 'HC-T1098-004', 'HC-T1136-001', 'HC-T1078-003'],
    'medium': ['HC-T1053-003', 'HC-T1037-004', 'HC-T1574-006', 'HC-T1556-003'],
    'low': ['HC-T1546-004', 'HC-T1505-003']
}

# Negative response patterns
NEGATIVE_PATTERNS = [
    "no such file", "cannot access", "not found", "no crontab",
    "does not exist", "permission denied", "command not found",
    "no such user", "not in the sudoers",
]

# Add project path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

p("[1/5] Importing modules...")
try:
    from mcp_client import HoneypotMCPClient
    p("  ✓ mcp_client imported successfully")
except ImportError as e:
    p(f"  ✗ mcp_client import failed: {e}")
    sys.exit(1)

try:
    from mcp_state_manager.command_analyzer import CommandAnalyzer
    from mcp_state_manager.event_graph import EventType, EventStatus
    p("  ✓ CommandAnalyzer imported successfully")
except ImportError as e:
    p(f"  ✗ CommandAnalyzer import failed: {e}")
    sys.exit(1)

# Critical: Import the real build_enhanced_messages function from the project
try:
    from LinuxSSHbot_mcp import build_enhanced_messages
    p("  ✓ build_enhanced_messages imported successfully (from actual project code)")
except ImportError as e:
    p(f"  ✗ build_enhanced_messages import failed: {e}")
    sys.exit(1)

try:
    from dotenv import dotenv_values
    import openai
    from deepseek_client import DeepSeekClient, DeepSeekChatCompletion
    p("  ✓ AI client modules imported successfully")
except ImportError as e:
    p(f"  ✗ AI client modules import failed: {e}")
    sys.exit(1)


# ============== AI Client Initialization ==============

config = dotenv_values(".env")
api_provider = config.get("API_PROVIDER", "openai").lower()

p(f"[2/5] Initializing AI client ({api_provider})...")

if api_provider == "openai":
    openai.api_key = config["OPENAI_API_KEY"]
    chat_client = None
    p("  ✓ OpenAI client configured")
elif api_provider == "deepseek":
    deepseek_client = DeepSeekClient(
        api_key=config["DEEPSEEK_API_KEY"],
        base_url=config.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    chat_client = DeepSeekChatCompletion(deepseek_client)
    p("  ✓ DeepSeek client configured")
else:
    p(f"  ✗ Unsupported API provider: {api_provider}")
    sys.exit(1)


# ============== Test Scenario Definition ==============

@dataclass
class E2ETestScenario:
    """End-to-End Test Scenario"""
    scenario_id: str
    mitre_id: str
    technique: str
    description: str
    implant_command: str
    verify_command: str
    persistence_type: str
    # LLM response verification
    expected_keywords: List[str]  # Keywords that the verify command response should contain
    negative_keywords: List[str] = None  # Keywords that should NOT appear


def load_scenarios_from_csv(csv_path: str) -> List[E2ETestScenario]:
    """
    Load test scenarios from CSV - direct reference to project test suite
    
    Ensures that real benchmark definitions are tested, rather than hardcoded scenarios.
    """
    import csv
    
    scenarios = []
    
    # Define verification command and expected keywords for each scenario
    # Fully consistent with the 10 Linux scenarios in test_honeycomb_persistence.py
    verification_config = {
        # ========== 1. T1053.003 -- Cron Scheduled Task ==========
        "HC-T1053-003": {
            "verify_command": "crontab -l | grep -E 'python3.*socket.*4444'",
            "expected_keywords": ["socket", "4444"],
            "negative_keywords": ["no crontab"]
        },
        # ========== 2. T1543.002 -- Systemd Service ==========
        "HC-T1543-002": {
            "verify_command": "systemctl is-enabled dbus-org.freedesktop.resolve1.service && cat /etc/systemd/system/dbus-org.freedesktop.resolve1.service | grep -E 'tcp.*4444'",
            "expected_keywords": ["enabled", "4444"],
            "negative_keywords": ["disabled", "not found", "Unit not found"]
        },
        # ========== 3. T1098.004 -- SSH Authorized Keys ==========
        "HC-T1098-004": {
            "verify_command": "cat /root/.ssh/authorized_keys | grep -E 'c2server'",
            "expected_keywords": ["ssh-rsa", "c2server"],
            "negative_keywords": ["No such file", "cannot open"]
        },
        # ========== 4. T1136.001 -- Create Local Account ==========
        "HC-T1136-001": {
            "verify_command": "id sysupdate | grep -E '(sudo|wheel)' && grep sysupdate /etc/passwd && sudo -l -U sysupdate | grep NOPASSWD",
            "expected_keywords": ["sysupdate", "sudo"],
            "negative_keywords": ["no such user", "not found"]
        },
        # ========== 5. T1546.004 -- Unix Shell Config Modification ==========
        "HC-T1546-004": {
            "verify_command": "cat /root/.bashrc | grep -E 'PROMPT_COMMAND.*tcp.*4444'",
            "expected_keywords": ["PROMPT_COMMAND", "4444"],
            "negative_keywords": ["No such file"]
        },
        # ========== 6. T1037.004 -- RC Scripts ==========
        "HC-T1037-004": {
            "verify_command": "cat /etc/rc.local | grep -E 'python3.*socket.*4444' && ls -la /etc/rc.local | grep -E '^-..x'",
            "expected_keywords": ["socket", "4444"],
            "negative_keywords": ["No such file"]
        },
        # ========== 7. T1505.003 -- Web Shell ==========
        "HC-T1505-003": {
            "verify_command": "cat /var/www/html/.system.php | grep -E '\\$_REQUEST.*system' && ls -la /var/www/html/.system.php",
            "expected_keywords": ["$_REQUEST", "system"],
            "negative_keywords": ["No such file"]
        },
        # ========== 8. T1574.006 -- Dynamic Linker Hijacking ==========
        "HC-T1574-006": {
            "verify_command": "cat /etc/ld.so.preload | grep -E 'libsystem.so' && ls -la /usr/local/lib/libsystem.so",
            "expected_keywords": ["libsystem.so"],
            "negative_keywords": ["No such file"]
        },
        # ========== 9. T1556.003 -- PAM Backdoor ==========
        "HC-T1556-003": {
            "verify_command": "head -1 /etc/pam.d/sshd | grep -E 'pam_permit.so'",
            "expected_keywords": ["pam_permit.so"],
            "negative_keywords": []
        },
        # ========== 10. T1078.003 -- Valid Account Manipulation ==========
        "HC-T1078-003": {
            "verify_command": "grep nobody /etc/passwd | grep -E '/bin/bash' && sudo -l -U nobody | grep NOPASSWD",
            "expected_keywords": ["nobody", "/bin/bash"],
            "negative_keywords": []
        },
    }
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            scenario_id = row['Scenario_ID']
            
            # Get verification config
            config = verification_config.get(scenario_id, {})
            
            scenario = E2ETestScenario(
                scenario_id=scenario_id,
                mitre_id=row['MITRE_ATT&CK_ID'],
                technique=row['ATT&CK_Technique'],
                description=row['攻击描述'],  # Keep as is or translate if needed. Let's assume description field might be useful in Chinese but the requirement is to translate.
                implant_command=row['Session_A_植入(Implant)'],
                verify_command=config.get('verify_command', row['Session_C_触发验证(Trigger)']),
                persistence_type=row['持久化类型'],
                expected_keywords=config.get('expected_keywords', []),
                negative_keywords=config.get('negative_keywords', [])
            )
            scenarios.append(scenario)
    
    return scenarios


# Load test scenarios from CSV (direct reference to project test suite)
CSV_PATH = os.path.join(os.path.dirname(__file__), "HoneyComb_v2_E2E_Benchmark.csv")
p(f"\n[Loading Scenarios] From CSV: {os.path.basename(CSV_PATH)}")

try:
    E2E_TEST_SCENARIOS = load_scenarios_from_csv(CSV_PATH)
    p(f"  ✓ Successfully loaded {len(E2E_TEST_SCENARIOS)} scenarios")
    for i, s in enumerate(E2E_TEST_SCENARIOS, 1):
        p(f"    {i:2d}. {s.scenario_id} - {s.technique}")
except Exception as e:
    p(f"  ✗ Failed to load CSV: {e}")
    sys.exit(1)


# ============== Test Results ==============

@dataclass
class E2ETestResult:
    scenario_id: str
    mitre_id: str
    technique: str
    # Phase results
    implant_success: bool
    implant_response: str
    verify_success: bool
    verify_response: str
    # Detailed determination
    llm_response_valid: bool  # Whether LLM response is reasonable
    state_persistent: bool    # Whether state is persistent (SPR AND SFR)
    keywords_matched: bool    # Whether keywords matched
    # ===== 5 Indicators Evaluation =====
    state_persisted: bool = False   # SPR: Whether state is acknowledged to exist
    state_fidelity: bool = False    # SFR: Whether state content is accurate
    implant_latency_ms: float = 0.0
    verify_latency_ms: float = 0.0
    implant_tokens: int = 0
    verify_tokens: int = 0
    # ===================
    error: Optional[str] = None


@dataclass
class RoundMetrics:
    """Aggregated metrics for multiple rounds"""
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


# ============== AI Call Functions ==============

async def call_ai_for_command(command: str, system_prompt: str = None, state_context: str = None) -> Tuple[str, int]:
    """
    Call LLM to simulate command execution
    
    Args:
        command: User command
        system_prompt: System prompt (optional)
        state_context: State context (critical! contains persisted file content, etc.)
    
    Returns:
        (LLM Response, Token Consumption)
    """
    if system_prompt is None:
        system_prompt = """You are a Linux terminal (Ubuntu 20.04) acting as a honeypot.
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
- cat file >> target: (no output) → content appended
- cat file > target: (no output) → file overwritten
- chmod [mode] [file]: (no output) → permissions changed
- mkdir -p [dir]: (no output) or "mkdir: created directory '...'" → directory created
- touch [file]: (no output) → empty file created
- crontab with pipe input: "crontab: installing new crontab" → cron job installed
- systemctl daemon-reload: (no output) → systemd reloaded
- systemctl enable [service]: "Created symlink /etc/systemd/system/..." → service enabled
- cat > file << 'EOF' ... EOF: (show heredoc lines with > prefix, then prompt) → file created

Current user: root (uid=0, full privileges)
Current directory: /root
Hostname: honeypot"""

    # If there is state context, inject it into the system prompt
    if state_context:
        system_prompt = f"""{system_prompt}

{state_context}"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": command}
    ]
    
    try:
        if api_provider == "openai":
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: openai.ChatCompletion.create(
                    model=config.get("OPENAI_MODEL", "gpt-3.5-turbo"),
                    messages=messages,
                    temperature=0.0,
                    max_tokens=500
                )
            )
            
            # Compatibility handling
            usage = getattr(response, 'usage', None)
            if hasattr(usage, 'total_tokens'):
                total_tokens = usage.total_tokens
            elif isinstance(usage, dict):
                total_tokens = usage.get('total_tokens', 0)
            else:
                total_tokens = 0
                
            return response.choices[0].message.content, total_tokens
        elif api_provider == "deepseek":
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: chat_client.create(
                    model=config.get("DEEPSEEK_MODEL", "deepseek-chat"),
                    messages=messages,
                    temperature=0.0,
                    max_tokens=500
                )
            )
            
            # Compatibility handling: DeepSeekResponse's usage might be a dict or object
            usage = getattr(response, 'usage', None)
            if hasattr(usage, 'total_tokens'):
                total_tokens = usage.total_tokens
            elif isinstance(usage, dict):
                total_tokens = usage.get('total_tokens', 0)
            else:
                total_tokens = 0
                
            return response.choices[0].message.content, total_tokens
    except Exception as e:
        return f"[API Error] {e}", 0


async def call_ai_with_state_injection(mcp_client: HoneypotMCPClient, command: str, ip_address: str) -> Tuple[str, int]:
    """
    Call LLM and inject state context (using project actual code)
    
    This function directly uses build_enhanced_messages from LinuxSSHbot_mcp.py,
    ensuring that the real project code is being tested.
    
    Returns:
        (LLM Response, Token Consumption)
    """
    # Base system prompt
    system_prompt = """You are a Linux terminal (Ubuntu 20.04). 
You must respond EXACTLY as a real Linux system would, including:
- Accurate command outputs
- Proper error messages
- File system state consistency
- Realistic timestamps and system information

Current user: root
Current directory: /root
Hostname: honeypot"""

    # Build base messages
    base_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": command}
    ]
    
    # Use real project code build_enhanced_messages to inject state context
    enhanced_messages = await build_enhanced_messages(
        messages=base_messages,
        command=command,
        current_cwd="/root",
        client=mcp_client,  # Pass the MCP client
        ip_address=ip_address
    )
    
    # Call LLM
    try:
        if api_provider == "openai":
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: openai.ChatCompletion.create(
                    model=config.get("OPENAI_MODEL", "gpt-3.5-turbo"),
                    messages=enhanced_messages,
                    temperature=0.0,
                    max_tokens=500
                )
            )
            total_tokens = response.usage.total_tokens if hasattr(response, 'usage') else 0
            return response.choices[0].message.content, total_tokens
        elif api_provider == "deepseek":
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: chat_client.create(
                    model=config.get("DEEPSEEK_MODEL", "deepseek-chat"),
                    messages=enhanced_messages,
                    temperature=0.0,
                    max_tokens=500
                )
            )
            
            # Compatibility handling
            usage = getattr(response, 'usage', None)
            if hasattr(usage, 'total_tokens'):
                total_tokens = usage.total_tokens
            elif isinstance(usage, dict):
                total_tokens = usage.get('total_tokens', 0)
            else:
                total_tokens = 0
                
            return response.choices[0].message.content, total_tokens
    except Exception as e:
        return f"[API Error] {e}", 0


# ============== End-to-End Test Executor ==============

class E2ETestExecutor:
    """End-to-End Test Executor"""
    
    def __init__(self, storage_path: str = "./test_e2e_memory", 
                 noise_level: int = 0, noise_position: str = "sandwich"):
        self.storage_path = storage_path
        self.test_ip = "192.168.100.100"
        self.results: List[E2ETestResult] = []
        self.mcp_client: Optional[HoneypotMCPClient] = None
        self.analyzer = CommandAnalyzer()
        # Lost-in-the-Middle control group parameters
        self.noise_level = noise_level
        self.noise_position = noise_position
        self.noise_tokens_consumed = 0  # Track tokens consumed by noise commands
        
    async def setup(self):
        """Initialize test environment"""
        p(f"\n[3/5] Initializing test environment: {self.storage_path}")
        
        # Clean test directory
        if os.path.exists(self.storage_path):
            shutil.rmtree(self.storage_path)
        os.makedirs(self.storage_path, exist_ok=True)
        os.makedirs(os.path.join(self.storage_path, "states"), exist_ok=True)
        os.makedirs(os.path.join(self.storage_path, "graphs"), exist_ok=True)
        p("  ✓ Test directory created")
        
        # Initialize MCP client
        self.mcp_client = HoneypotMCPClient(
            storage_path=self.storage_path,
            global_singleton_mode=True
        )
        await self.mcp_client.connect()
        p("  ✓ MCP client connected")
        
    async def cleanup(self):
        """Clean up test environment"""
        if self.mcp_client:
            await self.mcp_client.close()
            p("  ✓ MCP client disconnected")
        
    async def execute_command_with_llm(self, command: str, session_id: str, inject_state: bool = False) -> tuple:
        """
        Execute command using real LLM (complete flow)
        
        Args:
            command: Command to execute
            session_id: Session ID
            inject_state: Whether to inject persistent state context (should be True in verification phase)
        
        Returns:
            (response, event_type, status, latency_ms, tokens)
        """
        p(f"    → Calling LLM: {command[:60]}...")
        
        start_time = time.time()
        
        # Select call method based on whether state injection is needed
        if inject_state:
            # Use real project code build_enhanced_messages to inject state
            p(f"    → Using build_enhanced_messages (project actual code) to inject state...")
            response, tokens = await call_ai_with_state_injection(
                self.mcp_client, command, self.test_ip
            )
        else:
            # Do not inject state, call directly
            response, tokens = await call_ai_for_command(command)
        
        latency_ms = (time.time() - start_time) * 1000
        p(f"    ← LLM Response: {len(response)} chars, {latency_ms:.1f}ms, {tokens} tokens")
        
        # 2. Analyze using CommandAnalyzer
        event_type = self.analyzer.determine_event_type(command)
        status = self.analyzer.determine_status(command, response)
        state_changes = self.analyzer.analyze_state_changes(
            command, response, cwd="/root", system_state=None
        )
        
        p(f"    • Event Type: {event_type.value if hasattr(event_type, 'value') else event_type}")
        p(f"    • Execution Status: {status.value if hasattr(status, 'value') else status}")
        p(f"    • State Changes: {len(state_changes)} items")
        
        # 3. Record to MCP
        result = await self.mcp_client.record_event(
            ip_address=self.test_ip,
            session_id=session_id,
            command=command,
            user_context="root",
            event_type=event_type.value if hasattr(event_type, 'value') else str(event_type),
            status=status.value if hasattr(status, 'value') else str(status),
            stdout=response,
            state_changes=[{
                "target": sc.target,
                "change_type": sc.change_type,
                "old_value": sc.old_value,
                "new_value": sc.new_value,
                "metadata": sc.metadata
            } for sc in state_changes] if state_changes else []
        )
        
        if result.get("success"):
            p(f"    ✓ Event recorded: {result.get('event_id', 'unknown')[:16]}...")
        else:
            p(f"    ✗ Event recording failed: {result.get('message')}")
        
        return response, event_type, status, latency_ms, tokens
    
    async def run_single_test(self, scenario: E2ETestScenario, index: int) -> E2ETestResult:
        """Run single end-to-end test scenario"""
        p(f"\n{'='*70}")
        p(f"Scenario {index}: {scenario.scenario_id}")
        p(f"MITRE ID: {scenario.mitre_id}")
        p(f"Technique: {scenario.technique}")
        p(f"Description: {scenario.description}")
        p(f"{'='*70}")
        
        try:
            # ==================== Noise Simulation (Lost-in-the-Middle control) ====================
            noise_tokens_this_scenario = 0
            if self.noise_level > 0 and NOISE_GENERATOR:
                if self.noise_position in ["prefix", "sandwich"]:
                    # Inject noise before implant (simulating shelLM's noise load)
                    half_noise = self.noise_level // 2 if self.noise_position == "sandwich" else self.noise_level
                    p(f"\n[Noise Simulation] Simulating {half_noise} noise commands (parallel, does not affect MCP state)...")
                    noise_commands = NOISE_GENERATOR.generate_noise_batch(half_noise)
                    
                    # Parallelize noise calls to speed up test
                    sem = asyncio.Semaphore(10)
                    async def call_with_sem(cmd):
                        async with sem:
                            return await call_ai_for_command(cmd)
                    
                    results = await asyncio.gather(*[call_with_sem(cmd) for cmd in noise_commands])
                    noise_tokens_this_scenario += sum(res[1] for res in results)
                    p(f"    → Noise consumed {noise_tokens_this_scenario} tokens")
            
            # ==================== Session A: Implant ====================
            p("\n[Session A] Executing implant command...")
            p(f"  Command: {scenario.implant_command}")
            
            implant_response, _, implant_status, implant_latency, implant_tokens = await self.execute_command_with_llm(
                scenario.implant_command,
                "session_a_implant"
            )
            
            implant_success = "SUCCESS" in str(implant_status) or "error" not in implant_response.lower()
            p(f"  Result: {'✓ Success' if implant_success else '✗ Failure'} (Latency: {implant_latency:.1f}ms, Tokens: {implant_tokens})")
            
            # ==================== Session B: Disconnect & Reconnect ====================
            p("\n[Session B] Simulating disconnect & reconnect...")
            await self.mcp_client.close()
            p("  ✓ MCP client disconnected")
            
            await asyncio.sleep(0.5)  # Simulate network latency
            
            # Reconnect (new client instance)
            self.mcp_client = HoneypotMCPClient(
                storage_path=self.storage_path,
                global_singleton_mode=True
            )
            await self.mcp_client.connect()
            p("  ✓ New session established (simulated reconnect)")
            
            # ==================== Noise Simulation before verification (sandwich & suffix modes) ====================
            if self.noise_level > 0 and NOISE_GENERATOR:
                if self.noise_position in ["suffix", "sandwich"]:
                    # Inject noise before verification
                    remaining_noise = self.noise_level - (self.noise_level // 2) if self.noise_position == "sandwich" else self.noise_level
                    p(f"\n[Noise Simulation] Simulating {remaining_noise} noise commands before verification (parallel)...")
                    noise_commands = NOISE_GENERATOR.generate_noise_batch(remaining_noise)
                    
                    sem = asyncio.Semaphore(10)
                    async def call_with_sem(cmd):
                        async with sem:
                            return await call_ai_for_command(cmd)
                            
                    results = await asyncio.gather(*[call_with_sem(cmd) for cmd in noise_commands])
                    noise_tokens_this_scenario += sum(res[1] for res in results)
                    p(f"    → total noise consumed {noise_tokens_this_scenario} tokens")
            
            # ==================== Session C: Verification ====================
            p("\n[Session C] Executing verification command...")
            p(f"  Command: {scenario.verify_command}")
            
            # Critical: MUST inject persistent state in verification phase (inject_state=True)
            verify_response, _, _, verify_latency, verify_tokens = await self.execute_command_with_llm(
                scenario.verify_command,
                "session_c_verify",
                inject_state=True  # Key to solving cross-session persistence
            )
            
            p(f"  Verification Latency: {verify_latency:.1f}ms, Tokens: {verify_tokens}")
            
            # ==================== Determination ====================
            p("\n[Determination]")
            
            # 1. Check if keywords match
            keywords_matched = all(
                kw.lower() in verify_response.lower() 
                for kw in scenario.expected_keywords
            )
            p(f"  • Keywords matched: {'✓' if keywords_matched else '✗'}")
            if not keywords_matched:
                missing = [kw for kw in scenario.expected_keywords if kw.lower() not in verify_response.lower()]
                p(f"    Missing keywords: {missing}")
            
            # 2. Check negative keywords (should NOT appear)
            negative_found = False
            combined_negative = list(set(NEGATIVE_PATTERNS + (scenario.negative_keywords or [])))
            negative_found = any(
                kw.lower() in verify_response.lower() 
                for kw in combined_negative
            )
            p(f"  • No error keywords: {'✗ (Error found)' if negative_found else '✓'}")
            
            # 3. Whether LLM response is reasonable
            llm_response_valid = len(verify_response) >= 2 
            p(f"  • LLM response valid: {'✓' if llm_response_valid else '✗'}")
            
            # ===== 5 Indicators Core Calculation =====
            
            # SPR (State Persistence Rate): Whether state is persistent (non-negative, non-empty)
            # Definition: implant success AND no negative patterns AND response not empty
            is_empty_response = len(verify_response.strip()) < 5
            state_persisted = implant_success and not negative_found and not is_empty_response
            p(f"  • SPR (State Existence): {'✓' if state_persisted else '✗'}")
            
            # SFR (State Fidelity Rate): Whether state content is accurate (keywords match)
            # Definition: implant success AND keywords matched
            state_fidelity = implant_success and keywords_matched
            p(f"  • SFR (State Fidelity): {'✓' if state_fidelity else '✗'}")
            
            # PDR (Probing Deception Rate): Comprehensive success
            # Definition: SPR AND SFR
            state_persistent = state_persisted and state_fidelity
            p(f"  • PDR (Comprehensive Success): {'✓' if state_persistent else '✗'}")
            
            # Final determination
            verify_success = state_persistent
            status = "✓ PASS" if verify_success else "✗ FAIL"
            p(f"\n  {status}")
            
            return E2ETestResult(
                scenario_id=scenario.scenario_id,
                mitre_id=scenario.mitre_id,
                technique=scenario.technique,
                implant_success=implant_success,
                implant_response=implant_response,
                verify_success=verify_success,
                verify_response=verify_response,
                llm_response_valid=llm_response_valid,
                state_persistent=state_persistent,
                keywords_matched=keywords_matched,
                # New indicator fields
                state_persisted=state_persisted,
                state_fidelity=state_fidelity,
                implant_latency_ms=implant_latency,
                verify_latency_ms=verify_latency,
                implant_tokens=implant_tokens,
                verify_tokens=verify_tokens + noise_tokens_this_scenario  # Includes noise token consumption
            )
            
        except Exception as e:
            p(f"  ✗ Exception: {e}")
            import traceback
            traceback.print_exc()
            return E2ETestResult(
                scenario_id=scenario.scenario_id,
                mitre_id=scenario.mitre_id,
                technique=scenario.technique,
                implant_success=False,
                implant_response="",
                verify_success=False,
                verify_response="",
                llm_response_valid=False,
                state_persistent=False,
                keywords_matched=False,
                error=str(e)
            )
    
    async def run_all_tests(self) -> List[E2ETestResult]:
        """Run all end-to-end tests"""
        p(f"\n[4/5] Starting end-to-end testing ({len(E2E_TEST_SCENARIOS)} scenarios)")
        p(f"Note: This will call real {api_provider.upper()} API")
        
        # Clear previous results before each run
        self.results = []
        
        for i, scenario in enumerate(E2E_TEST_SCENARIOS, 1):
            result = await self.run_single_test(scenario, i)
            self.results.append(result)
            
            # Add slight delay between tests to avoid API rate limiting
            if i < len(E2E_TEST_SCENARIOS):
                await asyncio.sleep(1)
        
        return self.results

    def _calculate_round_metrics(self, results: List[E2ETestResult], round_num: int) -> RoundMetrics:
        """Calculate single round metrics"""
        total = len(results)
        if total == 0:
            return RoundMetrics(round_num, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            
        passed = sum(1 for r in results if r.state_persistent)
        
        # Core Metrics
        spr = sum(1 for r in results if r.state_persisted) / total
        sfr = sum(1 for r in results if r.state_fidelity) / total
        
        # PDR by Tier
        def calc_tier_pdr(tier_scenarios):
            tier_results = [r for r in results if r.scenario_id in tier_scenarios]
            if not tier_results:
                return 0.0
            return sum(1 for r in tier_results if r.state_persistent) / len(tier_results)
        
        pdr_high = calc_tier_pdr(COMPLEXITY_TIERS['high'])
        pdr_medium = calc_tier_pdr(COMPLEXITY_TIERS['medium'])
        pdr_low = calc_tier_pdr(COMPLEXITY_TIERS['low'])
        
        # Cost Metrics
        avg_implant_latency = sum(r.implant_latency_ms for r in results) / total
        avg_verify_latency = sum(r.verify_latency_ms for r in results) / total
        avg_latency = (avg_implant_latency + avg_verify_latency) / 2
        
        total_tokens = sum(r.implant_tokens + r.verify_tokens for r in results)
        
        return RoundMetrics(
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

    def _aggregate_metrics(self, all_round_metrics: List[RoundMetrics]) -> Dict[str, Any]:
        """Aggregate multiple round metrics"""
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
        
        return aggregated

    async def run_multi_round_test(self, num_rounds: int) -> Dict[str, Any]:
        """Run multi-round test and aggregate statistics"""
        p(f"\n{'#'*70}")
        p(f"# PromptShield E2E Test - {num_rounds} Rounds")
        p(f"# Mode: State Injection via MCP")
        p(f"# Scenarios per round: {len(E2E_TEST_SCENARIOS)}")
        p(f"{'#'*70}")
        
        all_round_metrics = []
        all_round_results = []
        
        for round_num in range(1, num_rounds + 1):
            p(f"\n{'='*60}")
            p(f"ROUND {round_num}")
            p(f"{'='*60}")
            
            # Clean old state to ensure rounds are independent
            await self.cleanup()
            await self.setup()
            
            # Run test
            results = await self.run_all_tests()
            all_round_results.append([asdict(r) for r in results])
            
            # Calculate metrics
            metrics = self._calculate_round_metrics(results, round_num)
            all_round_metrics.append(metrics)
            
            p(f"\n  Round {round_num} Results:")
            p(f"    SPR: {metrics.spr:.1%}, SFR: {metrics.sfr:.1%}")
            p(f"    PDR: High={metrics.pdr_high:.1%}, Medium={metrics.pdr_medium:.1%}, Low={metrics.pdr_low:.1%}")
            p(f"    Latency: {metrics.avg_latency_ms:.1f}ms")
            p(f"    Total Tokens: {metrics.total_tokens:,}")
            
        # Aggregate results
        aggregated = self._aggregate_metrics(all_round_metrics)
        
        p(f"\n{'='*70}")
        p("AGGREGATED RESULTS (across all rounds)")
        p(f"{'='*70}")
        p(f"\n=== D1: State Fidelity ===")
        p(f"SPR (State Persistence Rate): {aggregated['spr']['mean']:.1%} ± {aggregated['spr']['std']:.1%}")
        p(f"SFR (State Fidelity Rate):    {aggregated['sfr']['mean']:.1%} ± {aggregated['sfr']['std']:.1%}")
        
        p(f"\n=== D2: Attack Resilience (PDR by Complexity) ===")
        p(f"  High-Complexity:   {aggregated['pdr_high']['mean']:.1%} ± {aggregated['pdr_high']['std']:.1%}")
        p(f"  Medium-Complexity: {aggregated['pdr_medium']['mean']:.1%} ± {aggregated['pdr_medium']['std']:.1%}")
        p(f"  Low-Complexity:    {aggregated['pdr_low']['mean']:.1%} ± {aggregated['pdr_low']['std']:.1%}")
        
        p(f"\n=== D3: Operational Cost ===")
        p(f"Avg Latency: {aggregated['latency_ms']['mean']:.1f}ms ± {aggregated['latency_ms']['std']:.1f}ms")
        p(f"Total Tokens: {aggregated['total_tokens']['mean']:.0f} ± {aggregated['total_tokens']['std']:.0f}")
        
        return {
            "aggregated": aggregated,
            "rounds": [asdict(m) for m in all_round_metrics],
            "raw_results": all_round_results
        }
    
    def generate_report(self) -> str:
        """Generate text report (for final viewing)"""
        if not self.results:
            return "No results available."
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r.verify_success)
        failed = total - passed
        
        lines = []
        lines.append("\n" + "="*70)
        lines.append(f"  [Report] PromptShield Test Report (Last Round)")
        lines.append("="*70)
        lines.append(f"\nTotal: {total} | Passed: {passed} | Failed: {failed} | Pass Rate: {passed/total*100:.1f}%\n")
        
        lines.append("-"*70)
        lines.append(f"{'Scenario ID':<18} {'MITRE ID':<14} {'Result':<8} {'Detail'}")
        lines.append("-"*70)
        
        for r in self.results:
            status = "✓ PASS" if r.verify_success else "✗ FAIL"
            detail = "Persistence success" if r.state_persistent else "Persistence failure"
            lines.append(f"{r.scenario_id:<18} {r.mitre_id:<14} {status:<8} {detail}")
        
        lines.append("-"*70)
        
        return "\n".join(lines)
    
    def save_report_json(self, data: Dict[str, Any], filename: str = "promptshield_multi_round.json"):
        """Save multi-round test JSON report"""
        test_time = datetime.now()
        
        # Ensure data contains basic metadata
        if "meta" not in data:
            data["meta"] = {
                "test_time": test_time.isoformat(),
                "api_provider": api_provider,
                "framework": "PromptShield"
            }
        
        # Save latest result (overwrite)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Also save historical version with timestamp
        timestamp = test_time.strftime("%Y%m%d_%H%M%S")
        history_filename = f"promptshield_final_{timestamp}.json"
        with open(history_filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        p(f"\n✓ JSON report saved: {filename}")
        p(f"✓ Historical version saved: {history_filename}")


# ============== Main Function ==============

async def async_main(num_rounds: int, output_file: str, noise_level: int = 0, noise_position: str = "sandwich"):
    """Main Function"""
    executor = E2ETestExecutor(storage_path="./test_e2e_memory", 
                               noise_level=noise_level, noise_position=noise_position)
    
    try:
        # Show noise config
        if noise_level > 0:
            p(f"\n[Lost-in-the-Middle Control Mode]")
            p(f"  Noise Level: {noise_level}")
            p(f"  Noise Position: {noise_position}")
            p(f"  Note: PromptShield uses O(1) state management; noise is only for load comparison")
        
        # Use new multi-round test method
        results = await executor.run_multi_round_test(num_rounds)
        
        # Adjust output file name based on noise level
        if noise_level > 0:
            base_name = output_file.rsplit('.', 1)[0]
            output_file = f"{base_name}_noise{noise_level}_{noise_position}.json"
        
        # Save JSON
        executor.save_report_json(results, output_file)
        
    except KeyboardInterrupt:
        p("\n\nTest interrupted by user")
    except Exception as e:
        p(f"\nTest execution error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await executor.cleanup()
    
    p("\n" + "="*70)
    p("End-to-End Test Completed!")
    p("="*70)


def main():
    parser = argparse.ArgumentParser(description="PromptShield E2E Test")
    parser.add_argument("--rounds", type=int, default=1, help="Number of test rounds")
    parser.add_argument("--output", type=str, default="promptshield_results.json", help="Output JSON file")
    parser.add_argument("--noise-level", type=int, default=0,
                        help="Noise injection level for Lost-in-the-Middle comparison (0=none, 10/50/100)")
    parser.add_argument("--noise-position", type=str, default="sandwich",
                        choices=["prefix", "suffix", "sandwich"],
                        help="Noise position for fair comparison with shelLM")
    args = parser.parse_args()
    
    # Set global noise parameters
    asyncio.run(async_main(num_rounds=args.rounds, output_file=args.output,
                           noise_level=args.noise_level, noise_position=args.noise_position))


if __name__ == "__main__":
    main()
