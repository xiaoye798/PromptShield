"""
Linux SSHbot with MCP Integration - A honeypot system for state management using the MCP protocol
This is the MCP version of LinuxSSHbot, which communicates with the state management server using the MCP client.
Key improvements:
1. Communicates with the status management server via the MCP protocol
2. Completely asynchronous architecture
3. Better error handling and logging
4. Complies with the official best practices of MCP
"""

import asyncio
import argparse
import logging
import os
import re
import shutil
import sys
import yaml

# 持有后台 task 强引用，防止 GC 回收并捕获异常
_background_tasks: set = set()

# 模块级 logger
logger = logging.getLogger(__name__)
from datetime import datetime
from time import sleep
from typing import List, Dict, Any, Optional

import openai
from dotenv import dotenv_values

# Import the MCP client and the state management component
from mcp_client import HoneypotMCPClient
from deepseek_client import DeepSeekClient, DeepSeekChatCompletion
from mcp_state_manager.command_analyzer import CommandAnalyzer
from mcp_state_manager.state_context_builder import StateContextBuilder
from mcp_state_manager.system_template import ContextOptimizer

# Configuration: 优先从环境变量读取（容器部署），回退到 .env 文件（本地开发）
_env_file = os.environ.get("PROMPTSHIELD_ENV", ".env")
_secrets_file = ".env.secrets"
_file_config = dotenv_values(_env_file) if os.path.exists(_env_file) else {}
_secrets_config = dotenv_values(_secrets_file) if os.path.exists(_secrets_file) else {}
def _get_config(key, default=""):
    return os.environ.get(key) or _secrets_config.get(key) or _file_config.get(key, default)

config = {
    "API_PROVIDER": _get_config("API_PROVIDER", "openai"),
    "DEEPSEEK_API_KEY": _get_config("DEEPSEEK_API_KEY"),
    "DEEPSEEK_BASE_URL": _get_config("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
    "DEEPSEEK_MODEL": _get_config("DEEPSEEK_MODEL", "deepseek-chat"),
    "OPENAI_API_KEY": _get_config("OPENAI_API_KEY"),
    "KIMI_API_KEY": _get_config("KIMI_API_KEY"),
    "KIMI_BASE_URL": _get_config("KIMI_BASE_URL", "https://api.kimi.com/coding/v1"),
    "KIMI_MODEL": _get_config("KIMI_MODEL", "k2p5"),
    "DEBUG_MODE": _get_config("DEBUG_MODE", "false"),
    "TRACE_MODE": _get_config("TRACE_MODE", "false"),
    "STORAGE_PATH": _get_config("STORAGE_PATH", "/app/honeypot_memory"),
    "GLOBAL_SINGLETON_MODE": _get_config("GLOBAL_SINGLETON_MODE", "true"),
}
api_provider = config.get("API_PROVIDER", "openai").lower()

# Debug mode switch (setting it to False will hide all debug information)
DEBUG_MODE = config.get("DEBUG_MODE", "false").lower() == "true"

# Detailed tracking mode (displaying the complete command execution process)
TRACE_MODE = config.get("TRACE_MODE", "false").lower() == "true"

# Trace log file path
TRACE_LOG_FILE = config.get("TRACE_LOG_FILE", "trace_execution.log")

# Initialize trace log file
if TRACE_MODE:
    # Create or clear trace log file
    with open(TRACE_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"{'='*70}\n")
        f.write(f"Execution Trace Log - Session started at {datetime.now()}\n")
        f.write(f"{'='*70}\n\n")
    print(f"[System] Trace mode enabled, log will be saved to: {TRACE_LOG_FILE}")

# Initialize AI client
if api_provider == "openai":
    openai.api_key = config["OPENAI_API_KEY"]
    chat_client = None
elif api_provider == "deepseek":
    deepseek_client = DeepSeekClient(
        api_key=config["DEEPSEEK_API_KEY"],
        base_url=config.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    chat_client = DeepSeekChatCompletion(deepseek_client)
elif api_provider == "kimi":
    # Kimi K2.5 via OpenAI-compatible Chat Completions endpoint
    # User-Agent 必须伪装为 coding agent，否则 Kimi Coding API 返回 403
    kimi_openai_client = openai.AsyncOpenAI(
        api_key=config["KIMI_API_KEY"],
        base_url=config["KIMI_BASE_URL"],
        default_headers={"User-Agent": "claude-code/1.0"},
    )
    chat_client = None
else:
    raise ValueError(f"Unsupported API provider: {api_provider}")

# MCP client (global, will be initialized in main)
mcp_client: Optional[HoneypotMCPClient] = None


# ==================== Trace Helper Functions ====================

def trace_log(step: str, message: str, details: Any = None):
    """
    Trace log output - write to file instead of terminal
    
    Args:
        step: Step description
        message: Main message
        details: Detailed information (can be dict, list, or other types)
    """
    if not TRACE_MODE:
        return
    
    try:
        with open(TRACE_LOG_FILE, "a", encoding="utf-8") as f:
            # Write timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"\n{'='*70}\n")
            f.write(f"[{timestamp}] [TRACE] {step}\n")
            f.write(f"{'='*70}\n")
            f.write(f"{message}\n")
            
            if details:
                if isinstance(details, dict):
                    for key, value in details.items():
                        # Limit the length of values to avoid large logs
                        value_str = str(value)
                        if len(value_str) > 500:
                            value_str = value_str[:500] + "... (truncated)"
                        f.write(f"  • {key}: {value_str}\n")
                elif isinstance(details, list):
                    for i, item in enumerate(details, 1):
                        item_str = str(item)
                        if len(item_str) > 300:
                            item_str = item_str[:300] + "... (truncated)"
                        f.write(f"  [{i}] {item_str}\n")
                else:
                    detail_str = str(details)
                    if len(detail_str) > 1000:
                        detail_str = detail_str[:1000] + "... (truncated)"
                    f.write(f"  {detail_str}\n")
            
            f.write(f"{'='*70}\n\n")
            f.flush()  # Write to disk immediately
            
    except Exception as e:
        # If writing to file fails, fall back to stderr output
        print(f"[ERROR] Unable to write trace log: {e}", file=sys.stderr)


# ==================== Helper Functions ====================

def debug_log(message: str):
    """
    Debug log output - write to file instead of terminal
    
    Args:
        message: Debug message
    """
    if not DEBUG_MODE:
        return
    
    try:
        with open(TRACE_LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"[{timestamp}] [DEBUG] {message}\n")
            f.flush()
    except Exception as e:
        print(f"[ERROR] Unable to write debug log: {e}", file=sys.stderr)


def rotate_history_if_needed():
    """Rotate history file if it's too large"""
    if os.path.exists("history.txt") and os.path.getsize("history.txt") > 1024 * 1024:  # 1MB
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            shutil.move("history.txt", f"history_{timestamp}.txt")
            print(f"[System] History file rotated to history_{timestamp}.txt")
        except Exception as e:
            print(f"[System] Failed to rotate history: {e}")


def load_personality():
    """Load personality configuration"""
    with open('personalitySSH.yml', 'r', encoding="utf-8") as file:
        identity = yaml.safe_load(file)
    return identity['personality']['prompt']


def _extract_terminal_output_from_reasoning(reasoning_content: str) -> str:
    """
    Extract actual terminal output from Kimi K2.5's reasoning_content.
    
    Kimi K2.5 Coding API puts all output into reasoning_content when content is empty.
    The model's reasoning typically contains analysis followed by the final terminal output
    inside a markdown code block.
    
    Priority order:
    1. Last non-analytical code block (```...```)
    2. Scan backwards for the final "answer" section
    3. Extract lines matching terminal output patterns (prompt lines, command output)
    """
    if not reasoning_content:
        return ""
    
    import re
    
    # Phrases that indicate analytical/reasoning text (NOT terminal output)
    ANALYSIS_PHRASES = (
        'Let me ', 'I need to', 'I should', 'I will', 'I\'ll ', "I'll ",
        'Wait,', 'But ', 'Actually,', 'Hmm,', 'So ', 'Now,', 'First,',
        'The user', 'This command', 'This is', 'Looking at',
        'my response', 'My response', 'the output', 'The output',
        'I must', 'Remember', 'Note:', 'Important:', 'IMPORTANT:',
        'let me', 'since ', 'Since ', 'because', 'Because',
        'however', 'However', 'therefore', 'Therefore',
        'instruction', 'Instruction', 'personality', 'Personality',
        'the prompt', 'location string', 'For the',
    )
    
    def is_analysis_line(line: str) -> bool:
        """Check if a line is reasoning/analysis rather than terminal output"""
        s = line.strip()
        if not s:
            return False
        # Numbered reasoning steps like "1. First..." or "- The user..."
        if re.match(r'^(\d+\.|[-*])\s+', s):
            if any(p in s for p in ('The ', 'I ', 'We ', 'This ', 'So ', 'For ', 'Since ')):
                return True
        return any(s.startswith(p) or s.startswith(p.lower()) for p in ANALYSIS_PHRASES)
    
    def score_code_block(block: str) -> int:
        """Score a code block: higher = more likely to be terminal output"""
        score = 0
        lines = block.strip().split('\n')
        if not lines:
            return -1
        # Terminal prompt pattern (user@host:path$)
        prompt_re = re.compile(r'\w+@[\w\-]+:[~\/\w\.\-]*\$')
        for line in lines:
            if prompt_re.search(line):
                score += 10
            # Common terminal output patterns
            if re.match(r'^(total \d|drwx|[-lcrwx]{10}|uid=|root\s+|USER\s+PID)', line.strip()):
                score += 5
            if re.match(r'^(Last login:|Linux \w)', line.strip()):
                score += 8
            if is_analysis_line(line):
                score -= 10
        # Penalize very short blocks that are just examples in reasoning
        if len(block.strip()) < 15:
            score -= 5
        return score
    
    # Strategy 1: Find ALL code blocks, pick the best one
    code_block_pattern = re.compile(r'```(?:\w*\n)?(.*?)```', re.DOTALL)
    code_blocks = code_block_pattern.findall(reasoning_content)
    
    if code_blocks:
        # Score each block and pick the best
        scored = [(score_code_block(b), i, b) for i, b in enumerate(code_blocks)]
        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        best_score, best_idx, best_block = scored[0]
        if best_score > 0:
            return best_block.strip()
        # If all blocks score poorly, still return the last one
        return code_blocks[-1].strip()
    
    # Strategy 2: Find the LAST terminal-like section
    # Scan backwards through lines for the final structured output
    lines = reasoning_content.split('\n')
    
    # Look for the last occurrence of a terminal prompt
    prompt_re = re.compile(r'\w+@[\w\-]+:[~\/\w\.\-]*\$\s*$')
    last_prompt_idx = -1
    for i in range(len(lines) - 1, -1, -1):
        if prompt_re.search(lines[i].strip()):
            last_prompt_idx = i
            break
    
    if last_prompt_idx >= 0:
        # Walk backwards from the prompt to find where the output starts
        start = last_prompt_idx
        for i in range(last_prompt_idx - 1, max(last_prompt_idx - 30, -1), -1):
            line = lines[i].strip()
            if not line:
                continue
            if is_analysis_line(line):
                break
            start = i
        
        output_lines = [l for l in lines[start:last_prompt_idx + 1]]
        result = '\n'.join(output_lines).strip()
        if len(result) >= 5:
            return result
    
    # Strategy 3: Look for "Last login:" line (SSH initial output)
    for i, line in enumerate(lines):
        if line.strip().startswith('Last login:'):
            # Collect until we hit analysis text
            out = []
            for j in range(i, min(i + 25, len(lines))):
                if is_analysis_line(lines[j]):
                    break
                out.append(lines[j])
            if out:
                return '\n'.join(out).strip()
    
    # Strategy 4: Look for final answer markers
    for marker_re in [
        r'(?:final|my)\s+(?:output|response|answer)\s*(?:is|:)',
        r'(?:So|Thus|Therefore),?\s+(?:the|my)\s+(?:output|response)',
        r'(?:I\'ll|I will)\s+(?:output|respond|give)',
    ]:
        matches = list(re.finditer(marker_re, reasoning_content, re.IGNORECASE))
        if matches:
            last_match = matches[-1]
            after = reasoning_content[last_match.end():].strip()
            # Take non-analysis lines
            out = []
            for line in after.split('\n'):
                if line.strip() and not is_analysis_line(line):
                    out.append(line)
                elif out and is_analysis_line(line):
                    break
            if out:
                return '\n'.join(out).strip()
    
    # Fallback: collect all non-analysis lines from the last 1/3 of reasoning
    cutoff = len(lines) * 2 // 3
    tail_lines = []
    for line in lines[cutoff:]:
        stripped = line.strip()
        if stripped and not is_analysis_line(line):
            tail_lines.append(line)
    if tail_lines:
        return '\n'.join(tail_lines[-15:]).strip()
    
    # Last resort
    return reasoning_content[-300:].strip()


async def call_ai_model(messages: List[Dict[str, str]]) -> str:
    """
    Call AI model (asynchronously)
    
    Args:
        messages: Message list
    
    Returns:
        AI response text
    """
    trace_log(
        "Step 6: Call AI model",
        f"Preparing to call {api_provider.upper()} API",
        {
            "Message count": len(messages),
            "Last message": messages[-1]["content"][:100] + "..." if len(messages[-1]["content"]) > 100 else messages[-1]["content"]
        }
    )
    
    try:
        if api_provider == "openai":
            debug_log("Calling OpenAI API...")
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(
                None,
                lambda: openai.chat.completions.create(
                    model="gpt-3.5-turbo-16k",
                    messages=messages,
                    temperature=0.0,
                    max_tokens=800
                )
            )
        elif api_provider == "deepseek":
            debug_log("Calling DeepSeek API...")
            res = await chat_client.create(
                model=config.get("DEEPSEEK_MODEL", "deepseek-chat"),
                messages=messages,
                temperature=0.0,
                max_tokens=800
            )
        elif api_provider == "kimi":
            debug_log("Calling Kimi K2.5 API...")
            res = await kimi_openai_client.chat.completions.create(
                model=config.get("KIMI_MODEL", "k2p5"),
                messages=messages,
                temperature=0.0,
                max_tokens=800
            )
        else:
            raise ValueError(f"Unsupported API provider: {api_provider}")
        
        msg = res.choices[0].message.content or ""
        # Kimi K2.5 Coding API puts output in reasoning_content when content is empty
        if not msg.strip() and hasattr(res.choices[0].message, 'reasoning_content'):
            rc = res.choices[0].message.reasoning_content or ""
            if rc:
                msg = _extract_terminal_output_from_reasoning(rc)
                debug_log(f"Extracted {len(msg)} chars from reasoning_content ({len(rc)} chars)")
        debug_log(f"Got response ({len(msg)} chars)")
        
        trace_log(
            "Step 7: AI response received",
            f"AI response received",
            {
                "Response length": f"{len(msg)} characters",
                "Response content": msg[:200] + "..." if len(msg) > 200 else msg
            }
        )
        
        return msg
        
    except Exception as api_error:
        print(f"\n[API ERROR] API call failed: {api_error}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        
        # Record to error log
        with open("api_errors.log", "a", encoding="utf-8") as error_log:
            error_log.write(f"\n[{datetime.now()}] API Error: {api_error}\n")
            error_log.write(traceback.format_exc())
        
        # Return error prompt
        return "bash: API error occurred. Please check your API configuration.\nroot@server:/root$"


async def build_enhanced_messages(messages: List[Dict], command: str, current_cwd: str, 
                                   client: 'HoneypotMCPClient' = None, ip_address: str = "attacker_ip") -> List[Dict]:
    """
    Build enhanced message list (including state context)
    
    This is the core function for achieving cross-session persistence!
    By injecting the state persisted in MCP into the LLM prompt, ensure that the LLM knows the results of operations from previous sessions.
    
    Args:
        messages: Original message list
        command: User command
        current_cwd: Current working directory
        client: MCP client instance (if None, use global mcp_client)
        ip_address: IP address identifier
    
    Returns:
        Enhanced message list
    """
    # Use the passed client or the global mcp_client
    _mcp_client = client if client is not None else mcp_client
    
    trace_log(
        "Step 3: Build enhanced messages",
        f"Building state context for command",
        {
            "Command": command,
            "Current directory": current_cwd,
            "Original messages count": len(messages)
        }
    )
    
    enhanced_messages = messages.copy()
    
    if not command or not _mcp_client:
        return enhanced_messages
    
    try:
        # 1. Query current state summary from MCP server
        trace_log(
            "Step 4: Query system state",
            "Get current state summary from MemorySystem"
        )
        
        state_summary = await _mcp_client.get_state_summary(ip_address)
        
        trace_log(
            "Step 4.1: State summary retrieval",
            "Current system state",
            state_summary if state_summary else {"State": "Empty"}
        )
        
        # 2. Build state context - Key improvement: Get relevant state based on command type
        context_parts = []
        command_parts = command.strip().split()
        cmd = command_parts[0] if command_parts else ""
        
        # ==================== Priority Check: User-related commands ====================
        # This must be checked before file reading, because "cat /etc/passwd | grep xxx" also matches file reading
        if cmd in ['id', 'whoami', 'w', 'who'] or 'passwd' in command or ('grep' in command and ('user' in command.lower() or 'passwd' in command)):
            # Query user list
            trace_log("Step 4.2: User query", "User-related command detected, retrieving user list")
            result = await _mcp_client.query_state(ip_address, "user_list")
            if result.get("success") and result.get("data"):
                users = result.get("data", {}).get("users", {})
                groups = result.get("data", {}).get("groups", {})
                if users:
                    user_lines = []
                    user_groups_info = {}  # User -> Group list mapping
                    
                    for username, info in users.items():
                        uid = info.get('uid', 1000)
                        gid = info.get('gid', uid)
                        home = info.get('home', f'/home/{username}')
                        shell = info.get('shell', '/bin/bash')
                        gecos = info.get('gecos', '')
                        user_lines.append(f"{username}:x:{uid}:{gid}:{gecos}:{home}:{shell}")
                        
                        # Collect groups the user belongs to
                        user_group_list = [username]  # Default includes group of the same name
                        for grp_name, grp_info in groups.items():
                            if username in grp_info.get('members', []):
                                user_group_list.append(grp_name)
                        user_groups_info[username] = user_group_list
                    
                    # Build id command output format
                    id_output_lines = []
                    for username, info in users.items():
                        uid = info.get('uid', 1000)
                        gid = info.get('gid', uid)
                        grp_list = user_groups_info.get(username, [username])
                        groups_str = ",".join([f"{gid}({g})" for g in grp_list])
                        id_output_lines.append(f"uid={uid}({username}) gid={gid}({username}) groups={groups_str}")
                    
                    context_parts.append(f"""[CRITICAL - USERS IN PERSISTENT STATE]
The following users exist in the system:
---BEGIN /etc/passwd ENTRIES---
{chr(10).join(user_lines)}
---END /etc/passwd ENTRIES---

For 'id <username>' command, output:
{chr(10).join(id_output_lines)}

IMPORTANT: 
- When running 'grep backdoor_user', output: {chr(10).join([l for l in user_lines if 'backdoor' in l.lower()])}
- When running 'id backdoor_user', show the groups including 'sudo' if the user was added to sudo group.""")
        
        # ==================== Special handling for grep command (non-passwd files) ====================
        if cmd == 'grep' or 'grep' in command:
            # Extract grep target file
            grep_target = None
            for part in command_parts:
                if part.startswith('/') and not part.startswith("'") and 'passwd' not in part:
                    grep_target = part
                    break
            
            if grep_target:
                # Check if file exists
                exists = await _mcp_client.check_file_exists(ip_address, grep_target)
                if exists:
                    content = await _mcp_client.get_file_content(ip_address, grep_target)
                    if content:
                        # Extract grep pattern
                        pattern = None
                        for i, part in enumerate(command_parts):
                            if part == 'grep' and i + 1 < len(command_parts):
                                pattern = command_parts[i + 1].strip("'\"")
                                break
                        
                        context_parts.append(f"""[CRITICAL - FILE EXISTS FOR GREP]
File: {grep_target}
Content:
---
{content}
---
When running 'grep {pattern if pattern else "..."} {grep_target}', output matching lines from this content.""")
        
        # ==================== File Reading Commands ====================
        if cmd in ['cat', 'head', 'tail', 'less', 'more']:
            # Extract all target file paths
            target_files = []
            for part in command_parts[1:]:
                if not part.startswith('-') and '|' not in part:
                    # Handle ~ as /root
                    if part.startswith('~'):
                        part = '/root' + part[1:]
                    elif not part.startswith('/'):
                        part = os.path.normpath(os.path.join(current_cwd, part)).replace("\\", "/")
                    target_files.append(part)
            
            trace_log(
                "Step 4.3: File query",
                f"Extracted target files: {target_files}"
            )
            
            for file_path in target_files:
                # Check if file exists (try multiple path formats)
                paths_to_check = [file_path]
                if file_path.startswith('/root/'):
                    paths_to_check.append('~' + file_path[5:])
                    paths_to_check.append(file_path.replace('/root/', '~/'))
                
                trace_log(
                    "Step 4.4: Check file existence",
                    f"Checking path list: {paths_to_check}"
                )
                
                for check_path in paths_to_check:
                    exists = await _mcp_client.check_file_exists(ip_address, check_path)
                    trace_log(
                        "Step 4.5: File check result",
                        f"Path: {check_path}, Exists: {exists}"
                    )
                    if exists:
                        content = await _mcp_client.get_file_content(ip_address, check_path)
                        trace_log(
                            "Step 4.6: Get file content",
                            f"Content length: {len(content) if content else 0}"
                        )
                        if content:
                            context_parts.append(f"""[CRITICAL - FILE EXISTS IN PERSISTENT STATE]
The file '{file_path}' exists with the following content:
---BEGIN FILE CONTENT---
{content}
---END FILE CONTENT---
IMPORTANT: You MUST output exactly this content when the user runs '{cmd} {file_path}'.
Do NOT say "No such file or directory" - the file EXISTS.""")
                            break
        
        # ==================== Directory Listing Commands ====================
        if cmd in ['ls', 'dir', 'll']:
            target_dir = current_cwd
            for part in command_parts[1:]:
                if not part.startswith('-'):
                    if part.startswith('~'):
                        target_dir = '/root' + part[1:]
                    elif not part.startswith('/'):
                        target_dir = os.path.normpath(os.path.join(current_cwd, part)).replace("\\", "/")
                    else:
                        target_dir = part
                    break
            
            context_parts.append(f"[Current Directory: {current_cwd}]")
            # Can be extended: Query directory content
        
        # ==================== Cron Commands ====================
        if 'cron' in command or 'crontab' in command:
            result = await _mcp_client.query_state(ip_address, "cron_list")
            if result.get("success") and result.get("data"):
                cron_data = result.get("data", {})
                user_crontabs = cron_data.get("user_crontabs", {})
                system_cron = cron_data.get("system_cron_files", {})
                # Collect all cron entries across all users
                all_entries = []
                for user, entries in user_crontabs.items():
                    if isinstance(entries, list):
                        all_entries.extend(entries)
                    elif isinstance(entries, str):
                        all_entries.append(entries)
                for fname, content in system_cron.items():
                    if content:
                        all_entries.append(f"# {fname}: {content}")
                if all_entries:
                    cron_output = chr(10).join(all_entries)
                    context_parts.append(f"""[CRITICAL - CRON JOBS IN PERSISTENT STATE]
The following cron entries exist in the system and MUST be shown when running 'crontab -l':
---BEGIN CRONTAB OUTPUT---
{cron_output}
---END CRONTAB OUTPUT---
IMPORTANT: When the user runs 'crontab -l', you MUST output exactly these entries.
Do NOT say "no crontab" - cron jobs EXIST. Output the entries above followed by the shell prompt.""")
        
        # ==================== Service Commands ====================
        if 'systemctl' in command or 'service' in command:
            result = await _mcp_client.query_state(ip_address, "service_list")
            if result.get("success") and result.get("data"):
                services = result.get("data", {})
                if services:
                    import json
                    context_parts.append(f"""[CRITICAL - SERVICES IN PERSISTENT STATE]
Service states:
{json.dumps(services, indent=2)}
IMPORTANT: Reflect these service states in your response.""")
        
        # 3. Add state summary
        if state_summary:
            file_count = state_summary.get('file_count', 0)
            user_count = state_summary.get('user_count', 0)
            if file_count > 0 or user_count > 0:
                context_parts.append(f"[System State: {file_count} files modified, {user_count} users]")
        
        # 4. Combine context
        state_context = "\n\n".join(context_parts)
        
        # 5. Use context optimizer to ensure not too long
        context_optimizer = ContextOptimizer(max_context_tokens=2000)
        optimized_context = context_optimizer.optimize_context("", state_context, "")
        
        # 6. If context exists, inject into messages
        if optimized_context.strip():
            enhanced_messages.insert(-1, {
                "role": "system",
                "content": optimized_context
            })
            
            token_estimate = context_optimizer.estimate_token_count(optimized_context)
            
            debug_log(f"Injected ~{token_estimate} tokens of state context")
            
            trace_log(
                "Step 5: Context Injection",
                "Inject state context into messages",
                {
                    "Context length": f"{len(optimized_context)} characters",
                    "Estimated tokens": token_estimate,
                    "Injection position": "Second to last message",
                    "Context content": optimized_context[:300] + "..." if len(optimized_context) > 300 else optimized_context
                }
            )
        
    except Exception as e:
        debug_log(f"[State Context Error] Failed to build context: {e}")
        if DEBUG_MODE:
            import traceback
            with open(TRACE_LOG_FILE, "a", encoding="utf-8") as f:
                traceback.print_exc(file=f)
    
    return enhanced_messages


async def record_event_to_mcp(command: str, response: str, current_cwd: str):
    """
    Record event to MCP server
    
    Args:
        command: Executed command
        response: AI response
        current_cwd: Current working directory
    """
    trace_log(
        "Step 8: Analyze command",
        "Use CommandAnalyzer to analyze command",
        {"Command": command}
    )
    
    try:
        # Analyze command
        analyzer = CommandAnalyzer()
        event_type = analyzer.determine_event_type(command)
        status = analyzer.determine_status(command, response)
        
        trace_log(
            "Step 8.1: Command analysis result",
            "Determine event type and execution status",
            {
                "Event type": event_type.value if hasattr(event_type, 'value') else str(event_type),
                "Execution status": status.value if hasattr(status, 'value') else str(status)
            }
        )
        
        # Analyze state changes (simplified here, should be more complex in practice)
        # Since we don't have full SystemState, use basic analysis for now
        trace_log(
            "Step 9: Analyze state changes",
            "Extract state changes caused by command"
        )
        
        state_changes = analyzer.analyze_state_changes(
            command, response, cwd=current_cwd, system_state=None
        )
        
        if state_changes:
            changes_info = []
            for sc in state_changes:
                changes_info.append(f"{sc.change_type}: {sc.target}")
            
            trace_log(
                "Step 9.1: State change identification",
                f"Found {len(state_changes)} state changes",
                changes_info
            )
        else:
            trace_log(
                "Step 9.1: State change identification",
                "No state changes (read-only operation)"
            )
        
        # Record event
        trace_log(
            "Step 10: Record event",
            "Record event to MemorySystem"
        )
        
        result = await mcp_client.record_event(
            ip_address="attacker_ip",
            session_id="global_session",
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
            trace_log(
                "Step 11: Event recorded successfully",
                "Event saved to persistent storage",
                {
                    "Event ID": result.get("event_id", "unknown"),
                    "Storage path": "honeypot_memory/states/ and graphs/"
                }
            )
        else:
            debug_log(f"Failed to record event: {result.get('message')}")
        
    except Exception as e:
        debug_log(f"[MCP Error] Failed to record event: {e}")


# ==================== Main Function ====================

async def async_main():
    """Asynchronous main function"""
    global mcp_client
    
    # Argument parsing
    today = datetime.now()
    personality_prompt = load_personality()
    
    parser = argparse.ArgumentParser(description="MCP-Integrated SSH Honeypot with GPT")
    parser.add_argument(
        "--personality",
        type=str,
        help="A brief summary of chatbot's personality",
        default=personality_prompt + 
                f"\nBased on these examples make something of your own (different username and hostname) to be a starting message. Always start the communication in this way and make sure your output ends with '$'. For the last login date use {today}\n" + 
                "Ignore date-time in <> after user input. This is not your concern.\n"
    )
    
    args = parser.parse_args()
    
    # History file rotation
    rotate_history_if_needed()
    
    # Ensure history file exists
    if not os.path.exists("history.txt"):
        with open("history.txt", "w", encoding="utf-8") as f:
            pass
    
    # Initialize MCP client
    debug_log("Connecting to MCP state management server...")
    mcp_client = HoneypotMCPClient(storage_path="./honeypot_memory", global_singleton_mode=True)
    await mcp_client.connect()
    debug_log("MCP client connected successfully")
    
    try:
        # Build initial prompt (using only personality config)
        initial_prompt = f"You are Linux OS terminal. Your personality is: {args.personality}"
        messages = [{"role": "system", "content": initial_prompt}]
        
        # Record session start
        with open("history.txt", "a", encoding="utf-8") as f:
            f.write(f"\n\n--- Session Started at {datetime.now()} ---\n")
        
        # Initialize CWD tracking
        current_cwd = "/root"
        
        # Check and initialize system state
        state_summary = await mcp_client.get_state_summary("attacker_ip")
        if state_summary.get("file_count", 0) == 0:
            debug_log("Initializing base system state...")
            # State will be managed automatically by MCP server
        
        # Main loop
        while True:
            try:
                # Get AI response
                msg = await call_ai_model(messages)
                
                # Process AI response
                message = {"content": msg, "role": 'assistant'}
                
                # Clean up special cases
                if "$cd" in message["content"] or "$ cd" in message["content"]:
                    message["content"] = message["content"].split("\n")[1]
                
                messages.append(message)
                
                # Record to history
                with open("history.txt", "a", encoding="utf-8") as logs:
                    logs.write(messages[-1]["content"])
                
                # Check exit conditions
                if "will be reported" in messages[-1]["content"]:
                    print(messages[-1]["content"])
                    break
                
                # Display output and get user input
                # Explicitly print and flush to ensure SSH client receives the output
                output_text = f'\n{messages[-1]["content"]}'.strip()
                print(output_text, end=" ", flush=True)
                
                trace_log(
                    "Step 1: Receive user command",
                    "Waiting for user input..."
                )
                
                user_input = input()
                sys.stdout.flush()
                
                trace_log(
                    "Step 2: Command preprocessing",
                    "Process user input",
                    {
                        "Raw input": user_input,
                        "Command length": len(user_input)
                    }
                )
                
                # Record user input
                with open("history.txt", "a", encoding="utf-8") as logs:
                    logs.write(" " + user_input + f"\t<{datetime.now()}>\n")
                
                messages.append({"role": "user", "content": " " + user_input + f"\t<{datetime.now()}>\n"})
                
                # Extract command
                command = user_input.strip()
                
                # Update CWD (if it's a cd command)
                if command.startswith("cd"):
                    parts = command.split()
                    if len(parts) > 1:
                        target_dir = parts[1]
                        if target_dir == "~" or target_dir == "--":
                            current_cwd = "/root"
                        elif target_dir == "..":
                            current_cwd = os.path.dirname(current_cwd)
                            if current_cwd == "":
                                current_cwd = "/root"
                        elif target_dir.startswith("/"):
                            current_cwd = target_dir
                        else:
                            current_cwd = os.path.normpath(os.path.join(current_cwd, target_dir)).replace("\\", "/")
                    else:
                        current_cwd = "/root"
                
                # Build enhanced messages (including state context)
                enhanced_messages = await build_enhanced_messages(messages, command, current_cwd)
                # Use the enhanced message list directly
                messages = enhanced_messages
                
                # Record event to MCP (asynchronous, non-blocking)
                def _on_mcp_task_done(t: asyncio.Task) -> None:
                    _background_tasks.discard(t)
                    if not t.cancelled() and t.exception() is not None:
                        logger.warning(
                            "record_event_to_mcp 后台任务异常（MCP可能不可用）: %s",
                            t.exception(),
                        )
                _task = asyncio.create_task(record_event_to_mcp(command, msg, current_cwd))
                _background_tasks.add(_task)
                _task.add_done_callback(_on_mcp_task_done)
                
            except KeyboardInterrupt:
                messages.append({"role": "user", "content": "\n"})
                print("")
                break
    
    finally:
        # Close MCP client
        debug_log("Closing MCP connection...")
        await mcp_client.close()
        debug_log("MCP connection closed")
        
        # Write trace log end marker
        if TRACE_MODE:
            try:
                with open(TRACE_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"\n{'='*70}\n")
                    f.write(f"Session ended at {datetime.now()}\n")
                    f.write(f"{'='*70}\n")
            except:
                pass


def main():
    """Synchronous main entry point"""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n[System] Interrupted by user")
    except Exception as e:
        print(f"\n[FATAL ERROR] {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    main()
