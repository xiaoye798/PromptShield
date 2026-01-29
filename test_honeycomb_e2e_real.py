#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
HoneyComb v2 端到端真实测试脚本
测试真实的 LLM 交互流程，验证持久化在完整蜜罐系统中的表现

支持 5 指标评估框架：SPR, SFR, PDR (by tier), Latency, Token Consumption
"""

import asyncio
import json
import shutil
import os
import sys
import time
import statistics
import argparse
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

# 导入噪声生成器（用于 Lost-in-the-Middle 对照实验）
try:
    from baselines.shelLM.noise_generator import NoiseGenerator
    NOISE_GENERATOR = NoiseGenerator()
except ImportError:
    NOISE_GENERATOR = None

# 强制刷新输出
def p(msg):
    print(msg, flush=True)

p("="*70)
p("HoneyComb v2 端到端真实测试 - 启动中...")
p("="*70)
p(f"Python: {sys.executable}")
p(f"工作目录: {os.getcwd()}")
p("")

# Token 追踪文件
TOKENS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "promptshield_tokens.json")

# 复杂度分层（与 shelLM 保持一致）
COMPLEXITY_TIERS = {
    'high': ['HC-T1543-002', 'HC-T1098-004', 'HC-T1136-001', 'HC-T1078-003'],
    'medium': ['HC-T1053-003', 'HC-T1037-004', 'HC-T1574-006', 'HC-T1556-003'],
    'low': ['HC-T1546-004', 'HC-T1505-003']
}

# 负面响应模式
NEGATIVE_PATTERNS = [
    "no such file", "cannot access", "not found", "no crontab",
    "does not exist", "permission denied", "command not found",
    "no such user", "not in the sudoers",
]

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

p("[1/5] 导入模块...")
try:
    from mcp_client import HoneypotMCPClient
    p("  ✓ mcp_client 导入成功")
except ImportError as e:
    p(f"  ✗ mcp_client 导入失败: {e}")
    sys.exit(1)

try:
    from mcp_state_manager.command_analyzer import CommandAnalyzer
    from mcp_state_manager.event_graph import EventType, EventStatus
    p("  ✓ CommandAnalyzer 导入成功")
except ImportError as e:
    p(f"  ✗ CommandAnalyzer 导入失败: {e}")
    sys.exit(1)

# 关键：从项目中导入真实的 build_enhanced_messages 函数
try:
    from LinuxSSHbot_mcp import build_enhanced_messages
    p("  ✓ build_enhanced_messages 导入成功 (从项目真实代码)")
except ImportError as e:
    p(f"  ✗ build_enhanced_messages 导入失败: {e}")
    sys.exit(1)

try:
    from dotenv import dotenv_values
    import openai
    from deepseek_client import DeepSeekClient, DeepSeekChatCompletion
    p("  ✓ AI客户端模块导入成功")
except ImportError as e:
    p(f"  ✗ AI客户端模块导入失败: {e}")
    sys.exit(1)


# ============== AI 客户端初始化 ==============

config = dotenv_values(".env")
api_provider = config.get("API_PROVIDER", "openai").lower()

p(f"[2/5] 初始化 AI 客户端 ({api_provider})...")

if api_provider == "openai":
    openai.api_key = config["OPENAI_API_KEY"]
    chat_client = None
    p("  ✓ OpenAI 客户端已配置")
elif api_provider == "deepseek":
    deepseek_client = DeepSeekClient(
        api_key=config["DEEPSEEK_API_KEY"],
        base_url=config.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    chat_client = DeepSeekChatCompletion(deepseek_client)
    p("  ✓ DeepSeek 客户端已配置")
else:
    p(f"  ✗ 不支持的API提供商: {api_provider}")
    sys.exit(1)


# ============== 测试场景定义 ==============

@dataclass
class E2ETestScenario:
    """端到端测试场景"""
    scenario_id: str
    mitre_id: str
    technique: str
    description: str
    implant_command: str
    verify_command: str
    persistence_type: str
    # LLM响应验证
    expected_keywords: List[str]  # 验证命令响应应包含的关键字
    negative_keywords: List[str] = None  # 不应该出现的关键字


def load_scenarios_from_csv(csv_path: str) -> List[E2ETestScenario]:
    """
    从 CSV 文件加载测试场景 - 直接引用项目测试套件
    
    这确保测试的是真实的基准测试定义，而非硬编码的场景
    """
    import csv
    
    scenarios = []
    
    # 定义每个场景的验证命令和预期关键字
    # 与 test_honeycomb_persistence.py 中的 10 个 Linux 场景完全一致
    verification_config = {
        # ========== 1. T1053.003 -- Cron定时任务 ==========
        "HC-T1053-003": {
            "verify_command": "crontab -l | grep -E 'python3.*socket.*4444'",
            "expected_keywords": ["socket", "4444"],
            "negative_keywords": ["no crontab"]
        },
        # ========== 2. T1543.002 -- Systemd服务 ==========
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
        # ========== 4. T1136.001 -- 创建本地账户 ==========
        "HC-T1136-001": {
            "verify_command": "id sysupdate | grep -E '(sudo|wheel)' && grep sysupdate /etc/passwd && sudo -l -U sysupdate | grep NOPASSWD",
            "expected_keywords": ["sysupdate", "sudo"],
            "negative_keywords": ["no such user", "not found"]
        },
        # ========== 5. T1546.004 -- Unix Shell配置修改 ==========
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
        # ========== 8. T1574.006 -- 动态链接器劫持 ==========
        "HC-T1574-006": {
            "verify_command": "cat /etc/ld.so.preload | grep -E 'libsystem.so' && ls -la /usr/local/lib/libsystem.so",
            "expected_keywords": ["libsystem.so"],
            "negative_keywords": ["No such file"]
        },
        # ========== 9. T1556.003 -- PAM后门 ==========
        "HC-T1556-003": {
            "verify_command": "head -1 /etc/pam.d/sshd | grep -E 'pam_permit.so'",
            "expected_keywords": ["pam_permit.so"],
            "negative_keywords": []
        },
        # ========== 10. T1078.003 -- 有效账户操控 ==========
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
            
            # 获取验证配置
            config = verification_config.get(scenario_id, {})
            
            scenario = E2ETestScenario(
                scenario_id=scenario_id,
                mitre_id=row['MITRE_ATT&CK_ID'],
                technique=row['ATT&CK_Technique'],
                description=row['攻击描述'],
                implant_command=row['Session_A_植入(Implant)'],
                verify_command=config.get('verify_command', row['Session_C_触发验证(Trigger)']),
                persistence_type=row['持久化类型'],
                expected_keywords=config.get('expected_keywords', []),
                negative_keywords=config.get('negative_keywords', [])
            )
            scenarios.append(scenario)
    
    return scenarios


# 从 CSV 文件加载测试场景（直接引用项目测试套件）
CSV_PATH = os.path.join(os.path.dirname(__file__), "HoneyComb_v2_E2E_Benchmark.csv")
p(f"\n[加载测试场景] 从 CSV 文件: {os.path.basename(CSV_PATH)}")

try:
    E2E_TEST_SCENARIOS = load_scenarios_from_csv(CSV_PATH)
    p(f"  ✓ 成功加载 {len(E2E_TEST_SCENARIOS)} 个测试场景")
    for i, s in enumerate(E2E_TEST_SCENARIOS, 1):
        p(f"    {i:2d}. {s.scenario_id} - {s.technique}")
except Exception as e:
    p(f"  ✗ 加载 CSV 失败: {e}")
    sys.exit(1)


# ============== 测试结果 ==============

@dataclass
class E2ETestResult:
    scenario_id: str
    mitre_id: str
    technique: str
    # 各阶段结果
    implant_success: bool
    implant_response: str
    verify_success: bool
    verify_response: str
    # 详细判定
    llm_response_valid: bool  # LLM响应是否合理
    state_persistent: bool    # 状态是否持久化 (SPR AND SFR)
    keywords_matched: bool    # 关键字是否匹配
    # ===== 新增字段：5指标评估 =====
    state_persisted: bool = False   # SPR: 状态是否被承认存在
    state_fidelity: bool = False    # SFR: 状态内容是否准确
    implant_latency_ms: float = 0.0
    verify_latency_ms: float = 0.0
    implant_tokens: int = 0
    verify_tokens: int = 0
    # ===================
    error: Optional[str] = None


@dataclass
class RoundMetrics:
    """多轮测试的聚合指标"""
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


# ============== AI 调用函数 ==============

async def call_ai_for_command(command: str, system_prompt: str = None, state_context: str = None) -> Tuple[str, int]:
    """
    调用 LLM 模拟执行命令
    
    Args:
        command: 用户命令
        system_prompt: 系统提示（可选）
        state_context: 状态上下文（关键！包含持久化的文件内容等）
    
    Returns:
        (LLM 响应, Token 消耗)
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

    # 如果有状态上下文，注入到系统提示中
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
            
            # 兼容性处理
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
            
            # 兼容性处理：DeepSeekResponse 的 usage 可能是字典或对象
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
    调用 LLM 并注入状态上下文（使用项目真实代码）
    
    这个函数直接使用 LinuxSSHbot_mcp.py 中的 build_enhanced_messages，
    而不是重新硬编码实现，确保测试的是真实的项目代码。
    
    Returns:
        (LLM 响应, Token 消耗)
    """
    # 基础系统提示
    system_prompt = """You are a Linux terminal (Ubuntu 20.04). 
You must respond EXACTLY as a real Linux system would, including:
- Accurate command outputs
- Proper error messages
- File system state consistency
- Realistic timestamps and system information

Current user: root
Current directory: /root
Hostname: honeypot"""

    # 构建基础消息
    base_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": command}
    ]
    
    # 使用项目真实代码 build_enhanced_messages 注入状态上下文
    # 这是关键：直接调用项目中的函数，不是测试文件中硬编码的版本
    enhanced_messages = await build_enhanced_messages(
        messages=base_messages,
        command=command,
        current_cwd="/root",
        client=mcp_client,  # 传入 MCP 客户端
        ip_address=ip_address
    )
    
    # 调用 LLM
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
            
            # 兼容性处理：DeepSeekResponse 的 usage 可能是字典或对象
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


# ============== 端到端测试执行器 ==============

class E2ETestExecutor:
    """端到端测试执行器"""
    
    def __init__(self, storage_path: str = "./test_e2e_memory", 
                 noise_level: int = 0, noise_position: str = "sandwich"):
        self.storage_path = storage_path
        self.test_ip = "192.168.100.100"
        self.results: List[E2ETestResult] = []
        self.mcp_client: Optional[HoneypotMCPClient] = None
        self.analyzer = CommandAnalyzer()
        # Lost-in-the-Middle 对照实验参数
        self.noise_level = noise_level
        self.noise_position = noise_position
        self.noise_tokens_consumed = 0  # 追踪噪声命令消耗的 token
        
    async def setup(self):
        """初始化测试环境"""
        p(f"\n[3/5] 初始化测试环境: {self.storage_path}")
        
        # 清理测试目录
        if os.path.exists(self.storage_path):
            shutil.rmtree(self.storage_path)
        os.makedirs(self.storage_path, exist_ok=True)
        os.makedirs(os.path.join(self.storage_path, "states"), exist_ok=True)
        os.makedirs(os.path.join(self.storage_path, "graphs"), exist_ok=True)
        p("  ✓ 测试目录已创建")
        
        # 初始化 MCP 客户端
        self.mcp_client = HoneypotMCPClient(
            storage_path=self.storage_path,
            global_singleton_mode=True
        )
        await self.mcp_client.connect()
        p("  ✓ MCP 客户端已连接")
        
    async def cleanup(self):
        """清理测试环境"""
        if self.mcp_client:
            await self.mcp_client.close()
            p("  ✓ MCP 客户端已断开")
        
    async def execute_command_with_llm(self, command: str, session_id: str, inject_state: bool = False) -> tuple:
        """
        使用真实 LLM 执行命令（完整流程）
        
        关键：使用项目真实代码 build_enhanced_messages 而非测试文件中的硬编码实现
        
        Args:
            command: 要执行的命令
            session_id: 会话ID
            inject_state: 是否注入持久化状态上下文（验证阶段应为True）
        
        Returns:
            (response, event_type, status, latency_ms, tokens)
        """
        p(f"    → 调用 LLM: {command[:60]}...")
        
        start_time = time.time()
        
        # 根据是否需要注入状态选择不同的调用方式
        if inject_state:
            # 使用项目真实代码 build_enhanced_messages 注入状态
            p(f"    → 使用 build_enhanced_messages (项目真实代码) 注入状态...")
            response, tokens = await call_ai_with_state_injection(
                self.mcp_client, command, self.test_ip
            )
        else:
            # 不注入状态，直接调用
            response, tokens = await call_ai_for_command(command)
        
        latency_ms = (time.time() - start_time) * 1000
        p(f"    ← LLM 响应: {len(response)} 字符, {latency_ms:.1f}ms, {tokens} tokens")
        
        # 2. 使用 CommandAnalyzer 分析
        event_type = self.analyzer.determine_event_type(command)
        status = self.analyzer.determine_status(command, response)
        state_changes = self.analyzer.analyze_state_changes(
            command, response, cwd="/root", system_state=None
        )
        
        p(f"    • 事件类型: {event_type.value if hasattr(event_type, 'value') else event_type}")
        p(f"    • 执行状态: {status.value if hasattr(status, 'value') else status}")
        p(f"    • 状态变化: {len(state_changes)} 个")
        
        # 3. 记录到 MCP
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
            p(f"    ✓ 事件已记录: {result.get('event_id', 'unknown')[:16]}...")
        else:
            p(f"    ✗ 事件记录失败: {result.get('message')}")
        
        return response, event_type, status, latency_ms, tokens
    
    async def run_single_test(self, scenario: E2ETestScenario, index: int) -> E2ETestResult:
        """运行单个端到端测试场景"""
        p(f"\n{'='*70}")
        p(f"场景 {index}: {scenario.scenario_id}")
        p(f"MITRE ID: {scenario.mitre_id}")
        p(f"技术: {scenario.technique}")
        p(f"描述: {scenario.description}")
        p(f"{'='*70}")
        
        try:
            # ==================== 噪声模拟（Lost-in-the-Middle 对照）====================
            noise_tokens_this_scenario = 0
            if self.noise_level > 0 and NOISE_GENERATOR:
                if self.noise_position in ["prefix", "sandwich"]:
                    # 植入前注入噪声（模拟 shelLM 的噪声负载）
                    half_noise = self.noise_level // 2 if self.noise_position == "sandwich" else self.noise_level
                    p(f"\n[噪声模拟] 模拟 {half_noise} 条噪声命令（并行，不影响 MCP 状态）...")
                    noise_commands = NOISE_GENERATOR.generate_noise_batch(half_noise)
                    
                    # 并行化噪声调用以加速测试
                    sem = asyncio.Semaphore(10)
                    async def call_with_sem(cmd):
                        async with sem:
                            return await call_ai_for_command(cmd)
                    
                    results = await asyncio.gather(*[call_with_sem(cmd) for cmd in noise_commands])
                    noise_tokens_this_scenario += sum(res[1] for res in results)
                    p(f"    → 噪声消耗 {noise_tokens_this_scenario} tokens")
            
            # ==================== Session A: 植入 ====================
            p("\n[Session A] 执行植入命令...")
            p(f"  命令: {scenario.implant_command}")
            
            implant_response, _, implant_status, implant_latency, implant_tokens = await self.execute_command_with_llm(
                scenario.implant_command,
                "session_a_implant"
            )
            
            implant_success = "SUCCESS" in str(implant_status) or "error" not in implant_response.lower()
            p(f"  结果: {'✓ 成功' if implant_success else '✗ 失败'} (Latency: {implant_latency:.1f}ms, Tokens: {implant_tokens})")
            
            # ==================== Session B: 断开重连 ====================
            p("\n[Session B] 模拟断开重连...")
            await self.mcp_client.close()
            p("  ✓ MCP 客户端已断开")
            
            await asyncio.sleep(0.5)  # 模拟网络延迟
            
            # 重新连接（新客户端实例）
            self.mcp_client = HoneypotMCPClient(
                storage_path=self.storage_path,
                global_singleton_mode=True
            )
            await self.mcp_client.connect()
            p("  ✓ 新会话已建立（模拟重连）")
            
            # ==================== 验证前噪声模拟（sandwich 和 suffix 模式）====================
            if self.noise_level > 0 and NOISE_GENERATOR:
                if self.noise_position in ["suffix", "sandwich"]:
                    # 验证前注入噪声（模拟 shelLM 的噪声负载）
                    remaining_noise = self.noise_level - (self.noise_level // 2) if self.noise_position == "sandwich" else self.noise_level
                    p(f"\n[噪声模拟] 验证前模拟 {remaining_noise} 条噪声命令（并行）...")
                    noise_commands = NOISE_GENERATOR.generate_noise_batch(remaining_noise)
                    
                    sem = asyncio.Semaphore(10)
                    async def call_with_sem(cmd):
                        async with sem:
                            return await call_ai_for_command(cmd)
                            
                    results = await asyncio.gather(*[call_with_sem(cmd) for cmd in noise_commands])
                    noise_tokens_this_scenario += sum(res[1] for res in results)
                    p(f"    → 累计噪声消耗 {noise_tokens_this_scenario} tokens")
            
            # ==================== Session C: 验证 ====================
            p("\n[Session C] 执行验证命令...")
            p(f"  命令: {scenario.verify_command}")
            
            # 关键：验证阶段必须注入持久化状态 (inject_state=True)
            verify_response, _, _, verify_latency, verify_tokens = await self.execute_command_with_llm(
                scenario.verify_command,
                "session_c_verify",
                inject_state=True  # 这是解决"跨会话持久化"问题的关键！
            )
            
            p(f"  验证 Latency: {verify_latency:.1f}ms, Tokens: {verify_tokens}")
            
            # ==================== 结果判定 ====================
            p("\n[结果判定]")
            
            # 1. 检查关键字是否匹配
            keywords_matched = all(
                kw.lower() in verify_response.lower() 
                for kw in scenario.expected_keywords
            )
            p(f"  • 关键字匹配: {'✓' if keywords_matched else '✗'}")
            if not keywords_matched:
                missing = [kw for kw in scenario.expected_keywords if kw.lower() not in verify_response.lower()]
                p(f"    缺失关键字: {missing}")
            
            # 2. 检查负面关键字（不应该出现）
            negative_found = False
            # 使用全局定义的 NEGATIVE_PATTERNS 加上场景特定的
            combined_negative = list(set(NEGATIVE_PATTERNS + (scenario.negative_keywords or [])))
            negative_found = any(
                kw.lower() in verify_response.lower() 
                for kw in combined_negative
            )
            p(f"  • 无错误关键字: {'✗ (发现错误)' if negative_found else '✓'}")
            
            # 3. LLM 响应是否合理
            llm_response_valid = len(verify_response) >= 2 
            p(f"  • LLM响应有效: {'✓' if llm_response_valid else '✗'}")
            
            # ===== 5指标核心计算 =====
            
            # SPR (State Persistence Rate): 状态是否被持久化（非否定，非空）
            # 定义：植入成功 AND 没有否定模式 AND 响应不为空
            is_empty_response = len(verify_response.strip()) < 5
            state_persisted = implant_success and not negative_found and not is_empty_response
            p(f"  • SPR (状态存在): {'✓' if state_persisted else '✗'}")
            
            # SFR (State Fidelity Rate): 状态内容是否准确（关键字匹配）
            # 定义：植入成功 AND 关键字匹配
            state_fidelity = implant_success and keywords_matched
            p(f"  • SFR (状态准确): {'✓' if state_fidelity else '✗'}")
            
            # PDR (Probing Deception Rate): 综合成功
            # 定义：SPR AND SFR (既存在又准确)
            state_persistent = state_persisted and state_fidelity
            p(f"  • PDR (综合成功): {'✓' if state_persistent else '✗'}")
            
            # 最终判定
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
                # 新增指标字段
                state_persisted=state_persisted,
                state_fidelity=state_fidelity,
                implant_latency_ms=implant_latency,
                verify_latency_ms=verify_latency,
                implant_tokens=implant_tokens,
                verify_tokens=verify_tokens + noise_tokens_this_scenario  # 包含噪声 token 消耗
            )
            
        except Exception as e:
            p(f"  ✗ 异常: {e}")
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
        """运行所有端到端测试"""
        p(f"\n[4/5] 开始端到端测试 ({len(E2E_TEST_SCENARIOS)} 个场景)")
        p(f"注意: 这将调用真实的 {api_provider.upper()} API")
        
        # 每次运行前清空上次结果
        self.results = []
        
        for i, scenario in enumerate(E2E_TEST_SCENARIOS, 1):
            result = await self.run_single_test(scenario, i)
            self.results.append(result)
            
            # 每个测试之间稍作延迟，避免API限流
            if i < len(E2E_TEST_SCENARIOS):
                await asyncio.sleep(1)
        
        return self.results

    def _calculate_round_metrics(self, results: List[E2ETestResult], round_num: int) -> RoundMetrics:
        """计算单轮指标"""
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
        """聚合多轮指标"""
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
        """运行多轮测试并聚合统计"""
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
            
            # 清理旧状态，确保每轮独立
            await self.cleanup()
            await self.setup()
            
            # 运行测试
            results = await self.run_all_tests()
            all_round_results.append([asdict(r) for r in results])
            
            # 计算指标
            metrics = self._calculate_round_metrics(results, round_num)
            all_round_metrics.append(metrics)
            
            p(f"\n  Round {round_num} Results:")
            p(f"    SPR: {metrics.spr:.1%}, SFR: {metrics.sfr:.1%}")
            p(f"    PDR: High={metrics.pdr_high:.1%}, Medium={metrics.pdr_medium:.1%}, Low={metrics.pdr_low:.1%}")
            p(f"    Latency: {metrics.avg_latency_ms:.1f}ms")
            p(f"    Total Tokens: {metrics.total_tokens:,}")
            
        # 聚合结果
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
        """生成文本报告 (供最后查看)"""
        if not self.results:
            return "No results available."
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r.verify_success)
        failed = total - passed
        
        lines = []
        lines.append("\n" + "="*70)
        lines.append(f"  [Report] PromptShield Test Report (Last Round)")
        lines.append("="*70)
        lines.append(f"\n总计: {total} | 通过: {passed} | 失败: {failed} | 通过率: {passed/total*100:.1f}%\n")
        
        lines.append("-"*70)
        lines.append(f"{'场景ID':<18} {'MITRE ID':<14} {'结果':<8} {'详情'}")
        lines.append("-"*70)
        
        for r in self.results:
            status = "✓ PASS" if r.verify_success else "✗ FAIL"
            detail = "持久化成功" if r.state_persistent else "持久化失败"
            lines.append(f"{r.scenario_id:<18} {r.mitre_id:<14} {status:<8} {detail}")
        
        lines.append("-"*70)
        
        return "\n".join(lines)
    
    def save_report_json(self, data: Dict[str, Any], filename: str = "promptshield_multi_round.json"):
        """保存多轮测试的 JSON 报告"""
        test_time = datetime.now()
        
        # 确保数据包含基本元数据
        if "meta" not in data:
            data["meta"] = {
                "test_time": test_time.isoformat(),
                "api_provider": api_provider,
                "framework": "PromptShield"
            }
        
        # 保存最新结果（覆盖）
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # 同时保存带时间戳的历史版本
        timestamp = test_time.strftime("%Y%m%d_%H%M%S")
        history_filename = f"promptshield_final_{timestamp}.json"
        with open(history_filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        p(f"\n✓ JSON报告已保存: {filename}")
        p(f"✓ 历史版本已保存: {history_filename}")


# ============== 主函数 ==============

async def async_main(num_rounds: int, output_file: str, noise_level: int = 0, noise_position: str = "sandwich"):
    """主函数"""
    executor = E2ETestExecutor(storage_path="./test_e2e_memory", 
                               noise_level=noise_level, noise_position=noise_position)
    
    try:
        # 显示噪声配置
        if noise_level > 0:
            p(f"\n[Lost-in-the-Middle 对照模式]")
            p(f"  噪声级别: {noise_level}")
            p(f"  噪声位置: {noise_position}")
            p(f"  注意: PromptShield 使用 O(1) 状态管理，噪声仅用于模拟负载对比")
        
        # 使用新的多轮测试方法
        # setup 和 cleanup 在 run_multi_round_test 内部管理
        
        results = await executor.run_multi_round_test(num_rounds)
        
        # 根据噪声级别调整输出文件名
        if noise_level > 0:
            base_name = output_file.rsplit('.', 1)[0]
            output_file = f"{base_name}_noise{noise_level}_{noise_position}.json"
        
        # 保存JSON (需要适配新的结果结构)
        executor.save_report_json(results, output_file)
        
    except KeyboardInterrupt:
        p("\n\n测试被用户中断")
    except Exception as e:
        p(f"\n测试执行错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await executor.cleanup()
    
    p("\n" + "="*70)
    p("端到端测试完成！")
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
    
    # 设置全局噪声参数（传递到 async_main）
    asyncio.run(async_main(num_rounds=args.rounds, output_file=args.output,
                           noise_level=args.noise_level, noise_position=args.noise_position))


if __name__ == "__main__":
    main()
