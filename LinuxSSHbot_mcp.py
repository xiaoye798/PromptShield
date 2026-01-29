"""
LinuxSSHbot with MCP Integration - 使用MCP协议进行状态管理的蜜罐系统
(LinuxSSHbot with MCP Integration - Honeypot system using MCP protocol for state management)

这是LinuxSSHbot的MCP版本，使用MCP客户端与状态管理服务器通信。

主要改进：
1. 通过MCP协议与状态管理服务器通信
2. 完全异步架构
3. 更好的错误处理和日志记录
4. 符合MCP官方最佳实践
"""

import asyncio
import argparse
import os
import re
import shutil
import sys
import yaml
from datetime import datetime
from time import sleep
from typing import List, Dict, Any, Optional

import openai
from dotenv import dotenv_values

# 导入MCP客户端和状态管理组件
from mcp_client import HoneypotMCPClient
from deepseek_client import DeepSeekClient, DeepSeekChatCompletion
from mcp_state_manager.command_analyzer import CommandAnalyzer
from mcp_state_manager.state_context_builder import StateContextBuilder
from mcp_state_manager.system_template import ContextOptimizer

# 配置
config = dotenv_values(".env")
api_provider = config.get("API_PROVIDER", "openai").lower()

# 调试模式开关（设置为False可以隐藏所有调试信息）
DEBUG_MODE = config.get("DEBUG_MODE", "false").lower() == "true"

# 详细追踪模式（显示完整的命令执行流程）
TRACE_MODE = config.get("TRACE_MODE", "false").lower() == "true"

# 追踪日志文件路径
TRACE_LOG_FILE = config.get("TRACE_LOG_FILE", "trace_execution.log")

# 初始化追踪日志文件
if TRACE_MODE:
    # 创建或清空追踪日志文件
    with open(TRACE_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"{'='*70}\n")
        f.write(f"执行追踪日志 - 会话开始于 {datetime.now()}\n")
        f.write(f"{'='*70}\n\n")
    print(f"[系统] 追踪模式已启用，日志将保存到: {TRACE_LOG_FILE}")

# 初始化AI客户端
if api_provider == "openai":
    openai.api_key = config["OPENAI_API_KEY"]
    chat_client = None
elif api_provider == "deepseek":
    deepseek_client = DeepSeekClient(
        api_key=config["DEEPSEEK_API_KEY"],
        base_url=config.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    chat_client = DeepSeekChatCompletion(deepseek_client)
else:
    raise ValueError(f"不支持的API提供商: {api_provider}")

# MCP客户端（全局，会在main中初始化）
mcp_client: Optional[HoneypotMCPClient] = None


# ==================== 追踪辅助函数 ====================

def trace_log(step: str, message: str, details: Any = None):
    """
    追踪日志输出 - 写入文件而不是终端
    
    Args:
        step: 步骤描述
        message: 主要消息
        details: 详细信息（可以是dict、list或其他类型）
    """
    if not TRACE_MODE:
        return
    
    try:
        with open(TRACE_LOG_FILE, "a", encoding="utf-8") as f:
            # 写入时间戳
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"\n{'='*70}\n")
            f.write(f"[{timestamp}] [TRACE] {step}\n")
            f.write(f"{'='*70}\n")
            f.write(f"{message}\n")
            
            if details:
                if isinstance(details, dict):
                    for key, value in details.items():
                        # 限制值的长度，避免日志过大
                        value_str = str(value)
                        if len(value_str) > 500:
                            value_str = value_str[:500] + "... (截断)"
                        f.write(f"  • {key}: {value_str}\n")
                elif isinstance(details, list):
                    for i, item in enumerate(details, 1):
                        item_str = str(item)
                        if len(item_str) > 300:
                            item_str = item_str[:300] + "... (截断)"
                        f.write(f"  [{i}] {item_str}\n")
                else:
                    detail_str = str(details)
                    if len(detail_str) > 1000:
                        detail_str = detail_str[:1000] + "... (截断)"
                    f.write(f"  {detail_str}\n")
            
            f.write(f"{'='*70}\n\n")
            f.flush()  # 立即写入磁盘
            
    except Exception as e:
        # 如果写入文件失败，回退到stderr输出
        print(f"[ERROR] 无法写入追踪日志: {e}", file=sys.stderr)


# ==================== 辅助函数 ====================

def debug_log(message: str):
    """
    调试日志输出 - 写入文件而不是终端
    
    Args:
        message: 调试消息
    """
    if not DEBUG_MODE:
        return
    
    try:
        with open(TRACE_LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"[{timestamp}] [DEBUG] {message}\n")
            f.flush()
    except Exception as e:
        print(f"[ERROR] 无法写入调试日志: {e}", file=sys.stderr)


def rotate_history_if_needed():
    """如果历史文件太大，进行轮转"""
    if os.path.exists("history.txt") and os.path.getsize("history.txt") > 1024 * 1024:  # 1MB
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            shutil.move("history.txt", f"history_{timestamp}.txt")
            print(f"[System] History file rotated to history_{timestamp}.txt")
        except Exception as e:
            print(f"[System] Failed to rotate history: {e}")


def load_personality():
    """加载人格配置"""
    with open('personalitySSH.yml', 'r', encoding="utf-8") as file:
        identity = yaml.safe_load(file)
    return identity['personality']['prompt']


async def call_ai_model(messages: List[Dict[str, str]]) -> str:
    """
    调用AI模型（异步）
    
    Args:
        messages: 消息列表
    
    Returns:
        AI的响应文本
    """
    trace_log(
        "步骤 6: 调用AI模型",
        f"准备调用 {api_provider.upper()} API",
        {
            "消息数量": len(messages),
            "最后一条消息": messages[-1]["content"][:100] + "..." if len(messages[-1]["content"]) > 100 else messages[-1]["content"]
        }
    )
    
    try:
        if api_provider == "openai":
            debug_log("Calling OpenAI API...")
            # OpenAI的API是同步的，在异步上下文中运行
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
            # DeepSeek客户端也是同步的
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(
                None,
                lambda: chat_client.create(
                    model=config.get("DEEPSEEK_MODEL", "deepseek-chat"),
                    messages=messages,
                    temperature=0.0,
                    max_tokens=800
                )
            )
        else:
            raise ValueError(f"不支持的API提供商: {api_provider}")
        
        msg = res.choices[0].message.content
        debug_log(f"Got response ({len(msg)} chars)")
        
        trace_log(
            "步骤 7: AI响应接收",
            f"收到AI响应",
            {
                "响应长度": f"{len(msg)} 字符",
                "响应内容": msg[:200] + "..." if len(msg) > 200 else msg
            }
        )
        
        return msg
        
    except Exception as api_error:
        print(f"\n[API ERROR] API调用失败: {api_error}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        
        # 记录到错误日志
        with open("api_errors.log", "a", encoding="utf-8") as error_log:
            error_log.write(f"\n[{datetime.now()}] API Error: {api_error}\n")
            error_log.write(traceback.format_exc())
        
        # 返回错误提示
        return "bash: API error occurred. Please check your API configuration.\nroot@server:/root$"


async def build_enhanced_messages(messages: List[Dict], command: str, current_cwd: str, 
                                   client: 'HoneypotMCPClient' = None, ip_address: str = "attacker_ip") -> List[Dict]:
    """
    构建增强的消息列表（包含状态上下文）
    
    这是实现跨会话持久化的核心函数！
    通过将 MCP 中持久化的状态注入到 LLM 提示中，确保 LLM 知道之前会话的操作结果。
    
    Args:
        messages: 原始消息列表
        command: 用户命令
        current_cwd: 当前工作目录
        client: MCP客户端实例（如果为None，使用全局mcp_client）
        ip_address: IP地址标识
    
    Returns:
        增强后的消息列表
    """
    # 使用传入的client或全局mcp_client
    _mcp_client = client if client is not None else mcp_client
    
    trace_log(
        "步骤 3: 构建增强消息",
        f"为命令构建状态上下文",
        {
            "命令": command,
            "当前目录": current_cwd,
            "原始消息数": len(messages)
        }
    )
    
    enhanced_messages = messages.copy()
    
    if not command or not _mcp_client:
        return enhanced_messages
    
    try:
        # 1. 从MCP服务器查询当前状态摘要
        trace_log(
            "步骤 4: 查询系统状态",
            "从MemorySystem获取当前状态摘要"
        )
        
        state_summary = await _mcp_client.get_state_summary(ip_address)
        
        trace_log(
            "步骤 4.1: 状态摘要获取",
            "当前系统状态",
            state_summary if state_summary else {"状态": "空"}
        )
        
        # 2. 构建状态上下文 - 关键改进：根据命令类型获取相关状态
        context_parts = []
        command_parts = command.strip().split()
        cmd = command_parts[0] if command_parts else ""
        
        # ==================== 优先检查：用户相关命令 ====================
        # 这必须在文件读取之前检查，因为 "cat /etc/passwd | grep xxx" 也会匹配文件读取
        if cmd in ['id', 'whoami', 'w', 'who'] or 'passwd' in command or ('grep' in command and ('user' in command.lower() or 'passwd' in command)):
            # 查询用户列表
            trace_log("步骤 4.2: 用户查询", "检测到用户相关命令，获取用户列表")
            result = await _mcp_client.query_state(ip_address, "user_list")
            if result.get("success") and result.get("data"):
                users = result.get("data", {}).get("users", {})
                groups = result.get("data", {}).get("groups", {})
                if users:
                    user_lines = []
                    user_groups_info = {}  # 用户->组列表映射
                    
                    for username, info in users.items():
                        uid = info.get('uid', 1000)
                        gid = info.get('gid', uid)
                        home = info.get('home', f'/home/{username}')
                        shell = info.get('shell', '/bin/bash')
                        gecos = info.get('gecos', '')
                        user_lines.append(f"{username}:x:{uid}:{gid}:{gecos}:{home}:{shell}")
                        
                        # 收集用户所属的组
                        user_group_list = [username]  # 默认包含同名组
                        for grp_name, grp_info in groups.items():
                            if username in grp_info.get('members', []):
                                user_group_list.append(grp_name)
                        user_groups_info[username] = user_group_list
                    
                    # 构建 id 命令输出格式
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
        
        # ==================== grep 命令特殊处理（非 passwd 文件）====================
        if cmd == 'grep' or 'grep' in command:
            # 提取 grep 的目标文件
            grep_target = None
            for part in command_parts:
                if part.startswith('/') and not part.startswith("'") and 'passwd' not in part:
                    grep_target = part
                    break
            
            if grep_target:
                # 检查文件是否存在
                exists = await _mcp_client.check_file_exists(ip_address, grep_target)
                if exists:
                    content = await _mcp_client.get_file_content(ip_address, grep_target)
                    if content:
                        # 提取 grep 的模式
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
        
        # ==================== 文件读取命令 ====================
        if cmd in ['cat', 'head', 'tail', 'less', 'more']:
            # 提取所有目标文件路径
            target_files = []
            for part in command_parts[1:]:
                if not part.startswith('-') and '|' not in part:
                    # 处理 ~ 为 /root
                    if part.startswith('~'):
                        part = '/root' + part[1:]
                    elif not part.startswith('/'):
                        part = os.path.normpath(os.path.join(current_cwd, part)).replace("\\", "/")
                    target_files.append(part)
            
            trace_log(
                "步骤 4.3: 文件查询",
                f"提取目标文件: {target_files}"
            )
            
            for file_path in target_files:
                # 检查文件是否存在（尝试多种路径格式）
                paths_to_check = [file_path]
                if file_path.startswith('/root/'):
                    paths_to_check.append('~' + file_path[5:])
                    paths_to_check.append(file_path.replace('/root/', '~/'))
                
                trace_log(
                    "步骤 4.4: 检查文件存在",
                    f"检查路径列表: {paths_to_check}"
                )
                
                for check_path in paths_to_check:
                    exists = await _mcp_client.check_file_exists(ip_address, check_path)
                    trace_log(
                        "步骤 4.5: 文件检查结果",
                        f"路径: {check_path}, 存在: {exists}"
                    )
                    if exists:
                        content = await _mcp_client.get_file_content(ip_address, check_path)
                        trace_log(
                            "步骤 4.6: 获取文件内容",
                            f"内容长度: {len(content) if content else 0}"
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
        
        # ==================== 目录列表命令 ====================
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
            # 可以扩展：查询目录内容
        
        # ==================== Cron 命令 ====================
        if 'cron' in command or 'crontab' in command:
            result = await _mcp_client.query_state(ip_address, "cron_list")
            if result.get("success") and result.get("data"):
                cron_data = result.get("data", {})
                if cron_data:
                    import json
                    context_parts.append(f"""[CRITICAL - CRON JOBS IN PERSISTENT STATE]
Cron jobs in the system:
{json.dumps(cron_data, indent=2)}
IMPORTANT: Show these cron entries when listing crontab.""")
        
        # ==================== 服务命令 ====================
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
        
        # 3. 添加状态摘要
        if state_summary:
            file_count = state_summary.get('file_count', 0)
            user_count = state_summary.get('user_count', 0)
            if file_count > 0 or user_count > 0:
                context_parts.append(f"[System State: {file_count} files modified, {user_count} users]")
        
        # 4. 组合上下文
        state_context = "\n\n".join(context_parts)
        
        # 5. 使用上下文优化器确保不超长
        context_optimizer = ContextOptimizer(max_context_tokens=2000)
        optimized_context = context_optimizer.optimize_context("", state_context, "")
        
        # 6. 如果有上下文，注入到消息中
        if optimized_context.strip():
            enhanced_messages.insert(-1, {
                "role": "system",
                "content": optimized_context
            })
            
            token_estimate = context_optimizer.estimate_token_count(optimized_context)
            
            debug_log(f"Injected ~{token_estimate} tokens of state context")
            
            trace_log(
                "步骤 5: 上下文注入",
                "将状态上下文注入到消息中",
                {
                    "上下文长度": f"{len(optimized_context)} 字符",
                    "预估Token数": token_estimate,
                    "注入位置": "倒数第二条消息",
                    "上下文内容": optimized_context[:300] + "..." if len(optimized_context) > 300 else optimized_context
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
    记录事件到MCP服务器
    
    Args:
        command: 执行的命令
        response: AI的响应
        current_cwd: 当前工作目录
    """
    trace_log(
        "步骤 8: 分析命令",
        "使用CommandAnalyzer分析命令",
        {"命令": command}
    )
    
    try:
        # 分析命令
        analyzer = CommandAnalyzer()
        event_type = analyzer.determine_event_type(command)
        status = analyzer.determine_status(command, response)
        
        trace_log(
            "步骤 8.1: 命令分析结果",
            "确定事件类型和执行状态",
            {
                "事件类型": event_type.value if hasattr(event_type, 'value') else str(event_type),
                "执行状态": status.value if hasattr(status, 'value') else str(status)
            }
        )
        
        # 分析状态变化（这里简化处理，实际应该更复杂）
        # 由于我们没有完整的SystemState，先用基础分析
        trace_log(
            "步骤 9: 分析状态变化",
            "提取命令导致的状态变化"
        )
        
        state_changes = analyzer.analyze_state_changes(
            command, response, cwd=current_cwd, system_state=None
        )
        
        if state_changes:
            changes_info = []
            for sc in state_changes:
                changes_info.append(f"{sc.change_type}: {sc.target}")
            
            trace_log(
                "步骤 9.1: 状态变化识别",
                f"发现 {len(state_changes)} 个状态变化",
                changes_info
            )
        else:
            trace_log(
                "步骤 9.1: 状态变化识别",
                "无状态变化（只读操作）"
            )
        
        # 记录事件
        trace_log(
            "步骤 10: 记录事件",
            "将事件记录到MemorySystem"
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
                "步骤 11: 事件记录成功",
                "事件已保存到持久化存储",
                {
                    "事件ID": result.get("event_id", "unknown"),
                    "存储路径": "honeypot_memory/states/ 和 graphs/"
                }
            )
        else:
            debug_log(f"Failed to record event: {result.get('message')}")
        
    except Exception as e:
        debug_log(f"[MCP Error] Failed to record event: {e}")


# ==================== 主函数 ====================

async def async_main():
    """异步主函数"""
    global mcp_client
    
    # 参数解析
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
    
    # 历史文件轮转
    rotate_history_if_needed()
    
    # 确保历史文件存在
    if not os.path.exists("history.txt"):
        with open("history.txt", "w", encoding="utf-8") as f:
            pass
    
    # 初始化MCP客户端
    debug_log("Connecting to MCP state management server...")
    mcp_client = HoneypotMCPClient(storage_path="./honeypot_memory", global_singleton_mode=True)
    await mcp_client.connect()
    debug_log("MCP client connected successfully")
    
    try:
        # 构建初始prompt（仅使用personality配置）
        initial_prompt = f"You are Linux OS terminal. Your personality is: {args.personality}"
        messages = [{"role": "system", "content": initial_prompt}]
        
        # 记录会话开始
        with open("history.txt", "a", encoding="utf-8") as f:
            f.write(f"\n\n--- Session Started at {datetime.now()} ---\n")
        
        # 初始化CWD跟踪
        current_cwd = "/root"
        
        # 检查并初始化系统状态
        state_summary = await mcp_client.get_state_summary("attacker_ip")
        if state_summary.get("file_count", 0) == 0:
            debug_log("Initializing base system state...")
            # 状态会由MCP服务器自动管理
        
        # 主循环
        while True:
            try:
                # 获取AI响应
                msg = await call_ai_model(messages)
                
                # 处理AI响应
                message = {"content": msg, "role": 'assistant'}
                
                # 清理特殊情况
                if "$cd" in message["content"] or "$ cd" in message["content"]:
                    message["content"] = message["content"].split("\n")[1]
                
                messages.append(message)
                
                # 记录到历史
                with open("history.txt", "a", encoding="utf-8") as logs:
                    logs.write(messages[-1]["content"])
                
                # 检查退出条件
                if "will be reported" in messages[-1]["content"]:
                    print(messages[-1]["content"])
                    break
                
                # 显示输出并获取用户输入
                trace_log(
                    "步骤 1: 接收用户命令",
                    "等待用户输入..."
                )
                
                user_input = input(f'\n{messages[-1]["content"]}'.strip() + " ")
                
                trace_log(
                    "步骤 2: 命令预处理",
                    "处理用户输入",
                    {
                        "原始输入": user_input,
                        "命令长度": len(user_input)
                    }
                )
                
                # 记录用户输入
                with open("history.txt", "a", encoding="utf-8") as logs:
                    logs.write(" " + user_input + f"\t<{datetime.now()}>\n")
                
                messages.append({"role": "user", "content": " " + user_input + f"\t<{datetime.now()}>\n"})
                
                # 提取命令
                command = user_input.strip()
                
                # 更新CWD（如果是cd命令）
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
                
                # 构建增强消息（包含状态上下文）
                enhanced_messages = await build_enhanced_messages(messages, command, current_cwd)
                # 直接使用增强后的消息列表
                messages = enhanced_messages
                
                # 记录事件到MCP（异步，不阻塞）
                asyncio.create_task(record_event_to_mcp(command, msg, current_cwd))
                
            except KeyboardInterrupt:
                messages.append({"role": "user", "content": "\n"})
                print("")
                break
    
    finally:
        # 关闭MCP客户端
        debug_log("Closing MCP connection...")
        await mcp_client.close()
        debug_log("MCP connection closed")
        
        # 写入追踪日志结束标记
        if TRACE_MODE:
            try:
                with open(TRACE_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"\n{'='*70}\n")
                    f.write(f"会话结束于 {datetime.now()}\n")
                    f.write(f"{'='*70}\n")
            except:
                pass


def main():
    """同步main入口点"""
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

