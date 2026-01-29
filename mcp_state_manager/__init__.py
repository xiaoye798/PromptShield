"""
MCP蜜罐状态管理包 (MCP Honeypot State Management Package)

这个包提供了一个完整的MCP (Model Context Protocol) 蜜罐状态管理系统，
用于管理和分析LLM蜜罐环境中的状态变化和事件流。

主要功能：
- 事件图管理：跟踪命令执行和状态变化的因果关系
- 结构化长期记忆：持久化存储系统状态和历史事件
- IP隔离的状态存储：为不同IP地址维护独立的状态空间
"""

__version__ = "1.0.0"
__author__ = "MCP Honeypot State Manager Team"

# 导入核心模块
from .event_graph import EventGraph, EventNode, EventType, EventStatus, StateChange
from .memory_system import MemorySystem, SystemState
from .fastmcp_server import mcp  # 注意：使用Lifespan，不再需要initialize_components
from .state_context_builder import StateContextBuilder
from .system_template import SystemTemplate, ContextOptimizer

__all__ = [
    "EventGraph",
    "EventNode", 
    "EventType",
    "EventStatus",
    "StateChange",
    "MemorySystem",
    "SystemState",
    "mcp",
    # "initialize_components",  # 已移除：使用Lifespan自动管理
    "StateContextBuilder",
    "SystemTemplate",
    "ContextOptimizer"
]