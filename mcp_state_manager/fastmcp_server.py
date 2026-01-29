"""
MCP蜜罐状态管理服务器 - FastMCP实现 (MCP Honeypot State Management Server - FastMCP Implementation)

使用官方推荐的FastMCP框架实现的MCP服务器，提供：
- 事件记录和状态管理工具
- 跨会话一致性检测
- IP隔离的状态存储
- Resources暴露系统状态
- Lifespan资源管理
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.session import ServerSession
from pydantic import BaseModel, Field

from .event_graph import EventGraph, EventNode, EventType, EventStatus, StateChange
from .memory_system import MemorySystem
from .scenario_models import ScenarioManager

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ====================== 数据模型 ======================

@dataclass
class AppContext:
    """应用上下文 - 存储生命周期内的资源"""
    memory_system: MemorySystem
    scenario_manager: ScenarioManager
    storage_path: str
    global_singleton_mode: bool


class EventRecordResult(BaseModel):
    """事件记录结果"""
    success: bool = Field(description="是否成功记录事件")
    event_id: Optional[str] = Field(description="事件ID")
    message: str = Field(description="结果消息")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")


class StateQueryResult(BaseModel):
    """状态查询结果"""
    success: bool = Field(description="查询是否成功")
    state_type: str = Field(description="状态类型")
    data: Dict[str, Any] = Field(description="状态数据")
    timestamp: str = Field(description="查询时间戳")


# ====================== Lifespan管理 ======================

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """
    管理应用生命周期 - 在服务器启动时初始化资源，关闭时清理
    
    这是MCP官方推荐的资源管理方式，避免使用全局变量
    """
    import os
    
    # 从环境变量获取配置
    storage_path = os.environ.get("STORAGE_PATH", "./honeypot_memory")
    global_singleton_mode = os.environ.get("GLOBAL_SINGLETON_MODE", "false").lower() == "true"
    
    logger.info(f"Initializing MCP server with storage_path={storage_path}, global_singleton_mode={global_singleton_mode}")
    
    # 初始化存储路径
    storage_path_obj = Path(storage_path)
    storage_path_obj.mkdir(parents=True, exist_ok=True)
    
    # 初始化组件
    memory_sys = MemorySystem(str(storage_path_obj), global_singleton_mode=global_singleton_mode)
    scenario_mgr = ScenarioManager()
    
    logger.info("Memory system and scenario manager initialized successfully")
    
    try:
        # 返回应用上下文供工具使用
        yield AppContext(
            memory_system=memory_sys,
            scenario_manager=scenario_mgr,
            storage_path=storage_path,
            global_singleton_mode=global_singleton_mode
        )
    finally:
        # 清理资源（如果需要）
        logger.info("Cleaning up MCP server resources...")


# 创建FastMCP服务器实例（使用Lifespan）
mcp = FastMCP("honeypot-state-manager", lifespan=app_lifespan)


@mcp.tool()
async def record_event(
    ip_address: str,
    session_id: str,
    command: str,
    user_context: str,
    event_type: str,
    status: str,
    ctx: Context[ServerSession, AppContext],
    stdout: str = "",
    stderr: str = "",
    return_code: int = 0,
    state_changes: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> EventRecordResult:
    """记录LLM蜜罐中的命令执行事件和状态变化"""
    
    # 从上下文获取memory_system
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        await ctx.error("Memory system not available")
        return EventRecordResult(
            success=False,
            message="Memory system not initialized"
        )
    
    try:
        # 转换事件类型和状态
        try:
            event_type_enum = EventType(event_type.upper())
        except ValueError:
            event_type_enum = EventType.COMMAND_EXECUTION
        
        try:
            status_enum = EventStatus(status.upper())
        except ValueError:
            status_enum = EventStatus.SUCCESS
        
        # 处理状态变化
        processed_state_changes = []
        if state_changes:
            for change in state_changes:
                state_change = StateChange(
                    target=change.get("target", ""),
                    change_type=change.get("change_type", "unknown"),
                    old_value=change.get("old_value"),
                    new_value=change.get("new_value"),
                    metadata=change.get("metadata", {})
                )
                processed_state_changes.append(state_change)
        
        # 创建事件节点
        event = EventNode(
            event_type=event_type_enum,
            command=command,
            session_id=session_id,
            ip_address=ip_address,
            user_context=user_context,
            status=status_enum,
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            state_changes=processed_state_changes,
            metadata=metadata or {}
        )
        
        # 记录事件
        event_id = memory_system.record_event(event)
        
        # 使用MCP日志记录成功
        await ctx.info(f"Event recorded: {command} (ID: {event_id})")
        
        return EventRecordResult(
            success=True,
            event_id=event_id,
            message=f"Event recorded successfully with ID: {event_id}",
            metadata={
                "ip_address": ip_address,
                "session_id": session_id,
                "event_type": event_type,
                "timestamp": datetime.now().isoformat()
            }
        )
        
    except Exception as e:
        logger.error(f"Error recording event: {e}")
        await ctx.error(f"Failed to record event: {str(e)}")
        return EventRecordResult(
            success=False,
            event_id=None,
            message=f"Failed to record event: {str(e)}"
        )


@mcp.tool()
async def query_state(
    ip_address: str,
    query_type: str,
    ctx: Context[ServerSession, AppContext],
    target: Optional[str] = None
) -> StateQueryResult:
    """查询特定IP的系统状态信息"""
    
    # 从上下文获取memory_system
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        await ctx.error("Memory system not available")
        return StateQueryResult(
            success=False,
            state_type=query_type,
            data={},
            timestamp=datetime.now().isoformat()
        )
    
    try:
        system_state = memory_system.get_system_state(ip_address)
        
        if query_type == "file_exists" and target:
            exists = target in system_state.filesystem.files
            data = {"exists": exists, "target": target}
            
        elif query_type == "directory_exists" and target:
            exists = target in system_state.filesystem.directories
            data = {"exists": exists, "target": target}
            
        elif query_type == "file_content" and target:
            file_info = system_state.filesystem.files.get(target)
            data = {
                "exists": file_info is not None,
                "content": file_info.get("content") if file_info else None,
                "target": target
            }
            
        elif query_type == "user_exists" and target:
            exists = target in system_state.users.users
            data = {"exists": exists, "target": target}
            
        elif query_type == "service_status" and target:
            service = system_state.services.services.get(target)
            data = {
                "exists": service is not None,
                "status": service.get("status") if service else None,
                "target": target
            }
            
        elif query_type == "package_installed" and target:
            exists = target in system_state.packages.installed_packages
            data = {"exists": exists, "target": target}
            
        elif query_type == "state_summary":
            data = {
                "files_count": len(system_state.filesystem.files),
                "directories_count": len(system_state.filesystem.directories),
                "users_count": len(system_state.users.users),
                "services_count": len(system_state.services.services),
                "packages_count": len(system_state.packages.installed_packages),
                "network_interfaces_count": len(system_state.network.interfaces)
            }
        
        # 新增：用户列表查询
        elif query_type == "user_list":
            data = {
                "users": system_state.users.users,
                "groups": system_state.users.groups
            }
        
        # 新增：Cron 列表查询
        elif query_type == "cron_list":
            data = {
                "user_crontabs": system_state.cron.user_crontabs,
                "system_cron_files": system_state.cron.system_cron_files
            }
        
        # 新增：服务列表查询
        elif query_type == "service_list":
            data = {
                "services": system_state.services.services
            }
            
        else:
            data = {"error": f"Unknown query type: {query_type}"}
        
        await ctx.debug(f"Query state: {query_type} for {ip_address}")
        
        return StateQueryResult(
            success=True,
            state_type=query_type,
            data=data,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error querying state: {e}")
        await ctx.error(f"Failed to query state: {str(e)}")
        return StateQueryResult(
            success=False,
            state_type=query_type,
            data={"error": str(e)},
            timestamp=datetime.now().isoformat()
        )


@mcp.tool()
async def get_event_graph(
    ip_address: str,
    ctx: Context[ServerSession, AppContext],
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """获取指定IP的事件图信息"""
    
    # 从上下文获取memory_system
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        await ctx.error("Memory system not available")
        return {
            "success": False,
            "message": "Memory system not initialized",
            "events": [],
            "relationships": []
        }
    
    try:
        event_graph = memory_system.get_event_graph(ip_address)
        
        # 获取事件
        events = event_graph.get_events(session_id=session_id)
        
        # 转换为字典格式
        events_data = []
        for event in events:
            events_data.append({
                "event_id": event.id,  # 使用id而不是event_id
                "command": event.command,
                "session_id": event.session_id,
                "event_type": event.event_type.value,
                "status": event.status.value,
                "timestamp": event.timestamp.isoformat(),
                "user_context": event.user_context
            })
        
        # 获取关系
        relationships_data = []
        for edge in event_graph.edges.values():
            relationships_data.append({
                "from_event_id": edge.source_event_id,
                "to_event_id": edge.target_event_id,
                "relationship_type": edge.relationship_type,
                "metadata": edge.metadata
            })
        
        return {
            "success": True,
            "ip_address": ip_address,
            "session_id": session_id,
            "events_count": len(events_data),
            "relationships_count": len(relationships_data),
            "events": events_data,
            "relationships": relationships_data
        }
        
    except Exception as e:
        logger.error(f"Error getting event graph: {e}")
        return {
            "success": False,
            "message": f"Failed to get event graph: {str(e)}",
            "events": [],
            "relationships": []
        }


@mcp.tool()
async def link_ip_to_instance(
    ip_address: str,
    instance_id: str,
    ctx: Context[ServerSession, AppContext]
) -> Dict[str, Any]:
    """将IP关联到指定的实例ID"""
    
    # 从上下文获取memory_system
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        await ctx.error("Memory system not available")
        return {
            "success": False,
            "message": "Memory system not initialized"
        }
    
    try:
        memory_system.link_ip_to_instance(ip_address, instance_id)
        return {
            "success": True,
            "message": f"Successfully linked IP {ip_address} to instance {instance_id}",
            "ip_address": ip_address,
            "instance_id": instance_id
        }
    except Exception as e:
        logger.error(f"Error linking IP to instance: {e}")
        await ctx.error(f"Failed to link IP: {str(e)}")
        return {
            "success": False,
            "message": f"Failed to link IP to instance: {str(e)}"
        }


# ====================== Resources（暴露状态数据） ======================

@mcp.resource("system://state/{ip_address}")
def get_system_state_resource(ip_address: str, ctx: Context[ServerSession, AppContext]) -> str:
    """
    获取完整系统状态 - 作为Resource暴露给LLM
    
    这是MCP推荐的数据暴露方式，允许LLM直接访问系统状态
    """
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        return json.dumps({"error": "Memory system not initialized"})
    
    try:
        state = memory_system.get_system_state(ip_address)
        state_dict = state.dict()
        
        # 转换datetime为ISO格式
        state_dict["timestamp"] = state_dict["timestamp"].isoformat() if hasattr(state_dict["timestamp"], "isoformat") else str(state_dict["timestamp"])
        
        return json.dumps(state_dict, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting system state resource: {e}")
        return json.dumps({"error": str(e)})


# 注意: 由于FastMCP当前版本不支持 {path:path} 路径参数语法，此资源已被禁用
# 如需此功能，请使用对应的tool方法或考虑升级FastMCP版本
# @mcp.resource("filesystem://directory/{ip_address}/{path:path}")
# def get_directory_listing_resource(ip_address: str, path: str, ctx: Context[ServerSession, AppContext]) -> str:
#     """
#     获取目录内容列表 - Resource方式
#     
#     示例: filesystem://directory/192.168.1.1/tmp
#     """
#     memory_system = ctx.request_context.lifespan_context.memory_system
#     
#     if not memory_system:
#         return json.dumps({"error": "Memory system not initialized"})
#     
#     try:
#         # 确保路径以/开头
#         full_path = f"/{path}" if not path.startswith("/") else path
#         
#         contents = memory_system.get_directory_contents(ip_address, full_path)
#         return json.dumps(contents, indent=2, ensure_ascii=False)
#     except Exception as e:
#         logger.error(f"Error getting directory listing: {e}")
#         return json.dumps({"error": str(e), "files": [], "directories": []})


# 注意: 由于FastMCP当前版本不支持 {path:path} 路径参数语法，此资源已被禁用
# 如需此功能，请使用对应的tool方法或考虑升级FastMCP版本
# @mcp.resource("filesystem://file/{ip_address}/{path:path}")
# def get_file_content_resource(ip_address: str, path: str, ctx: Context[ServerSession, AppContext]) -> str:
#     """
#     获取文件内容 - Resource方式
#     
#     示例: filesystem://file/192.168.1.1/etc/passwd
#     """
#     memory_system = ctx.request_context.lifespan_context.memory_system
#     
#     if not memory_system:
#         return "Error: Memory system not initialized"
#     
#     try:
#         # 确保路径以/开头
#         full_path = f"/{path}" if not path.startswith("/") else path
#         
#         content = memory_system.get_file_content(ip_address, full_path)
#         return content if content else f"File not found: {full_path}"
#     except Exception as e:
#         logger.error(f"Error getting file content: {e}")
#         return f"Error: {str(e)}"


@mcp.resource("state://summary/{ip_address}")
def get_state_summary_resource(ip_address: str, ctx: Context[ServerSession, AppContext]) -> str:
    """
    获取系统状态摘要 - Resource方式
    
    提供快速概览，不包含详细数据
    """
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        return json.dumps({"error": "Memory system not initialized"})
    
    try:
        summary = memory_system.get_state_summary(ip_address)
        return json.dumps(summary, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting state summary: {e}")
        return json.dumps({"error": str(e)})


@mcp.resource("events://graph/{ip_address}")
def get_event_graph_resource(ip_address: str, ctx: Context[ServerSession, AppContext]) -> str:
    """
    获取事件图 - Resource方式
    
    暴露完整的事件图数据
    """
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        return json.dumps({"error": "Memory system not initialized"})
    
    try:
        event_graph = memory_system.get_event_graph(ip_address)
        
        if not event_graph:
            return json.dumps({
                "events": [],
                "relationships": [],
                "message": "No event graph found for this IP"
            })
        
        # 导出为字典
        graph_data = {
            "ip_address": event_graph.ip_address,
            "events": [
                {
                    "id": node.id,
                    "command": node.command,
                    "event_type": node.event_type.value,
                    "status": node.status.value,
                    "timestamp": node.timestamp.isoformat(),
                    "session_id": node.session_id
                }
                for node in event_graph.nodes.values()
            ],
            "relationships": [
                {
                    "from": edge.source_event_id,
                    "to": edge.target_event_id,
                    "type": edge.relationship_type
                }
                for edge in event_graph.edges.values()
            ]
        }
        
        return json.dumps(graph_data, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting event graph resource: {e}")
        return json.dumps({"error": str(e)})


# ====================== 主函数 ======================

def main():
    """主函数 - 启动MCP服务器"""
    import sys
    import os
    
    # 注意：由于使用了Lifespan，不再需要手动调用initialize_components
    # Lifespan会在服务器启动时自动初始化资源
    
    # 检查是否有命令行参数
    if len(sys.argv) > 1:
        if "--help" in sys.argv or "-h" in sys.argv:
            print("MCP蜜罐状态管理服务器 (MCP Honeypot State Management Server)")
            print("使用官方MCP框架实现的MCP服务器")
            print()
            print("用法:")
            print("  python mcp_server.py                    # 启动MCP服务器 (stdio传输)")
            print("  python mcp_server.py --help             # 显示此帮助信息")
            print("  python mcp_server.py --sse              # 启动SSE服务器")
            print("  python mcp_server.py --http             # 启动HTTP服务器")
            print()
            print("环境变量:")
            print("  STORAGE_PATH                            # 存储路径 (默认: ./honeypot_memory)")
            print("  GLOBAL_SINGLETON_MODE                   # 全局单例模式开关 (true/false, 默认: false)")
            print()
            print("MCP工具:")
            print("  - record_event: 记录命令执行事件和状态变化")
            print("  - query_state: 查询系统状态信息")
            print("  - get_event_graph: 获取事件图信息")
            print("  - link_ip_to_instance: 将IP关联到指定的实例ID")
            return
        
        elif "--sse" in sys.argv:
            # SSE模式
            print("启动SSE服务器...")
            mcp.run(transport="sse")
            return
            
        elif "--http" in sys.argv:
            # HTTP模式 (streamable-http)
            print("启动HTTP服务器 (streamable-http传输)...")
            mcp.run(transport="streamable-http")
            return
    
    # 默认stdio模式
    print("启动MCP服务器 (stdio传输)...", file=sys.stderr)
    print("服务器已就绪，等待MCP客户端连接", file=sys.stderr)
    
    # 运行服务器 (stdio传输)
    # Lifespan会自动处理初始化
    mcp.run()


if __name__ == "__main__":
    main()