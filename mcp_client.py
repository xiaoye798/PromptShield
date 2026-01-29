"""
MCP蜜罐客户端 - 用于LinuxSSHbot与MCP状态管理服务器通信
(MCP Honeypot Client - For LinuxSSHbot to communicate with MCP state management server)

这个客户端封装了与MCP服务器的所有通信，提供简洁的异步API。
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HoneypotMCPClient:
    """
    蜜罐MCP客户端 - 负责与MCP状态管理服务器通信
    
    使用方法:
        client = HoneypotMCPClient()
        await client.connect()
        result = await client.record_event(...)
        await client.close()
    
    或使用异步上下文管理器:
        async with HoneypotMCPClient() as client:
            result = await client.record_event(...)
    """
    
    def __init__(self, storage_path: str = "./honeypot_memory", global_singleton_mode: bool = True):
        """
        初始化MCP客户端
        
        Args:
            storage_path: 状态存储路径
            global_singleton_mode: 是否启用全局单例模式（所有IP共享状态）
        """
        self.storage_path = storage_path
        self.global_singleton_mode = global_singleton_mode
        
        # MCP服务器参数
        self.server_params = StdioServerParameters(
            command=sys.executable,  # 使用当前Python解释器
            args=[
                "-m", "mcp_state_manager",  # 运行mcp_state_manager模块
            ],
            env={
                "STORAGE_PATH": storage_path,
                "GLOBAL_SINGLETON_MODE": "true" if global_singleton_mode else "false",
                # 传递所有必要的环境变量
                **os.environ
            }
        )
        
        # 连接对象
        self._client_context = None
        self._session_context = None
        self.session: Optional[ClientSession] = None
        
        # 连接状态
        self._connected = False
    
    async def connect(self) -> None:
        """连接到MCP服务器"""
        if self._connected:
            logger.warning("Client already connected")
            return
        
        try:
            logger.info("Connecting to MCP state management server...")
            
            # 启动MCP服务器进程并建立stdio连接
            self._client_context = stdio_client(self.server_params)
            read, write = await self._client_context.__aenter__()
            
            # 创建客户端会话
            self._session_context = ClientSession(read, write)
            self.session = await self._session_context.__aenter__()
            
            # 初始化连接
            await self.session.initialize()
            
            self._connected = True
            logger.info("Successfully connected to MCP server")
            
            # 列出可用的工具（调试信息）
            tools = await self.session.list_tools()
            logger.info(f"Available MCP tools: {[tool.name for tool in tools.tools]}")
            
        except Exception as e:
            logger.error(f"Failed to connect to MCP server: {e}")
            raise
    
    async def close(self) -> None:
        """关闭MCP连接"""
        if not self._connected:
            return
        
        try:
            logger.info("Closing MCP connection...")
            
            if self._session_context:
                await self._session_context.__aexit__(None, None, None)
            
            if self._client_context:
                await self._client_context.__aexit__(None, None, None)
            
            self._connected = False
            logger.info("MCP connection closed")
            
        except Exception as e:
            logger.error(f"Error closing MCP connection: {e}")
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.close()
    
    def _ensure_connected(self) -> None:
        """确保已连接到MCP服务器"""
        if not self._connected or not self.session:
            raise RuntimeError("Not connected to MCP server. Call connect() first.")
    
    # ====================== MCP工具方法 ======================
    
    async def record_event(
        self,
        ip_address: str,
        session_id: str,
        command: str,
        user_context: str,
        event_type: str,
        status: str,
        stdout: str = "",
        stderr: str = "",
        return_code: int = 0,
        state_changes: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        记录命令执行事件
        
        Args:
            ip_address: 攻击者IP
            session_id: 会话ID
            command: 执行的命令
            user_context: 用户上下文
            event_type: 事件类型 (FILE_OPERATION, USER_MANAGEMENT等)
            status: 执行状态 (SUCCESS, FAILURE, ERROR)
            stdout: 标准输出
            stderr: 标准错误输出
            return_code: 返回码
            state_changes: 状态变化列表
            metadata: 额外元数据
        
        Returns:
            包含success, event_id, message的字典
        """
        self._ensure_connected()
        
        try:
            result = await self.session.call_tool(
                "record_event",
                arguments={
                    "ip_address": ip_address,
                    "session_id": session_id,
                    "command": command,
                    "user_context": user_context,
                    "event_type": event_type,
                    "status": status,
                    "stdout": stdout,
                    "stderr": stderr,
                    "return_code": return_code,
                    "state_changes": state_changes or [],
                    "metadata": metadata or {}
                }
            )
            
            # 解析结构化输出
            if hasattr(result, 'structuredContent') and result.structuredContent:
                return result.structuredContent
            
            # 降级：解析文本内容
            if result.content and len(result.content) > 0:
                content = result.content[0]
                if hasattr(content, 'text'):
                    try:
                        return json.loads(content.text)
                    except json.JSONDecodeError:
                        return {"success": False, "message": content.text}
            
            return {"success": False, "message": "Unknown response format"}
            
        except Exception as e:
            logger.error(f"Error recording event: {e}")
            return {"success": False, "message": str(e)}
    
    async def query_state(
        self,
        ip_address: str,
        query_type: str,
        target: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        查询系统状态
        
        Args:
            ip_address: IP地址
            query_type: 查询类型
                - "file_exists": 检查文件是否存在
                - "directory_exists": 检查目录是否存在
                - "file_content": 获取文件内容
                - "user_exists": 检查用户是否存在
                - "service_status": 获取服务状态
                - "package_installed": 检查软件包是否安装
                - "state_summary": 获取状态摘要
            target: 查询目标（文件路径、用户名等）
        
        Returns:
            包含success, state_type, data, timestamp的字典
        """
        self._ensure_connected()
        
        try:
            result = await self.session.call_tool(
                "query_state",
                arguments={
                    "ip_address": ip_address,
                    "query_type": query_type,
                    "target": target
                }
            )
            
            # 解析结构化输出
            if hasattr(result, 'structuredContent') and result.structuredContent:
                return result.structuredContent
            
            # 降级：解析文本内容
            if result.content and len(result.content) > 0:
                content = result.content[0]
                if hasattr(content, 'text'):
                    try:
                        return json.loads(content.text)
                    except json.JSONDecodeError:
                        return {"success": False, "data": {}, "state_type": query_type}
            
            return {"success": False, "data": {}, "state_type": query_type}
            
        except Exception as e:
            logger.error(f"Error querying state: {e}")
            return {"success": False, "data": {"error": str(e)}, "state_type": query_type}
    
    async def get_event_graph(
        self,
        ip_address: str,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        获取事件图信息
        
        Args:
            ip_address: IP地址
            session_id: 可选的会话ID筛选
        
        Returns:
            包含events和relationships的事件图数据
        """
        self._ensure_connected()
        
        try:
            result = await self.session.call_tool(
                "get_event_graph",
                arguments={
                    "ip_address": ip_address,
                    "session_id": session_id
                }
            )
            
            # 解析结构化输出
            if hasattr(result, 'structuredContent') and result.structuredContent:
                return result.structuredContent
            
            # 降级：解析文本内容
            if result.content and len(result.content) > 0:
                content = result.content[0]
                if hasattr(content, 'text'):
                    try:
                        return json.loads(content.text)
                    except json.JSONDecodeError:
                        return {"success": False, "events": [], "relationships": []}
            
            return {"success": False, "events": [], "relationships": []}
            
        except Exception as e:
            logger.error(f"Error getting event graph: {e}")
            return {"success": False, "message": str(e), "events": [], "relationships": []}
    
    async def link_ip_to_instance(
        self,
        ip_address: str,
        instance_id: str
    ) -> Dict[str, Any]:
        """
        将IP关联到指定的实例ID
        
        Args:
            ip_address: IP地址
            instance_id: 实例ID
        
        Returns:
            包含success和message的字典
        """
        self._ensure_connected()
        
        try:
            result = await self.session.call_tool(
                "link_ip_to_instance",
                arguments={
                    "ip_address": ip_address,
                    "instance_id": instance_id
                }
            )
            
            # 解析结构化输出
            if hasattr(result, 'structuredContent') and result.structuredContent:
                return result.structuredContent
            
            # 降级：解析文本内容
            if result.content and len(result.content) > 0:
                content = result.content[0]
                if hasattr(content, 'text'):
                    try:
                        return json.loads(content.text)
                    except json.JSONDecodeError:
                        return {"success": False, "message": content.text}
            
            return {"success": False, "message": "Unknown response format"}
            
        except Exception as e:
            logger.error(f"Error linking IP to instance: {e}")
            return {"success": False, "message": str(e)}
    
    # ====================== 便捷方法 ======================
    
    async def check_file_exists(self, ip_address: str, file_path: str) -> bool:
        """检查文件是否存在"""
        result = await self.query_state(ip_address, "file_exists", file_path)
        return result.get("data", {}).get("exists", False)
    
    async def check_directory_exists(self, ip_address: str, dir_path: str) -> bool:
        """检查目录是否存在"""
        result = await self.query_state(ip_address, "directory_exists", dir_path)
        return result.get("data", {}).get("exists", False)
    
    async def get_file_content(self, ip_address: str, file_path: str) -> Optional[str]:
        """获取文件内容"""
        result = await self.query_state(ip_address, "file_content", file_path)
        return result.get("data", {}).get("content")
    
    async def check_user_exists(self, ip_address: str, username: str) -> bool:
        """检查用户是否存在"""
        result = await self.query_state(ip_address, "user_exists", username)
        return result.get("data", {}).get("exists", False)
    
    async def get_state_summary(self, ip_address: str) -> Dict[str, Any]:
        """获取状态摘要"""
        result = await self.query_state(ip_address, "state_summary")
        return result.get("data", {})


# ====================== 同步包装器（用于兼容旧代码） ======================

class SyncHoneypotMCPClient:
    """
    同步MCP客户端包装器 - 用于在同步代码中使用
    
    注意：这会创建一个新的事件循环，不建议在已有异步上下文中使用
    """
    
    def __init__(self, storage_path: str = "./honeypot_memory", global_singleton_mode: bool = True):
        self._async_client = HoneypotMCPClient(storage_path, global_singleton_mode)
        self._loop = None
    
    def __enter__(self):
        """同步上下文管理器入口"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._async_client.connect())
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """同步上下文管理器出口"""
        if self._loop:
            self._loop.run_until_complete(self._async_client.close())
            self._loop.close()
    
    def _run_async(self, coro):
        """运行异步协程"""
        if not self._loop:
            raise RuntimeError("Client not connected. Use 'with' statement.")
        return self._loop.run_until_complete(coro)
    
    def record_event(self, *args, **kwargs) -> Dict[str, Any]:
        """同步版本的record_event"""
        return self._run_async(self._async_client.record_event(*args, **kwargs))
    
    def query_state(self, *args, **kwargs) -> Dict[str, Any]:
        """同步版本的query_state"""
        return self._run_async(self._async_client.query_state(*args, **kwargs))
    
    def check_file_exists(self, ip_address: str, file_path: str) -> bool:
        """同步版本的check_file_exists"""
        return self._run_async(self._async_client.check_file_exists(ip_address, file_path))
    
    def check_directory_exists(self, ip_address: str, dir_path: str) -> bool:
        """同步版本的check_directory_exists"""
        return self._run_async(self._async_client.check_directory_exists(ip_address, dir_path))
    
    def get_file_content(self, ip_address: str, file_path: str) -> Optional[str]:
        """同步版本的get_file_content"""
        return self._run_async(self._async_client.get_file_content(ip_address, file_path))


# ====================== 测试代码 ======================

async def test_mcp_client():
    """测试MCP客户端功能"""
    print("Testing MCP Client...")
    
    async with HoneypotMCPClient() as client:
        # 测试1: 记录事件
        print("\n1. Testing record_event...")
        result = await client.record_event(
            ip_address="192.168.1.100",
            session_id="test_session",
            command="touch /tmp/test.txt",
            user_context="root",
            event_type="FILE_OPERATION",
            status="SUCCESS",
            stdout="",
            state_changes=[{
                "target": "/tmp/test.txt",
                "change_type": "create",
                "new_value": ""
            }]
        )
        print(f"Record event result: {result}")
        
        # 测试2: 查询文件是否存在
        print("\n2. Testing check_file_exists...")
        exists = await client.check_file_exists("192.168.1.100", "/tmp/test.txt")
        print(f"File exists: {exists}")
        
        # 测试3: 获取状态摘要
        print("\n3. Testing get_state_summary...")
        summary = await client.get_state_summary("192.168.1.100")
        print(f"State summary: {summary}")
        
        # 测试4: 获取事件图
        print("\n4. Testing get_event_graph...")
        graph = await client.get_event_graph("192.168.1.100")
        print(f"Event graph: {graph.get('events_count')} events")
    
    print("\n✅ MCP Client test completed!")


if __name__ == "__main__":
    # 运行测试
    asyncio.run(test_mcp_client())

