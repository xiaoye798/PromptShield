"""
MCP Honeypot Client - For LinuxSSHbot to communicate with MCP state management server
This client encapsulates all communication with the MCP server and provides a clean asynchronous API.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HoneypotMCPClient:
    """
    Honeypot MCP Client - Responsible for communicating with the MCP state management server
    
    Usage:
        client = HoneypotMCPClient()
        await client.connect()
        result = await client.record_event(...)
        await client.close()
    
    Or use asynchronous context manager:
        async with HoneypotMCPClient() as client:
            result = await client.record_event(...)
    """
    
    def __init__(self, storage_path: str = "./honeypot_memory", global_singleton_mode: bool = True):
        """
        Initialize MCP client
        
        Args:
            storage_path: Path for state storage
            global_singleton_mode: Whether to enable global singleton mode (all IPs share state)
        """
        self.storage_path = storage_path
        self.global_singleton_mode = global_singleton_mode
        
        # MCP server parameters
        self.server_params = StdioServerParameters(
            command=sys.executable,  # Use current Python interpreter
            args=[
                "-m", "mcp_state_manager",  # Run mcp_state_manager module
            ],
            env={
                "STORAGE_PATH": storage_path,
                "GLOBAL_SINGLETON_MODE": "true" if global_singleton_mode else "false",
                # Pass all necessary environment variables
                **os.environ
            }
        )
        
        # Connection objects
        self._client_context = None
        self._session_context = None
        self.session: Optional[ClientSession] = None
        
        # Connection status
        self._connected = False
    
    async def connect(self) -> None:
        """Connect to MCP server"""
        if self._connected:
            logger.warning("Client already connected")
            return
        
        try:
            logger.info("Connecting to MCP state management server...")
            
            # Start MCP server process and establish stdio connection
            self._client_context = stdio_client(self.server_params)
            read, write = await self._client_context.__aenter__()
            
            # Create client session
            self._session_context = ClientSession(read, write)
            self.session = await self._session_context.__aenter__()
            
            # Initialize connection
            await self.session.initialize()
            
            self._connected = True
            logger.info("Successfully connected to MCP server")
            
            # List available tools (debug info)
            tools = await self.session.list_tools()
            logger.info(f"Available MCP tools: {[tool.name for tool in tools.tools]}")
            
        except Exception as e:
            logger.error(f"Failed to connect to MCP server: {e}")
            raise
    
    async def close(self) -> None:
        """Close MCP connection"""
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
        """Asynchronous context manager entrance"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Asynchronous context manager exit"""
        await self.close()
    
    def _ensure_connected(self) -> None:
        """Ensure connected to MCP server"""
        if not self._connected or not self.session:
            raise RuntimeError("Not connected to MCP server. Call connect() first.")
    
    # ====================== MCP Tool Methods ======================
    
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
        Record command execution event
        
        Args:
            ip_address: Attacker IP
            session_id: Session ID
            command: Executed command
            user_context: User context
            event_type: Event type (FILE_OPERATION, USER_MANAGEMENT, etc.)
            status: Execution status (SUCCESS, FAILURE, ERROR)
            stdout: Standard output
            stderr: Standard error output
            return_code: Return code
            state_changes: List of state changes
            metadata: Additional metadata
        
        Returns:
            Dictionary containing success, event_id, and message
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
            
            # Parse structured output
            if hasattr(result, 'structuredContent') and result.structuredContent:
                return result.structuredContent
            
            # Fallback: Parse text content
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
        Query system state
        
        Args:
            ip_address: IP address
            query_type: Query type
                - "file_exists": Check if file exists
                - "directory_exists": Check if directory exists
                - "file_content": Get file content
                - "user_exists": Check if user exists
                - "service_status": Get service status
                - "package_installed": Check if package is installed
                - "state_summary": Get state summary
            target: Query target (file path, username, etc.)
        
        Returns:
            Dictionary containing success, state_type, data, and timestamp
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
            
            # Parse structured output
            if hasattr(result, 'structuredContent') and result.structuredContent:
                return result.structuredContent
            
            # Fallback: Parse text content
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
        Get event graph information
        
        Args:
            ip_address: IP address
            session_id: Optional session ID filter
        
        Returns:
            Event graph data containing events and relationships
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
            
            # Parse structured output
            if hasattr(result, 'structuredContent') and result.structuredContent:
                return result.structuredContent
            
            # Fallback: Parse text content
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
        Link IP to specified instance ID
        
        Args:
            ip_address: IP address
            instance_id: Instance ID
        
        Returns:
            Dictionary containing success and message
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
            
            # Parse structured output
            if hasattr(result, 'structuredContent') and result.structuredContent:
                return result.structuredContent
            
            # Fallback: Parse text content
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
    
    # ====================== Convenience Methods ======================
    
    async def check_file_exists(self, ip_address: str, file_path: str) -> bool:
        """Check if file exists"""
        result = await self.query_state(ip_address, "file_exists", file_path)
        return result.get("data", {}).get("exists", False)
    
    async def check_directory_exists(self, ip_address: str, dir_path: str) -> bool:
        """Check if directory exists"""
        result = await self.query_state(ip_address, "directory_exists", dir_path)
        return result.get("data", {}).get("exists", False)
    
    async def get_file_content(self, ip_address: str, file_path: str) -> Optional[str]:
        """Get file content"""
        result = await self.query_state(ip_address, "file_content", file_path)
        return result.get("data", {}).get("content")
    
    async def check_user_exists(self, ip_address: str, username: str) -> bool:
        """Check if user exists"""
        result = await self.query_state(ip_address, "user_exists", username)
        return result.get("data", {}).get("exists", False)
    
    async def get_state_summary(self, ip_address: str) -> Dict[str, Any]:
        """Get state summary"""
        result = await self.query_state(ip_address, "state_summary")
        return result.get("data", {})


# ====================== Synchronous Wrapper (for compatibility with legacy code) ======================

class SyncHoneypotMCPClient:
    """
    Synchronous MCP Client Wrapper - For use in synchronous code
    
    Note: This creates a new event loop, not recommended for use within an existing asynchronous context.
    """
    
    def __init__(self, storage_path: str = "./honeypot_memory", global_singleton_mode: bool = True):
        self._async_client = HoneypotMCPClient(storage_path, global_singleton_mode)
        self._loop = None
    
    def __enter__(self):
        """Synchronous context manager entrance"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._async_client.connect())
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Synchronous context manager exit"""
        if self._loop:
            self._loop.run_until_complete(self._async_client.close())
            self._loop.close()
    
    def _run_async(self, coro):
        """Run asynchronous coroutine"""
        if not self._loop:
            raise RuntimeError("Client not connected. Use 'with' statement.")
        return self._loop.run_until_complete(coro)
    
    def record_event(self, *args, **kwargs) -> Dict[str, Any]:
        """Synchronous version of record_event"""
        return self._run_async(self._async_client.record_event(*args, **kwargs))
    
    def query_state(self, *args, **kwargs) -> Dict[str, Any]:
        """Synchronous version of query_state"""
        return self._run_async(self._async_client.query_state(*args, **kwargs))
    
    def check_file_exists(self, ip_address: str, file_path: str) -> bool:
        """Synchronous version of check_file_exists"""
        return self._run_async(self._async_client.check_file_exists(ip_address, file_path))
    
    def check_directory_exists(self, ip_address: str, dir_path: str) -> bool:
        """Synchronous version of check_directory_exists"""
        return self._run_async(self._async_client.check_directory_exists(ip_address, dir_path))
    
    def get_file_content(self, ip_address: str, file_path: str) -> Optional[str]:
        """Synchronous version of get_file_content"""
        return self._run_async(self._async_client.get_file_content(ip_address, file_path))


# ====================== Test Code ======================

async def test_mcp_client():
    """Test MCP Client functionality"""
    print("Testing MCP Client...")
    
    async with HoneypotMCPClient() as client:
        # Test 1: Record event
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
        
        # Test 2: Check if file exists
        print("\n2. Testing check_file_exists...")
        exists = await client.check_file_exists("192.168.1.100", "/tmp/test.txt")
        print(f"File exists: {exists}")
        
        # Test 3: Get state summary
        print("\n3. Testing get_state_summary...")
        summary = await client.get_state_summary("192.168.1.100")
        print(f"State summary: {summary}")
        
        # Test 4: Get event graph
        print("\n4. Testing get_event_graph...")
        graph = await client.get_event_graph("192.168.1.100")
        print(f"Event graph: {graph.get('events_count')} events")
    
    print("\n✅ MCP Client test completed!")


if __name__ == "__main__":
    # Run test
    asyncio.run(test_mcp_client())
