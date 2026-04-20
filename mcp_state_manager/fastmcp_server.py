"""
MCP Honeypot State Management Server - FastMCP Implementation

MCP server implemented using the official recommended FastMCP framework, providing:
- Event recording and state management tools
- Cross-session consistency detection
- IP-isolated state storage
- System state exposure via Resources
- Lifespan resource management
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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ====================== Data Models ======================

@dataclass
class AppContext:
    """App Context - Stores resources within the lifecycle"""
    memory_system: MemorySystem
    scenario_manager: ScenarioManager
    storage_path: str
    global_singleton_mode: bool


class EventRecordResult(BaseModel):
    """Event Recording Result"""
    success: bool = Field(description="Whether the event was successfully recorded")
    event_id: Optional[str] = Field(description="Event ID")
    message: str = Field(description="Result message")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class StateQueryResult(BaseModel):
    """State Query Result"""
    success: bool = Field(description="Whether the query was successful")
    state_type: str = Field(description="State type")
    data: Dict[str, Any] = Field(description="State data")
    timestamp: str = Field(description="Query timestamp")


# ====================== Lifespan Management ======================

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """
    Manage application lifecycle - Initialize resources on startup, clean up on shutdown
    
    This is the resource management method recommended by MCP official, avoiding global variables
    """
    import os
    
    # Get configuration from environment variables
    storage_path = os.environ.get("STORAGE_PATH", "./honeypot_memory")
    global_singleton_mode = os.environ.get("GLOBAL_SINGLETON_MODE", "false").lower() == "true"
    
    logger.info(f"Initializing MCP server with storage_path={storage_path}, global_singleton_mode={global_singleton_mode}")
    
    # Initialize storage path
    storage_path_obj = Path(storage_path)
    storage_path_obj.mkdir(parents=True, exist_ok=True)
    
    # Initialize components
    memory_sys = MemorySystem(str(storage_path_obj), global_singleton_mode=global_singleton_mode)
    scenario_mgr = ScenarioManager()
    
    logger.info("Memory system and scenario manager initialized successfully")
    
    try:
        # Return app context for tools
        yield AppContext(
            memory_system=memory_sys,
            scenario_manager=scenario_mgr,
            storage_path=storage_path,
            global_singleton_mode=global_singleton_mode
        )
    finally:
        # Clean up resources (if needed)
        logger.info("Cleaning up MCP server resources...")


# Create FastMCP server instance (using Lifespan)
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
    """Record command execution events and state changes in the LLM honeypot"""
    
    # Get memory_system from context
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        await ctx.error("Memory system not available")
        return EventRecordResult(
            success=False,
            message="Memory system not initialized"
        )
    
    try:
        # Convert event type and status
        try:
            event_type_enum = EventType(event_type.upper())
        except ValueError:
            event_type_enum = EventType.COMMAND_EXECUTION
        
        try:
            status_enum = EventStatus(status.upper())
        except ValueError:
            status_enum = EventStatus.SUCCESS
        
        # Process state changes
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
        
        # Create event node
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
        
        # Record event
        event_id = memory_system.record_event(event)
        
        # Log success using MCP logger
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
    """Query system state information for a specific IP"""
    
    # Get memory_system from context
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
        
        # Added: User list query
        elif query_type == "user_list":
            data = {
                "users": system_state.users.users,
                "groups": system_state.users.groups
            }
        
        # Added: Cron list query
        elif query_type == "cron_list":
            data = {
                "user_crontabs": system_state.cron.user_crontabs,
                "system_cron_files": system_state.cron.system_cron_files
            }
        
        # Added: Service list query
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
    """Get event graph information for a specific IP"""
    
    # Get memory_system from context
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
        
        # Get events
        events = event_graph.get_events(session_id=session_id)
        
        # Convert to dictionary format
        events_data = []
        for event in events:
            events_data.append({
                "event_id": event.id,  # Use id instead of event_id
                "command": event.command,
                "session_id": event.session_id,
                "event_type": event.event_type.value,
                "status": event.status.value,
                "timestamp": event.timestamp.isoformat(),
                "user_context": event.user_context
            })
        
        # Get relationships
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
    """Link IP to the specified instance ID"""
    
    # Get memory_system from context
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


# ====================== Resources (Expose State Data) ======================

@mcp.resource("system://state/{ip_address}")
def get_system_state_resource(ip_address: str, ctx: Context[ServerSession, AppContext]) -> str:
    """
    Get complete system state - Exposed as a Resource to LLM
    
    This is the data exposure method recommended by MCP, allowing LLM to directly access system state
    """
    memory_system = ctx.request_context.lifespan_context.memory_system
    
    if not memory_system:
        return json.dumps({"error": "Memory system not initialized"})
    
    try:
        state = memory_system.get_system_state(ip_address)
        state_dict = state.dict()
        
        # Convert datetime to ISO format
        state_dict["timestamp"] = state_dict["timestamp"].isoformat() if hasattr(state_dict["timestamp"], "isoformat") else str(state_dict["timestamp"])
        
        return json.dumps(state_dict, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting system state resource: {e}")
        return json.dumps({"error": str(e)})


# Note: Since current FastMCP version does not support {path:path} path parameter syntax, this resource is disabled
# If this feature is needed, use the corresponding tool method or consider upgrading FastMCP
# @mcp.resource("filesystem://directory/{ip_address}/{path:path}")
# def get_directory_listing_resource(ip_address: str, path: str, ctx: Context[ServerSession, AppContext]) -> str:
#     """
#     Get directory content list - Resource mode
#     
#     Example: filesystem://directory/192.168.1.1/tmp
#     """
#     memory_system = ctx.request_context.lifespan_context.memory_system
#     
#     if not memory_system:
#         return json.dumps({"error": "Memory system not initialized"})
#     
#     try:
#         # Ensure path starts with /
#         full_path = f"/{path}" if not path.startswith("/") else path
#         
#         contents = memory_system.get_directory_contents(ip_address, full_path)
#         return json.dumps(contents, indent=2, ensure_ascii=False)
#     except Exception as e:
#         logger.error(f"Error getting directory listing: {e}")
#         return json.dumps({"error": str(e), "files": [], "directories": []})


# Note: Since current FastMCP version does not support {path:path} path parameter syntax, this resource is disabled
# If this feature is needed, use the corresponding tool method or consider upgrading FastMCP
# @mcp.resource("filesystem://file/{ip_address}/{path:path}")
# def get_file_content_resource(ip_address: str, path: str, ctx: Context[ServerSession, AppContext]) -> str:
#     """
#     Get file content - Resource mode
#     
#     Example: filesystem://file/192.168.1.1/etc/passwd
#     """
#     memory_system = ctx.request_context.lifespan_context.memory_system
#     
#     if not memory_system:
#         return "Error: Memory system not initialized"
#     
#     try:
#         # Ensure path starts with /
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
    Get system state summary - Resource mode
    
    Provide quick overview, excluding detailed data
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
    Get event graph - Resource mode
    
    Expose complete event graph data
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
        
        # Export as dictionary
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


# ====================== Main Function ======================

def main():
    """Main function - Start MCP server"""
    import sys
    import os
    
    # Note: Since Lifespan is used, manual call to initialize_components is no longer needed
    # Lifespan will automatically initialize resources on server startup
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if "--help" in sys.argv or "-h" in sys.argv:
            print("MCP Honeypot State Management Server")
            print("MCP server implemented using official MCP framework")
            print()
            print("Usage:")
            print("  python mcp_server.py                    # Start MCP server (stdio transport)")
            print("  python mcp_server.py --help             # Show this help message")
            print("  python mcp_server.py --sse              # Start SSE server")
            print("  python mcp_server.py --http             # Start HTTP server")
            print()
            print("Environment Variables:")
            print("  STORAGE_PATH                            # Storage Path (Default: ./honeypot_memory)")
            print("  GLOBAL_SINGLETON_MODE                   # Global Singleton Mode Switch (true/false, Default: false)")
            print()
            print("MCP Tools:")
            print("  - record_event: Record command execution events and state changes")
            print("  - query_state: Query system state information")
            print("  - get_event_graph: Get event graph information")
            print("  - link_ip_to_instance: Link IP to specified instance ID")
            return
        
        elif "--sse" in sys.argv:
            # SSE Mode
            print("Starting SSE server...")
            mcp.run(transport="sse")
            return
            
        elif "--http" in sys.argv:
            # HTTP Mode (streamable-http)
            print("Starting HTTP server (streamable-http transport)...")
            mcp.run(transport="streamable-http")
            return
    
    # Default stdio mode
    print("Starting MCP server (stdio transport)...", file=sys.stderr)
    print("Server ready, waiting for MCP client connection", file=sys.stderr)
    
    # Run server (stdio transport)
    # Lifespan will handle initialization automatically
    mcp.run()


if __name__ == "__main__":
    main()
