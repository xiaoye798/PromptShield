"""
MCP Honeypot State Management Package (MCP)
This package provides a complete MCP (Model Context Protocol) honeypot state management system,
used for managing and analyzing the state changes and event flows in the LLM honeypot environment.
Main functions:
- Event graph management: Tracking the cause-and-effect relationship of command execution and state changes
- Structured long-term memory: Persistently storing system states and historical events
- IP isolated state storage: Maintaining independent state spaces for different IP addresses
"""

__version__ = "1.0.0"
__author__ = "MCP Honeypot State Manager Team"

# Import core modules
from .event_graph import EventGraph, EventNode, EventType, EventStatus, StateChange
from .memory_system import MemorySystem, SystemState
from .fastmcp_server import mcp  # Note: Using Lifespan, initialize_components is no longer needed
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
    # "initialize_components",  # Removed: Automatically managed using Lifespan
    "StateContextBuilder",
    "SystemTemplate",
    "ContextOptimizer"
]
