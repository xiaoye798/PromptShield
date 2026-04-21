"""
MCP Honeypot State Management Server Entry Point

Provide standard MCP server entry points and support the stdio transmission protocol
"""

import sys
import asyncio
from pathlib import Path

# # Add the src directory to the Python path
src_path = Path(__file__).parent.parent
sys.path.insert(0, str(src_path))

from mcp_state_manager.fastmcp_server import main

if __name__ == "__main__":
    main()
