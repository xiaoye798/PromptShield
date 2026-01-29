"""
MCP蜜罐状态管理服务器入口点 (MCP Honeypot State Management Server Entry Point)

提供标准的MCP服务器入口点，支持stdio传输协议
"""

import sys
import asyncio
from pathlib import Path

# 添加src目录到Python路径
src_path = Path(__file__).parent.parent
sys.path.insert(0, str(src_path))

from mcp_state_manager.fastmcp_server import main

if __name__ == "__main__":
    main()