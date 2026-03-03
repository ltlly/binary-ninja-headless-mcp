"""Single-command launcher for the simple Binary Ninja Headless MCP server.

Usage:
    python binary_ninja_headless_mcp.py
"""

from binary_ninja_headless_mcp.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
