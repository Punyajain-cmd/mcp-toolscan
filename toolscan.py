"""Backward-compatible entry point (v0.1). Prefer `mcp-toolscan` or `python -m mcp_toolscan`."""
import sys
from mcp_toolscan import scan_tool, scan_manifest  # noqa: F401
from mcp_toolscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
