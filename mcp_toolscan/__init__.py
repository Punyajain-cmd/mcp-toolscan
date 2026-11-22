"""mcp-toolscan: static scanner for poisoned or risky MCP / agent tool definitions,
risky MCP server source patterns, and malicious .pth startup hooks. Stdlib only."""
from .manifest import scan_tool, scan_manifest, load_tools
from .source import scan_source
from .pth import scan_pth

__version__ = "0.2.0"
__all__ = ["scan_tool", "scan_manifest", "load_tools", "scan_source", "scan_pth", "__version__"]
