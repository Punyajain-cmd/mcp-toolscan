"""Collects tools/list output from public reference MCP servers (benign, for false-positive
measurement). Requires node/npx and uv. Writes eval/real_world/<server>.json."""
import json, os, subprocess, sys, tempfile
SERVERS = {
    "filesystem": ["npx", "-y", "@modelcontextprotocol/server-filesystem", tempfile.gettempdir()],
    "memory": ["npx", "-y", "@modelcontextprotocol/server-memory"],
    "everything": ["npx", "-y", "@modelcontextprotocol/server-everything"],
    "sequential-thinking": ["npx", "-y", "@modelcontextprotocol/server-sequential-thinking"],
    "fetch": ["uvx", "mcp-server-fetch"],
    "git": ["uvx", "mcp-server-git"],
    "time": ["uvx", "mcp-server-time"],
}
def rpc(p, i, method, params=None):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n"); p.stdin.flush()
    while True:
        line = p.stdout.readline()
        if not line: raise RuntimeError("server closed")
        try: msg = json.loads(line)
        except ValueError: continue
        if msg.get("id") == i: return msg
def main():
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "real_world")
    os.makedirs(out, exist_ok=True)
    for name, cmd in SERVERS.items():
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            rpc(p, 1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-toolscan-eval", "version": "0"}})
            p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"); p.stdin.flush()
            res = rpc(p, 2, "tools/list")
            json.dump(res["result"], open(os.path.join(out, f"{name}.json"), "w"), indent=1)
            print(name, len(res["result"]["tools"]), "tools")
            p.kill()
        except Exception as e:
            print(name, "FAILED", e, file=sys.stderr)
if __name__ == "__main__": main()
