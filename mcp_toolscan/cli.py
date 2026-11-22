import argparse, json, sys
from . import __version__
from .manifest import scan_file
from .source import scan_source
from .pth import scan_pth

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

def main(argv=None):
    ap = argparse.ArgumentParser(prog="mcp-toolscan", description="Static scanner for poisoned/risky MCP tool definitions, MCP server source, and .pth startup hooks.")
    ap.add_argument("manifest", nargs="*", help="tool manifest JSON (list, {tools:[...]}, or a tools/list JSON-RPC response)")
    ap.add_argument("--source", action="append", default=[], metavar="PATH", help="scan MCP server source code (file or directory)")
    ap.add_argument("--pth", action="append", default=[], metavar="PATH", help="scan for .pth startup hooks (site-packages dir, package dir, .whl, .tar.gz)")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON lines")
    ap.add_argument("--all", action="store_true", help="also print unflagged tools and info-level findings")
    ap.add_argument("--fail-on", choices=["medium", "high", "never"], default="high", help="exit 1 if a code/.pth finding reaches this severity (manifests: any flagged tool) [default: high]")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if not (a.manifest or a.source or a.pth):
        ap.print_help(); return 2
    bad = False
    thr = SEV_ORDER.get(a.fail_on, 99)
    for m in a.manifest:
        for r in scan_file(m):
            bad |= r["flagged"] and a.fail_on != "never"
            if a.json:
                print(json.dumps({"kind": "tool", "file": m, **r}))
            elif r["flagged"] or a.all:
                tag = "FLAG" if r["flagged"] else "ok  "
                print(f"[{tag}] {m}: tool {r['tool']!r} score={r['score']}")
                for f in r["findings"]:
                    print(f"        {f['rule']:<24} {f['path']}" + (f"  - {f['note']}" if f.get("note") else ""))
    findings = [("code", f) for s in a.source for f in scan_source(s)] + [("pth", f) for p in a.pth for f in scan_pth(p)]
    for kind, f in findings:
        if f["severity"] == "info" and not a.all:
            continue
        bad |= SEV_ORDER[f["severity"]] >= thr
        if a.json:
            print(json.dumps({"kind": kind, **f}))
        else:
            print(f"[{f['severity'].upper():<6}] {f['file']}:{f['line']}  {f['rule']}  - {f['note']}")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
