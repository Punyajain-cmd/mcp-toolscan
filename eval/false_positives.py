"""False-positive check on real, benign MCP tool manifests (tools/list output of the official
reference servers, captured with fetch_real_manifests.py) plus the fixed AWS Pricing server."""
import glob, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from mcp_toolscan import scan_manifest
files = sorted(glob.glob(os.path.join(HERE, "real_world", "*.json"))) + [os.path.join(HERE, "cve_regression", "aws-pricing-1.0.31.json")]
n = flagged = withfind = 0; detail = []
for f in files:
    for r in scan_manifest(json.load(open(f))):
        n += 1; flagged += r["flagged"]
        real = [x["rule"] for x in r["findings"] if x["rule"] != "OVERLONG_DESCRIPTION"]
        if real: withfind += 1; detail.append((os.path.basename(f), r["tool"], real, r["flagged"]))
out = {"servers": len(files), "tools": n, "flagged": flagged, "tools_with_non_length_findings": withfind, "details": detail}
print(json.dumps(out, indent=1)); json.dump(out, open(os.path.join(HERE, "false_positive_results.json"), "w"), indent=1)
