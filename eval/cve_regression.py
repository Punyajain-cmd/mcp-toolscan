"""Regression check against REAL vulnerable and fixed MCP server code/manifests.
Downloads source files from upstream at pinned refs (nothing vendored) and scans them.
Note: the v0.2 rules were written after reading these advisories, so this shows the rules
reproduce the known bugs and stay quiet on the fixes; it is not an unbiased recall estimate."""
import json, os, sys, tempfile, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from mcp_toolscan import scan_source, scan_manifest

AWS = "https://raw.githubusercontent.com/awslabs/mcp/{ref}/src/{path}"
KS = "https://raw.githubusercontent.com/kubeshark/kubeshark/{ref}/cmd/mcpRunner.go"
DL = "document-loader-mcp-server/awslabs/document_loader_mcp_server/server.py"
TS = "timestream-for-influxdb-mcp-server/awslabs/timestream_for_influxdb_mcp_server/server.py"
SOURCE_CASES = [  # (advisory, expected rule, vulnerable url, fixed url)
    ("Kubeshark CVE-2026-129236 / GHSA-8vf2-hxg5-crqh", "ARG_INJECTION", KS.format(ref="v53.3.0"), KS.format(ref="v53.4.0")),
    ("AWS Document Loader MCP CVE-2026-130901", "SANDBOX_ENV_BYPASS", AWS.format(ref="2026.08.20260813230114", path=DL), AWS.format(ref="2026.11.20261119223057", path=DL)),
    ("AWS Timestream for InfluxDB MCP GHSA-2f9r-g4f3-wc2j", "CREDENTIAL_URL_MIX", AWS.format(ref="2026.05.20260508233259", path=TS), AWS.format(ref="2026.09.20260922000649", path=TS)),
]
MANIFEST_CASES = [  # tools/list captured from `uvx --with "mcp<2" awslabs.aws-pricing-mcp-server@VER`
    ("AWS Pricing MCP CVE-2026-126816", "READONLY_MISLABEL", "generate_cost_report",
     os.path.join(HERE, "cve_regression", "aws-pricing-1.0.30.json"), os.path.join(HERE, "cve_regression", "aws-pricing-1.0.31.json")),
]

def fetch(url, d):
    p = os.path.join(d, url.rsplit("/", 1)[-1] + "." + str(abs(hash(url))) + os.path.splitext(url)[1])
    with urllib.request.urlopen(url, timeout=60) as r, open(p, "wb") as f:
        f.write(r.read())
    return p

def main():
    rows = []
    with tempfile.TemporaryDirectory() as d:
        for name, rule, vuln, fixed in SOURCE_CASES:
            hv = any(f["rule"] == rule for f in scan_source(fetch(vuln, d)))
            hf = [f["rule"] for f in scan_source(fetch(fixed, d))]
            rows.append({"case": name, "rule": rule, "vulnerable_detected": hv, "fixed_findings": hf})
    for name, rule, tool, vuln, fixed in MANIFEST_CASES:
        rv = {r["tool"]: r for r in scan_manifest(json.load(open(vuln)))}
        rf = {r["tool"]: r for r in scan_manifest(json.load(open(fixed)))}
        rows.append({"case": name, "rule": rule, "vulnerable_detected": rv[tool]["flagged"] and any(f["rule"] == rule for f in rv[tool]["findings"]),
                     "fixed_findings": [f["rule"] for f in rf[tool]["findings"] if f["rule"] == rule]})
    print(json.dumps(rows, indent=1))
    json.dump(rows, open(os.path.join(HERE, "cve_regression_results.json"), "w"), indent=1)
    return 0 if all(r["vulnerable_detected"] and not r["fixed_findings"] for r in rows) else 1

if __name__ == "__main__":
    sys.exit(main())
