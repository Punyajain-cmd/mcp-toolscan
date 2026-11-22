# Changelog

## 0.2.0 (2026-11-22)
- Package layout (`mcp_toolscan/`), `mcp-toolscan` CLI with CI-friendly exit codes, JSON output.
- Accepts bare tool lists, `{"tools": [...]}`, and raw `tools/list` JSON-RPC responses.
- New manifest rules: `INSTRUCTION_FENCE`, `MODEL_ADDRESSED`, `STEALTH_ACTION` (OpenHuman CVE-2026-54140 style),
  `READONLY_MISLABEL` (AWS Pricing MCP CVE-2026-126816), `ARG_INJECTION` / `SHELL_PASSTHROUGH` (Kubeshark CVE-2026-129236),
  `CREDENTIALED_URL_PARAM` (AWS Timestream for InfluxDB MCP GHSA-2f9r-g4f3-wc2j). `title` fields are scanned.
- New `--source` scanner: `SANDBOX_ENV_BYPASS`, `SANDBOX_OPTIONAL_BASE_DIR` (AWS Document Loader MCP CVE-2026-130901),
  `ARG_INJECTION`, `SHELL_INJECTION`, `CREDENTIAL_URL_MIX`, `CREDENTIAL_TO_ARG_URL`.
- New `--pth` scanner for executable `.pth` startup hooks in site-packages, wheels and sdists.
- Real-world evaluation: CVE regression on upstream vulnerable/fixed code, false-positive check on official reference servers.

## 0.1.0 (2026-11-01)
- Single-file regex scanner for tool-poisoning text (hidden instructions, secret paths, shadowing, invisible Unicode, NFKC).
