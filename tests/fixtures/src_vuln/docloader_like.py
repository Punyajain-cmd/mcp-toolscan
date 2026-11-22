# Synthetic reproduction of the AWS Document Loader MCP CVE-2026-130901 pattern.
import os
from pathlib import Path

def _get_base_directory():
    env_base = os.getenv("DOCUMENT_BASE_DIR")
    if env_base:
        return Path(env_base)
    if any(k in os.environ for k in ["PYTEST_CURRENT_TEST", "CI", "GITHUB_ACTIONS"]):
        return Path("/")
    return Path.cwd()
