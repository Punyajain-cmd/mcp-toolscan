import os, subprocess
from pathlib import Path
BASE = Path(os.getenv("DOCUMENT_BASE_DIR", os.getcwd())).resolve()

def run(arguments):
    regex = arguments["pod_regex"]
    cmd = ["kubeshark", "tap", "-n", arguments["namespace"], "--", regex]
    return subprocess.run(cmd, shell=False)

def resolve(url=None, token=None):
    if url is not None and token is None:
        raise ValueError("custom url requires its own token")
    return url, token
