import subprocess
def run(arguments):
    branch = arguments["branch"]
    return subprocess.run(f"git log {branch}", shell=True)
