"""Source scanner: line-window heuristics over MCP server code (Python, JS/TS, Go) for
patterns behind recent MCP CVEs. Heuristic by design: findings are leads for review."""
import os, re

EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}

ENV_READ = r"(os\.environ(\.get)?\s*[\[(]|os\.getenv\s*\(|process\.env\.|process\.env\[|os\.Getenv\s*\()"
CI_ENV = re.compile(ENV_READ + r"\s*['\"]?(CI|GITHUB_ACTIONS|TESTING|TEST|PYTEST_CURRENT_TEST|NODE_ENV|DEBUG|DEV_MODE)\b")
CI_NAME = re.compile(r"['\"](CI|GITHUB_ACTIONS|GITLAB_CI|TESTING|TEST|PYTEST_CURRENT_TEST|NODE_ENV|DEBUG|DEV_MODE)['\"]")
ENV_ANY = re.compile(r"os\.environ|os\.getenv|process\.env|os\.Getenv|os\.LookupEnv")
BYPASS = re.compile(r"Path\(\s*['\"]/['\"]\s*\)|return\s+['\"]/['\"]|\b(skip|bypass|disable|allow_?all|unrestricted|no_?sandbox)\w*|return\s+(True|true|path|p|resolved|abs_?path)\b|\b(validate|check|enforce|restrict)\w*\s*[:=]\s*(False|false)")
BASE_ENV = re.compile(r"(\w+)\s*:?=\s*" + ENV_READ + r"\s*['\"]\w*(DIR|ROOT|BASE|PATH|FOLDER)\w*['\"]\s*\)?\s*(;|$|\))")
EXEC_CALL = re.compile(r"subprocess\.(run|Popen|call|check_call|check_output)\s*\(|exec\.Command(Context)?\s*\(|\b(spawn|execFile|spawnSync|execFileSync)\s*\(|os\.exec[lv]p?e?\s*\(")
SHELL_STR = re.compile(r"shell\s*=\s*True|os\.system\s*\(|\bexecSync\s*\(\s*[`'\"].*\$\{|child_process\.exec\s*\(\s*[`'\"].*\$\{")
ARG_SRC = re.compile(r"\b(args|arguments|params|request|req|tool_input|input|kwargs|payload)\s*(\.|\[|\.get\()")
END_OPTS = re.compile(r"""['"]--['"]""")
HTTP_CALL = re.compile(r"\b(requests|httpx|session|client)\.(get|post|put|request|delete|patch)\s*\(|\bfetch\s*\(|\baxios(\.\w+)?\s*\(|http\.NewRequest(WithContext)?\s*\(|urlopen\s*\(")
ARG_URL = re.compile(r"\b(args|arguments|params|request|req|tool_input|input|kwargs)\s*(\.|\[\s*['\"]|\.get\(\s*['\"])\w*(url|uri|endpoint|host|server)\w*", re.I)
_FB = r"\s*(?:=|:=)\s*\w+\s*(?:or|\|\||\?\?)\s*(?:os\.(?:getenv|environ)|process\.env|config\.|settings\.|[A-Z][A-Z0-9_]*)"
URL_FALLBACK = re.compile(r"\b\w*(url|uri|endpoint|host)\w*" + _FB + r"\w*", re.I)
CRED_FALLBACK = re.compile(r"\b\w*(token|api_?key|secret|password|credential)\w*" + _FB + r"\w*", re.I)
AUTH_HDR = re.compile(r"authorization|bearer|x-api-key|api[_-]?key|\btoken\b", re.I)


FUNC_START = re.compile(r"^\s*(async\s+)?(def|func|function)\b|^\s*(export\s+)?(async\s+)?function\b|=>\s*\{\s*$")
ASSIGN = re.compile(r"(?:^|[\s(;])(?:const |let |var )?(\w+)\s*(?:,\s*\w+)?\s*(?::=|=)(?!=)\s*(.+)")
GROW = re.compile(r"\b(append|push|extend|insert)\s*\((.*)\)|\+=\s*\[(.*)\]|=\s*\[(.*)\]|\(\s*\[(.*)\]")
LIT = re.compile(r"""^\s*[`'"](.*)[`'"]\s*$""")

def _tainted_argv(lines, i):
    """True if the function around line i appends a tool-argument value to an argv list as a
    bare positional (not as the value of a '-x' flag) and never adds a '--' separator."""
    lo = i
    while lo > 0 and i - lo < 80 and not FUNC_START.search(lines[lo]):
        lo -= 1
    region = lines[lo:i + 1]
    if any(END_OPTS.search(l) for l in region):
        return False
    tainted = set()
    for l in region:
        m = ASSIGN.search(l)
        if m and ARG_SRC.search(m.group(2)):
            tainted.add(m.group(1))
    for l in region:
        g = GROW.search(l)
        if not g:
            continue
        elems = [e.strip() for e in next(x for x in g.groups()[1:] if x is not None).split(",")]
        elems = [e.strip("[]() ") for e in elems]
        for j, e in enumerate(elems):
            if e in tainted or ARG_SRC.search(e):
                if j == 0 and g.group(1) in ("append", "insert") and re.search(r"\bappend\s*\(\s*\w+\s*,", l):
                    continue  # Go: append(slice, ...) - first element is the slice itself
                prev = LIT.match(elems[j - 1]) if j > 0 else None
                if prev and prev.group(1).startswith("-") and "=" not in prev.group(1):
                    continue  # value of a flag like "-n", v: consumed as a value, not parsed as a flag
                return True
    return False

def _window(lines, i, before, after):
    return "\n".join(lines[max(0, i - before): i + after + 1])

def scan_text(text, path="<string>"):
    lines = text.splitlines()
    out = []
    def add(rule, sev, i, note):
        out.append({"rule": rule, "severity": sev, "file": path, "line": i + 1, "note": note})
    for i, line in enumerate(lines):
        # A. Folder sandbox silently switched off by environment (AWS Document Loader MCP
        #    CVE-2026-130901 pattern: base dir unset + CI/test env => no confinement).
        ci_gate = CI_ENV.search(line) or (CI_NAME.search(line) and ENV_ANY.search(_window(lines, i, 2, 2)))
        if ci_gate and not line.lstrip().startswith(("#", "//")) and BYPASS.search(_window(lines, i, 0, 5)):
            add("SANDBOX_ENV_BYPASS", "high", i, "a CI/test/debug environment variable gates a path or validation bypass")
        m = BASE_ENV.search(line)
        if m:
            var = re.escape(m.group(1))
            win = _window(lines, i, 0, 8)
            if re.search(r"if\s*\(?\s*(not\s+|!\s*)" + var + r"\b|if\s+" + var + r"\s*(is None|==\s*None|==\s*['\"]{2})", win) and re.search(r"return\b", win):
                add("SANDBOX_OPTIONAL_BASE_DIR", "medium", i, f"confinement root '{m.group(1)}' comes from env and an unset value appears to short-circuit the check")
        # B. Argument injection into a CLI (Kubeshark CVE-2026-129236 pattern, CWE-88).
        if SHELL_STR.search(line) and ARG_SRC.search(_window(lines, i, 4, 1)):
            add("SHELL_INJECTION", "high", i, "shell command string built near tool arguments")
        elif EXEC_CALL.search(line):
            if _tainted_argv(lines, i):
                add("ARG_INJECTION", "medium", i, "process argv includes tool-argument values with no '--' end-of-options separator")
        # C. Server credential sent to a caller-chosen URL (AWS Timestream for InfluxDB MCP
        #    GHSA-2f9r-g4f3-wc2j pattern).
        if URL_FALLBACK.search(line) and CRED_FALLBACK.search(_window(lines, i, 6, 6)):
            add("CREDENTIAL_URL_MIX", "high", i, "caller-supplied URL falls back independently of the server's stored credential, so a caller URL can receive the server token")
        if HTTP_CALL.search(line):
            win = _window(lines, i, 8, 4)
            if ARG_URL.search(win) and AUTH_HDR.search(win):
                add("CREDENTIAL_TO_ARG_URL", "high", i, "request URL comes from tool arguments and the request carries credentials")
    return out

def scan_source(root):
    if os.path.isfile(root):
        with open(root, encoding="utf-8", errors="replace") as f:
            return scan_text(f.read(), root)
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for fn in sorted(files):
            if os.path.splitext(fn)[1] in EXTS:
                p = os.path.join(d, fn)
                try:
                    with open(p, encoding="utf-8", errors="replace") as f:
                        out += scan_text(f.read(), os.path.relpath(p, root))
                except OSError:
                    pass
    return out
