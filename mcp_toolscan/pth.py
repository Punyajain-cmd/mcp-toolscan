""".pth startup-hook scanner. Python executes any line of a site-packages .pth file that
starts with 'import', at every interpreter start. Malicious packages (e.g. the 2026 PyPI
credential stealers) abuse this for persistence. Scans directories, wheels/zips and sdists."""
import io, os, re, tarfile, zipfile

SUSPICIOUS = re.compile(r"\b(exec|eval|compile|b64decode|base64|marshal|zlib|codecs\.decode|subprocess|os\.system|popen|urllib|urlopen|requests|httpx|socket|http\.client|getenv|environ)\b|\\x[0-9a-f]{2}|__import__\(\s*['\"](base64|subprocess|socket|urllib|requests)", re.I)
# Well-known benign hooks shipped by setuptools, virtualenv, coverage, editable installs, namespace pkgs.
KNOWN = re.compile(r"^(distutils-precedence|_virtualenv|coverage|a1_coverage|__editable__\..*|.*-nspkg|_[\w-]*_editable|matplotlib|pywin32|setuptools)\.pth$")

def scan_pth_text(text, name):
    out = []
    base = os.path.basename(name)
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not (s.startswith("import ") or s.startswith("import\t")):
            continue
        sus = bool(SUSPICIOUS.search(s))
        if KNOWN.match(base) and not re.search(r"b64decode|exec\(|eval\(|socket|urlopen|requests|http", s):
            sev, rule = "info", "PTH_KNOWN_HOOK"
        elif sus:
            sev, rule = "high", "PTH_SUSPICIOUS_EXEC"
        else:
            sev, rule = "medium", "PTH_EXEC_LINE"
        out.append({"rule": rule, "severity": sev, "file": name, "line": n,
                    "note": f"executable .pth line ({len(s)} chars)"})
    return out

def _scan_archive(path):
    out = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for n in z.namelist():
                    if n.endswith(".pth"):
                        out += scan_pth_text(z.read(n).decode("utf-8", "replace"), f"{path}!{n}")
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                for m in t.getmembers():
                    if m.isfile() and m.name.endswith(".pth"):
                        f = t.extractfile(m)
                        if f:
                            out += scan_pth_text(f.read().decode("utf-8", "replace"), f"{path}!{m.name}")
    except (OSError, zipfile.BadZipFile, tarfile.TarError):
        pass
    return out

def scan_pth(root):
    """root: a directory (e.g. site-packages or an unpacked package), a .pth file,
    or a .whl/.zip/.tar.gz archive."""
    if os.path.isfile(root):
        if root.endswith(".pth"):
            with open(root, encoding="utf-8", errors="replace") as f:
                return scan_pth_text(f.read(), root)
        return _scan_archive(root)
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in {".git", "node_modules"}]
        for fn in files:
            p = os.path.join(d, fn)
            if fn.endswith(".pth"):
                with open(p, encoding="utf-8", errors="replace") as f:
                    out += scan_pth_text(f.read(), p)
            elif fn.endswith((".whl", ".tar.gz", ".tgz")) or (fn.endswith(".zip") and "dist" in d):
                out += _scan_archive(p)
    return out
