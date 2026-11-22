"""Manifest scanner: inspects every string in a tool definition (name, title, description,
inputSchema, annotations) for prompt-injection / poisoning text, and inspects the schema
itself for risky capabilities (mislabelled read-only tools, CLI argument pass-through,
credentialed requests to caller-chosen URLs)."""
import json, re, unicodedata

# (rule id, weight, regex over NFKC-normalised, lower-cased, whitespace-collapsed text)
TEXT_RULES = [
    ("HIDDEN_INSTRUCTION", 3,
     r"<\s*(important|system|instructions?|secret)\s*>|\bignore (all |any )?(previous|prior|above)\b"
     r"|\bdo not (tell|mention|inform|reveal)\b.{0,40}\b(user|human|this step)\b"),
    ("EXFIL_SENSITIVE_PATH", 3,
     r"(~/\.ssh|id_rsa|\.env\b|\.aws/credentials|/etc/passwd|mcp\.json|\.cursor/|api[_ -]?key|private key|\.kube/config|kubeconfig)"),
    ("CROSS_TOOL_SHADOW", 2,
     r"\b(when|whenever|before) (using|calling|you use|invoking) (the )?[`'\"]?\w+[`'\"]? tool\b"
     r"|\b(all|any) (emails?|messages?|requests?) (must|should) (be )?(sent|forwarded|cc)"),
    ("COVERT_PARAM", 2, r"\b(sidenote|side_note|notes?|context|metadata)\b.{0,60}\b(content|contents|full|entire)\b"),
    ("URL_EXFIL", 2, r"https?://[^\s\"']+\?(\w+=)?\{|send (it|them|the \w+) to https?://|curl\s+-d"),
    ("FORCED_CALL", 1, r"\byou must (always )?(call|invoke|run)\b|\bmandatory\b.{0,30}\b(call|step)"),
    # OpenHuman CVE-2026-54140 style: chat-template / instruction-fence markers and
    # model-addressed directives inside tool metadata.
    ("INSTRUCTION_FENCE", 3,
     r"<\|im_(start|end)\|>|<<\s*/?sys\s*>>|\[/?inst\]|\[/?sys(tem)?\]|#{2,} ?(system )?instructions?:"
     r"|\b(priority|high[- ]priority|urgent) (system )?(instruction|directive|override)\b|\bsystem (override|prompt update)\b"),
    ("MODEL_ADDRESSED", 2,
     r"\b(note|tip|message|instructions?|reminder)s? (to|for) (the )?(ai|assistant|model|llm|agent)s?\b"
     r"|\b(the |an )?(ai|assistant|model|llm|agent)s? (must|should|needs to) (always |also |first |silently |quietly )?"
     r"(call|send|copy|paste|include|append|upload|forward|read|run|invoke)\b"),
    ("STEALTH_ACTION", 2,
     r"\b(silently|quietly|secretly|covertly|discreetly)\b.{0,20}\b(call|send|copy|append|include|upload|forward|read|run|paste|exfiltrate|attach)\b"
     r"|\bkeep (this|that|it) between us\b|\bwithout (telling|notifying|informing|asking) the user\b"),
]

READONLY_CLAIM = re.compile(r"\bread[- ]?only\b|\bdoes not (modify|change|write)\b|\bno side[- ]effects\b|\bsafe to call\b")
WRITE_NAME = re.compile(r"(^|[_\-.])(create|delete|remove|update|write|put|post|patch|insert|drop|exec|execute|upload|modify|set|kill|deploy|save|move|rename|generate|apply)([_\-.]|$)")
WRITE_TEXT = re.compile(r"\b(writes?|saves?) (it |them |the (\w+ )?)?(to|into) (a |the |disk|file|path|\w+ (file|path|directory))|\boverwrites?\b|\bdeletes? (the |a |any )?(file|record|resource|bucket|table|directory|object)s?\b|\bcreates? (a |the |new )?(file|directory|folder)s?\b|\buploads? (to|the|a)\b")
WRITE_PARAM = re.compile(r"^(output_?(path|file|dir)?|out_?(path|file)|dest(ination)?(_path)?|save_?(to|path)|write_?(to|path)|target_?(path|file)|file_?path_?out)$")
SHELL_PARAM = re.compile(r"^(command|cmd|shell|script|shell_command|bash)$")
ARGV_PARAM = re.compile(r"^(args|argv|extra_?args|cli_?args|flags|extra_?flags|options_?string|raw_?args)$")
PASSTHRU_TEXT = re.compile(r"\b(passed|forwarded|appended|added|inserted) (directly |verbatim |as[- ]is |unchanged )?(to|into|onto) (the )?([\w-]+ )?(command|cli|command line|shell|subprocess|argv|invocation)\b"
                           r"|\b(raw|extra|additional) (cli |command[- ]line )?(flags|arguments|args)\b")
URL_PARAM = re.compile(r"^(url|uri|endpoint|host|hostname|base_?url|server_?url|server|api_?url|webhook(_url)?|callback(_url)?|instance_?url|target_?url|influx(db)?_?url)$")
CRED_TEXT = re.compile(r"\b(token|api[ _-]?key|credentials?|bearer|auth(entication|orization)?|secret|password)\b")

def _norm(s):
    s = "".join(c for c in s if unicodedata.category(c) != "Cf")
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", s)).lower()

def _strings(o, path=""):
    if isinstance(o, str):
        yield path, o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _strings(v, f"{path}[{i}]")

def _props(tool):
    schema = tool.get("inputSchema") or tool.get("input_schema") or tool.get("parameters") or {}
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}

def _free_string(spec):
    return isinstance(spec, dict) and spec.get("type", "string") == "string" and not spec.get("enum") and not spec.get("pattern") and "const" not in spec

def _capability_findings(tool):
    out = []
    name = str(tool.get("name", "")).lower()
    ann = tool.get("annotations") or {}
    desc = _norm(" ".join(str(tool.get(k, "")) for k in ("title", "description")))
    props = _props(tool)
    prop_text = {k: _norm(str(v.get("description", ""))) if isinstance(v, dict) else "" for k, v in props.items()}

    # 1. Read-only mislabel (AWS Pricing MCP CVE-2026-126816 pattern): tool claims read-only
    #    but its name, description, parameters or annotations show it can write.
    claims_ro = ann.get("readOnlyHint") is True or bool(READONLY_CLAIM.search(desc))
    if claims_ro:
        why = []
        if WRITE_NAME.search(name): why.append("name")
        if WRITE_TEXT.search(READONLY_CLAIM.sub(" ", desc)): why.append("description")
        if any(WRITE_PARAM.match(k.lower()) for k in props): why.append("write-path parameter")
        if ann.get("destructiveHint") is True: why.append("destructiveHint")
        if why:
            # A write-ish verb in the name or description alone is weak evidence (e.g.
            # "trigger-resource-update" only sends a notification), so it scores 2. A write-path
            # parameter, destructiveHint, or two independent signals score 3.
            w = 3 if (len(why) > 1 or why[0] in ("write-path parameter", "destructiveHint")) else 2
            out.append(("READONLY_MISLABEL", w, ".annotations" if ann.get("readOnlyHint") else ".description", "claims read-only but " + ", ".join(why) + " indicate writes"))

    # 2. Argument / shell pass-through (Kubeshark CVE-2026-129236 pattern, CWE-88):
    #    free-form strings that reach a command line can smuggle '--flag=' options.
    for k, spec in props.items():
        kl = k.lower()
        if not _free_string(spec):
            continue
        if SHELL_PARAM.match(kl):
            out.append(("SHELL_PASSTHROUGH", 2, f".inputSchema.properties.{k}", "unconstrained shell/command string"))
        elif ARGV_PARAM.match(kl) or PASSTHRU_TEXT.search(prop_text[k]):
            out.append(("ARG_INJECTION", 2, f".inputSchema.properties.{k}", "unconstrained string reaches a command line; values starting with '-' can become flags"))
    if PASSTHRU_TEXT.search(desc) and not any(f[0] == "ARG_INJECTION" for f in out):
        out.append(("ARG_INJECTION", 2, ".description", "description says caller values are passed to a command line"))

    # 3. Credentialed request to a caller-controlled URL (AWS Timestream for InfluxDB MCP
    #    GHSA-2f9r-g4f3-wc2j pattern): model context picks the endpoint, server attaches its token.
    url_params = [k for k, spec in props.items() if URL_PARAM.match(k.lower()) and _free_string(spec)]
    if url_params:
        all_text = desc + " " + " ".join(prop_text.values())
        if CRED_TEXT.search(all_text):
            for k in url_params:
                out.append(("CREDENTIALED_URL_PARAM", 2, f".inputSchema.properties.{k}", "caller chooses the endpoint of a request that carries server credentials"))
    return out

def scan_tool(tool):
    findings = []
    for path, s in _strings(tool):
        if any(unicodedata.category(c) == "Cf" for c in s):
            findings.append(("INVISIBLE_UNICODE", 3, path, "zero-width / format characters"))
        norm = _norm(s)
        for rid, w, rx in TEXT_RULES:
            if re.search(rx, norm):
                findings.append((rid, w, path, ""))
        if len(s.encode("utf-8")) > 1024 and path in (".description", ".title"):
            findings.append(("OVERLONG_DESCRIPTION", 1, path, "over 1024 bytes"))
    findings += _capability_findings(tool)
    # Each rule counts once toward the score, however many fields it fires in.
    score = sum({rid: w for rid, w, _, _ in findings}.values())
    uniq = sorted({(rid, p, note) for rid, _, p, note in findings})
    return {"tool": tool.get("name"), "score": score, "flagged": score >= 3,
            "findings": [{"rule": r, "path": p, **({"note": n} if n else {})} for r, p, n in uniq]}

def load_tools(obj):
    """Accepts a bare list of tools, {"tools": [...]}, or a JSON-RPC tools/list response."""
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        if isinstance(obj.get("result"), dict):
            obj = obj["result"]
        if isinstance(obj.get("tools"), list):
            return obj["tools"]
    return []

def scan_manifest(m):
    return [scan_tool(t) for t in load_tools(m) if isinstance(t, dict)]

def scan_file(path):
    with open(path, encoding="utf-8") as f:
        return scan_manifest(json.load(f))
