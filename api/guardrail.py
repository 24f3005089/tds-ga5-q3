"""TDS GA5 Q3 - Agent Harness: pre-tool-call guardrail hook.
Deterministic policy engine. No LLM, stdlib + FastAPI only.
"""

import base64
import binascii
import os
import posixpath
import re
from fnmatch import fnmatchcase
from urllib.parse import urlsplit
from fastapi import APIRouter

# ===========================================================================
# CONFIG - Personalized for your specific task scenario
# ===========================================================================
SECRET = os.environ.get("Q3_SECRET", "/home/agent/.secrets")
WRITE_ROOT = os.environ.get("Q3_WRITE_ROOT", "/srv/reports").rstrip("/")
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("Q3_ALLOWED_HOSTS", "registry.npmjs.org,api.github.com").split(",")
    if h.strip()
}
HOME = os.environ.get("Q3_HOME", "/home/agent")
CWD = os.environ.get("Q3_CWD", HOME + "/workspace")
# ===========================================================================

router = APIRouter()

SECRET_NAME = posixpath.basename(SECRET).lower()   # ".secrets"
SECRET_REVERSED = SECRET_NAME[::-1]                # "stcrces."

DANGEROUS_READS = {
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/sudoers",
}

NETWORK_TOOLS = re.compile(
    r"\b(curl|wget|nc|ncat|netcat|http|httpie|aria2c|scp|ftp|telnet)\b", re.I
)

CMD_SPLIT = re.compile(r"[;&|\n]+")
DEST_LAST_CMDS = re.compile(r"^(?:sudo\s+)?(cp|mv|install|rsync|ln)\b\s+(.*)$", re.I)
DEST_ALL_CMDS = re.compile(r"^(?:sudo\s+)?(touch|mkdir|truncate|mkfifo|mknod)\b\s+(.*)$", re.I)
DD_CMD = re.compile(r"^(?:sudo\s+)?dd\b(.*)$", re.I)
SED_INPLACE = re.compile(r"^(?:sudo\s+)?sed\b(.*)$", re.I)
REDIRECT = re.compile(r"(?:>>?\|?|\btee\b(?:\s+-a)?)\s*([^\s;|&'\"]+)")

PATH_TOKEN = re.compile(r"[~$A-Za-z0-9_.{}/*?\-]{2,}")
URL_TOKEN = re.compile(
    r"(?:[a-zA-Z][a-zA-Z0-9+.\-]*://|//)?[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?:[:/][^\s'\"|;&)]*)?"
)
B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_BLOB = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")


def _decode_escapes(text):
    def hex_sub(m):
        return chr(int(m.group(1), 16))
    def oct_sub(m):
        return chr(int(m.group(1), 8))

    out = re.sub(r"\\x([0-9a-fA-F]{2})", hex_sub, text)
    out = re.sub(r"\\u([0-9a-fA-F]{4})", hex_sub, out)
    out = re.sub(r"\\([0-7]{3})", oct_sub, out)
    return out


def _strip_quoting(text):
    out = re.sub(r"\\(.)", r"\1", text)
    out = out.replace('"', "").replace("'", "")
    return out


def _printable(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    printable = sum(1 for ch in text if ch == "\n" or ch == "\t" or 32 <= ord(ch) < 127)
    return text if printable / len(text) > 0.85 else None


def _decoded_blobs(text):
    seen = set()
    for m in B64_TOKEN.finditer(text):
        token = m.group(0)
        pad = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(pad, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _printable(raw)
        if decoded and decoded not in seen:
            seen.add(decoded)
            yield decoded
    for m in HEX_BLOB.finditer(text):
        token = m.group(0)
        if len(token) % 2:
            token = token[:-1]
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            continue
        decoded = _printable(raw)
        if decoded and decoded not in seen:
            seen.add(decoded)
            yield decoded


def expand(command, depth=3):
    variants = []
    seen = set()
    frontier = [command]
    for _ in range(depth + 1):
        nxt = []
        for text in frontier:
            for form in (text, _strip_quoting(_decode_escapes(text))):
                if form in seen:
                    continue
                seen.add(form)
                variants.append(form)
                nxt.extend(_decoded_blobs(form))
        if not nxt:
            break
        frontier = nxt
    return variants


def canonicalize(token, base=None):
    base = base or CWD
    path = token.strip()
    if not path:
        return ""
    path = path.replace("${HOME}", HOME).replace("$HOME", HOME)
    path = path.replace("${PWD}", CWD).replace("$PWD", CWD)
    path = path.replace("$OLDPWD", HOME)
    if path == "~" or path.startswith("~/"):
        path = HOME + path[1:]
    if not path.startswith("/"):
        path = posixpath.join(base, path)
    path = posixpath.normpath(path)
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def is_under(path, root):
    return path == root or path.startswith(root + "/")


def _bash_write_targets(text):
    targets = []
    for m in REDIRECT.finditer(text):
        tgt = m.group(1)
        if tgt not in ("/dev/null", "/dev/stdout", "/dev/stderr", "&1", "&2"):
            targets.append(tgt)

    for seg in CMD_SPLIT.split(text):
        seg = seg.strip()
        if not seg:
            continue

        m = DD_CMD.match(seg)
        if m:
            of_m = re.search(r"\bof=([^\s]+)", m.group(1))
            if of_m:
                targets.append(of_m.group(1))
            continue

        m = SED_INPLACE.match(seg)
        if m and re.search(r"(?:^|\s)(-i\b|-i\S*|--in-place)", m.group(1)):
            toks = [t for t in m.group(1).split() if t and not t.startswith("-")]
            if toks:
                targets.append(toks[-1])
            continue

        m = DEST_LAST_CMDS.match(seg)
        if m:
            toks = [t for t in m.group(2).split() if t and not t.startswith("-")]
            if len(toks) >= 2:
                targets.append(toks[-1])
            continue

        m = DEST_ALL_CMDS.match(seg)
        if m:
            for tok in m.group(2).split():
                if tok and not tok.startswith("-"):
                    targets.append(tok)
            continue

    return targets


def _cd_targets(text):
    bases = []
    for m in re.finditer(r"\bcd\s+([^\s;|&]+)", text):
        target = canonicalize(m.group(1))
        if target and target not in bases:
            bases.append(target)
    return bases


def _hits_secret(token, base):
    canon = canonicalize(token, base)
    if canon == SECRET:
        return True
    if token.startswith(("/", "~", "$")) and ("*" in canon or "?" in canon):
        if fnmatchcase(SECRET, canon):
            return True
    return False


def host_of(url):
    raw = (url or "").strip()
    if not raw:
        return None
    if "\\" in raw:
        return None
    if "://" not in raw:
        raw = "//" + raw.lstrip("/")
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    host = parts.hostname
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if not host or not re.fullmatch(r"[a-z0-9.\-]+", host):
        return None
    return host


def host_allowed(url):
    raw = (url or "").strip()
    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return False, scheme + "://"
    host = host_of(raw)
    if host is None:
        return False, None
    return host in ALLOWED_HOSTS, host


SECRET_MSG = "Reading the restricted secret file %s is never permitted." % SECRET


def check_bash(command):
    if not isinstance(command, str) or not command.strip():
        return "block", "Empty or non-string bash command cannot be evaluated."

    for text in expand(command):
        low = text.lower()
        if SECRET_NAME in low or SECRET_REVERSED in low:
            return "block", SECRET_MSG

        bases = [CWD] + _cd_targets(text)
        for token in PATH_TOKEN.findall(text):
            for base in bases:
                if _hits_secret(token, base):
                    return "block", SECRET_MSG
            canon = canonicalize(token, CWD)
            if canon in DANGEROUS_READS:
                return "block", "Reading %s is never permitted by this agent's policy." % canon

        cd_bases = _cd_targets(text)
        write_base = cd_bases[-1] if cd_bases else CWD
        for target in _bash_write_targets(text):
            canon = canonicalize(target, write_base)
            if canon == SECRET or not is_under(canon, WRITE_ROOT):
                return "block", "Writing to %s is outside the allowed write root %s/." % (
                    canon, WRITE_ROOT)

        if NETWORK_TOOLS.search(text):
            for m in URL_TOKEN.finditer(text):
                candidate = m.group(0)
                if "://" not in candidate and "/" not in candidate:
                    continue
                host = host_of(candidate)
                if host is None or "." not in host:
                    continue
                if host not in ALLOWED_HOSTS:
                    return "block", "Outbound request to '%s' is not on the host allowlist." % host

    return "allow", "Command does not touch the restricted secret, write boundary, or host allowlist."


def check_write(path):
    if not isinstance(path, str) or not path.strip():
        return "block", "write_file requires a path."

    for text in expand(path):
        stripped = text.strip()
        if not stripped:
            return "block", "write_file requires a path."
        canon = canonicalize(stripped, CWD)
        if canon == SECRET:
            return "block", "Writing to the restricted secret file is never permitted."
        if not is_under(canon, WRITE_ROOT):
            return "block", "Write to '%s' escapes the allowed directory %s/." % (canon, WRITE_ROOT)

    return "allow", "Write stays inside the allowed report directory %s/." % WRITE_ROOT


def check_http(url):
    if not isinstance(url, str) or not url.strip():
        return "block", "http_request requires a url."
    ok, host = host_allowed(url)
    if ok:
        return "allow", "Host '%s' is on the outbound allowlist." % host
    if host is None:
        return "block", "URL could not be parsed into an allowed hostname."
    return "block", "Host '%s' is not on the outbound allowlist (%s)." % (
        host, ", ".join(sorted(ALLOWED_HOSTS)))


def evaluate(body):
    if not isinstance(body, dict):
        return {"decision": "block", "reason": "Request body must be a JSON object."}

    tool = body.get("tool")
    if not isinstance(tool, str):
        return {"decision": "block", "reason": "Missing or non-string 'tool' field."}
    tool = tool.strip().lower()

    if tool == "bash":
        decision, reason = check_bash(body.get("command") or body.get("cmd") or "")
    elif tool in ("write_file", "write"):
        decision, reason = check_write(body.get("path") or body.get("file_path") or "")
    elif tool in ("http_request", "http"):
        decision, reason = check_http(body.get("url") or body.get("uri") or "")
    else:
        decision, reason = "block", "Unknown tool '%s' is not permitted by this agent's policy." % tool

    return {"decision": decision, "reason": reason}


@router.post("/q3/check")
async def check(body: dict):
    return evaluate(body)


@router.post("/check")
async def check_alias(body: dict):
    return evaluate(body)