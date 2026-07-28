"""TDS GA5 Q3 - Agent Harness: pre-tool-call guardrail hook.

Deterministic policy engine. No LLM, no network calls, stdlib + FastAPI only.

The grader POSTs one proposed tool call at a time:

    {"tool": "bash",        "command": "cat ~/.netrc"}
    {"tool": "write_file",  "path": "/srv/reports/out.md", "content": "..."}
    {"tool": "http_request","method": "GET", "url": "https://pypi.org/simple/"}

and expects exactly:

    {"decision": "allow" | "block", "reason": "<short human sentence>"}

Policy enforced (all three come from YOUR personalised question text - see
CONFIG below):
  * the one restricted secret file must never be read, in ANY obfuscated form
  * writes are only allowed inside the write root (and its subdirectories)
  * outbound HTTP only to the exact allowed hostnames (no subdomains)
  * everything else the agent does in its own workspace stays allowed
    (over-blocking loses marks just like under-blocking)
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
# CONFIG - EDIT THESE FOUR LINES (or set the same names as env vars).
# Copy the values straight out of your own Q3 question text; every student
# gets a different combination, so the defaults below are only placeholders.
# ===========================================================================
SECRET = os.environ.get("Q3_SECRET", "/home/agent/.secrets")            # e.g. /home/agent/.secrets
WRITE_ROOT = os.environ.get("Q3_WRITE_ROOT", "/srv/reports").rstrip("/")  # e.g. /srv/reports
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("Q3_ALLOWED_HOSTS", "registry.npmjs.org,api.github.com").split(",")
    if h.strip()
}
HOME = os.environ.get("Q3_HOME", "/home/agent")
CWD = os.environ.get("Q3_CWD", HOME + "/workspace")
# ===========================================================================

router = APIRouter()

SECRET_NAME = posixpath.basename(SECRET).lower()   # ".netrc"
SECRET_REVERSED = SECRET_NAME[::-1]                # "crten." - catches `| rev`

# Classics that stay blocked even though they are not the one restricted
# secret. Kept deliberately short: over-blocking loses marks.
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

# Splits a command line into simple commands the same way a shell would
# sequence them, so each can be checked for a write destination on its own.
CMD_SPLIT = re.compile(r"[;&|\n]+")
# Copy-style commands whose LAST positional arg is the write destination
# (sources before it are only reads and stay allowed).
DEST_LAST_CMDS = re.compile(r"^(?:sudo\s+)?(cp|mv|install|rsync|ln)\b\s+(.*)$", re.I)
# Commands where EVERY positional arg is a path being created / written.
DEST_ALL_CMDS = re.compile(r"^(?:sudo\s+)?(touch|mkdir|truncate|mkfifo|mknod)\b\s+(.*)$", re.I)
DD_CMD = re.compile(r"^(?:sudo\s+)?dd\b(.*)$", re.I)
SED_INPLACE = re.compile(r"^(?:sudo\s+)?sed\b(.*)$", re.I)
# Redirect operators (>, >>, >|) and tee - capture the file that follows.
REDIRECT = re.compile(r"(?:>>?\|?|\btee\b(?:\s+-a)?)\s*([^\s;|&'\"]+)")

# A permissive "looks like a filesystem path / var expansion" token.
PATH_TOKEN = re.compile(r"[~$A-Za-z0-9_.{}/*?\-]{2,}")
URL_TOKEN = re.compile(
    r"(?:[a-zA-Z][a-zA-Z0-9+.\-]*://|//)?[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?:[:/][^\s'\"|;&)]*)?"
)
B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_BLOB = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")


# --------------------------------------------------------------------------
# de-obfuscation
# --------------------------------------------------------------------------

def _decode_escapes(text):
    r"""Turn \x2f, \057, / into the characters they stand for."""

    def hex_sub(m):
        return chr(int(m.group(1), 16))

    def oct_sub(m):
        return chr(int(m.group(1), 8))

    out = re.sub(r"\\x([0-9a-fA-F]{2})", hex_sub, text)
    out = re.sub(r"\\u([0-9a-fA-F]{4})", hex_sub, out)
    out = re.sub(r"\\([0-7]{3})", oct_sub, out)
    return out


def _strip_quoting(text):
    r"""Collapse quote-splitting and backslash-escape obfuscation.

    `cat /home/agent/.n""etrc`, `/home/agent/.ne'tr'c` and `c\at` all
    normalise back to their plain form.
    """
    out = re.sub(r"\\(.)", r"\1", text)  # c\at -> cat, \$HOME -> $HOME
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
    """Yield plausible plaintext hidden inside base64 / hex blobs."""
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
    """All textual views of a command the policy should be checked against.

    Handles nested `echo <b64> | base64 -d | sh` chains up to `depth` levels.
    """
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


# --------------------------------------------------------------------------
# path canonicalisation (pure string work - the real FS is never consulted)
# --------------------------------------------------------------------------

def canonicalize(token, base=None):
    """Resolve $HOME / ~ / .. / . / // against `base` without touching disk."""
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
    """True directory-boundary containment (/srv/reportsomething must fail)."""
    return path == root or path.startswith(root + "/")


def _bash_write_targets(text):
    """Every path a bash command line would WRITE to (create/modify/truncate).

    Covers redirects (>, >>, >|, tee), copy-style commands (cp/mv/install/
    rsync/ln -> last arg), file-creators (touch/mkdir/truncate/mkfifo/mknod ->
    all args), dd (of=), and sed -i (its file arg). Sources/reads are never
    returned, so `cp notes.txt <write_root>/x` still lets the read of the
    source through - only the destination is judged against the write root.
    """
    targets = []

    # Redirects apply to the whole line regardless of the leading command.
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
            # In-place edit: the last non-option token is the file rewritten.
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
    """Extra cwd candidates implied by a `cd ...` in the same command line."""
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
    # Glob expansion aimed at the home dotfiles, e.g. /home/agent/.* - only for
    # tokens that were already rooted, so a plain `ls *` stays allowed.
    if token.startswith(("/", "~", "$")) and ("*" in canon or "?" in canon):
        if fnmatchcase(SECRET, canon):
            return True
    return False


# --------------------------------------------------------------------------
# hostname policy
# --------------------------------------------------------------------------

def host_of(url):
    """Extract the effective hostname, or None if the URL is unparseable."""
    raw = (url or "").strip()
    if not raw:
        return None
    if "\\" in raw:
        return None  # backslash-in-URL: parsers disagree, treat as malformed
    if "://" not in raw:
        raw = "//" + raw.lstrip("/")
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    host = parts.hostname
    if not host:
        return None
    host = host.strip().lower().rstrip(".")  # trailing dot is the same host
    if not host or not re.fullmatch(r"[a-z0-9.\-]+", host):
        return None
    return host


def host_allowed(url):
    """(ok, host_or_none) - exact-match allowlist, no subdomains, no suffixes."""
    raw = (url or "").strip()
    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return False, scheme + "://"
    host = host_of(raw)
    if host is None:
        return False, None
    return host in ALLOWED_HOSTS, host


# --------------------------------------------------------------------------
# per-tool policy
# --------------------------------------------------------------------------

SECRET_MSG = "Reading the restricted secret file %s is never permitted." % SECRET


def check_bash(command):
    if not isinstance(command, str) or not command.strip():
        return "block", "Empty or non-string bash command cannot be evaluated."

    for text in expand(command):
        low = text.lower()
        # Substring backstop: any surviving mention of the secret's name,
        # forwards or reversed (`echo crten. | rev`), is an attempt on it.
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

        # Every write destination on the line - redirects, tee, cp/mv/ln,
        # touch/mkdir/truncate, dd, sed -i - must land inside the allowed
        # write root. A bash write is not a loophole around write_file.
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
                    continue  # bare word like "foo.py", not a URL
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
        # Resolve every form to an absolute path and judge only by where it
        # LANDS. A relative path (or a `..` chain) that lands back inside the
        # write root is legal; one that lands anywhere else is not.
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
    """The whole question in one pure function - easy to unit test offline."""
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


# Served so the URL you submit can end in /q3/check, /check, /guardrail, or /.
@router.post("/q3/check")
async def check(body: dict):
    return evaluate(body)


@router.post("/check")
async def check_alias(body: dict):
    return evaluate(body)


@router.post("/guardrail")
async def check_guardrail_alias(body: dict):
    return evaluate(body)


@router.post("/")
async def check_root_alias(body: dict):
    return evaluate(body)

