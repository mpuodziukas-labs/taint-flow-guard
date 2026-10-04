"""Scan text before it enters an agent's context. Verdict PASS, QUARANTINE or BLOCK, with reason and byte offset.

Usage: python3 scanner.py FILE...   prints one JSON verdict per file; exit 0 all PASS, 1 QUARANTINE, 2 BLOCK.
Fail closed: unreadable input, undecodable bytes, oversize input or any scanner exception is BLOCK.
"""
import base64
import binascii
import json
import re
import sys
import unicodedata
import urllib.parse

FAIL_VERDICT = "BLOCK"
MAX_BYTES = 1 << 20
MAX_FINDINGS = 50

TAG_CHARS = range(0xE0000, 0xE0080)
BIDI = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF})
EMOJI = (range(0x1F000, 0x20000), range(0x2600, 0x27C0), range(0x2190, 0x2200), range(0xFE00, 0xFE10))

OVERRIDE_PATTERNS = tuple(re.compile(p) for p in (
    r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|every|the|your|my|these)\s+)*"
    r"(?:previous|prior|above|earlier|preceding|former|system|safety)\s+"
    r"(?:instructions?|prompts?|rules?|directions?|guidelines?|context|messages?)",
    r"\bforget\s+(?:everything|all)\s+(?:above|before|previous|you\s+(?:were|have\s+been)\s+told)",
    r"\bnew\s+instructions?\s*:",
    r"\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|jailbroken|in\s+developer\s+mode)",
    r"\b(?:reveal|print|show|output|repeat|leak)\s+(?:your|the)\s+(?:system\s+prompt|hidden\s+instructions|initial\s+instructions)",
))
EXEC_PATTERNS = tuple(re.compile(p) for p in (
    r"\b(?:curl|wget)\s+https?://",
    r"\brm\s+-rf\b",
    r"\b(?:send|email|upload|post)\b.{0,40}\b(?:keys?|secrets?|passwords?|tokens?|credentials?|env)\b",
))
ROLE_PATTERNS = tuple(re.compile(p, f) for p, f in (
    (r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>", re.I),
    (r"</?(?:system|assistant|tool_result|tool_results|function_results|function_calls|tool_use)>", re.I),
    (r"\[/?(?:INST|SYS|SYSTEM)\]|<</?SYS>>", re.I),
    (r"^[ \t]*(?:SYSTEM|ASSISTANT)[ \t]*:[ \t]*\S", re.M),
))

MD_URL = re.compile(r"(!?)\[[^\]\n]*\]\(\s*<?([^)\s>]+)")
HTML_URL = re.compile(r"""<(img|a)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']""", re.I)
SLOT_RE = re.compile(r"\{\{|\$\{|%7B%7B|%24%7B", re.I)
VALUE_RE = re.compile(r"[A-Za-z0-9+/_%-]{16,}={0,2}")
B64_RUN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}")
HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
HOST_RE = re.compile(r"https?://([^/\s?#)>\"']+)", re.I)

CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK")
FOLD = {ord(a): b for a, b in zip(
    "аеорсухіѕјοαεινρτυ",
    "aeopcyxisjoaeivptu")}
SHELL_LANGS = frozenset({"sh", "bash", "shell", "zsh", "console", "terminal", "fish", "powershell", "ps1", "cmd", "bat"})
FENCE = re.compile(r"^\s*```\s*([A-Za-z0-9_+-]*)")
PROMPT = re.compile(r"^\s*[$>]\s+(?=\S)")


def _boff(text, i):
    return len(text[:i].encode("utf-8"))


def _f(text, rule, severity, i, detail):
    return {"rule": rule, "severity": severity, "offset": _boff(text, i), "detail": detail}


def _is_emoji(ch):
    o = ord(ch)
    return any(o in r for r in EMOJI)


def _hidden(ch):
    o = ord(ch)
    return o in TAG_CHARS or o in BIDI or o in ZERO_WIDTH or o == 0xAD


def _norm(text):
    """NFKC + casefold + confusable fold + invisibles dropped + whitespace collapsed; idx maps back to text."""
    out, idx, prev = [], [], False
    for i, ch in enumerate(text):
        if _hidden(ch):
            continue
        for c in unicodedata.normalize("NFKC", ch).casefold():
            c = c.translate(FOLD)
            if c.isspace():
                if prev or not out:
                    continue
                out.append(" ")
                idx.append(i)
                prev = True
            else:
                out.append(c)
                idx.append(i)
                prev = False
    return "".join(out), idx


def _runs(text, member):
    i, n = 0, len(text)
    while i < n:
        if member(text[i]):
            j = i
            while j < n and member(text[j]):
                j += 1
            yield i, j
            i = j
        else:
            i += 1


def _instruction(norm):
    return any(p.search(norm) for p in OVERRIDE_PATTERNS + EXEC_PATTERNS)


def detect_unicode(text):
    out = []
    for i, j in _runs(text, lambda c: ord(c) in TAG_CHARS):
        out.append(_f(text, "unicode-tag", "BLOCK", i, f"{j - i} tag characters (hidden text)"))
        hidden = "".join(chr(ord(c) - 0xE0000) for c in text[i:j])
        if _instruction(_norm(hidden)[0]):
            out.append(_f(text, "override", "BLOCK", i, "hidden tag characters spell an instruction"))
    for i, j in _runs(text, lambda c: ord(c) in BIDI):
        out.append(_f(text, "unicode-bidi", "BLOCK", i, f"{j - i} bidirectional control characters"))
    for i, ch in enumerate(text):
        if ord(ch) not in ZERO_WIDTH or (ord(ch) == 0xFEFF and i == 0):
            continue
        if ord(ch) == 0x200D and 0 < i < len(text) - 1 and _is_emoji(text[i - 1]) and _is_emoji(text[i + 1]):
            continue
        out.append(_f(text, "unicode-zero-width", "QUARANTINE", i, f"U+{ord(ch):04X} zero-width character"))
    return out


def detect_override(text):
    out = []
    norm, idx = _norm(text)
    for p in OVERRIDE_PATTERNS:
        for m in p.finditer(norm):
            out.append(_f(text, "override", "BLOCK", idx[m.start()], "instruction override in data"))
    for p in ROLE_PATTERNS:
        for m in p.finditer(text):
            out.append(_f(text, "role-spoof", "BLOCK", m.start(), "role or tool-result marker in data"))
    return out


def _decode(s):
    """Decode a hex or base64 run to text, or None."""
    try:
        if re.fullmatch(r"[0-9A-Fa-f]+", s) and len(s) % 2 == 0:
            raw = bytes.fromhex(s)
        else:
            t = s.rstrip("=").replace("-", "+").replace("_", "/")
            if len(t) % 4 == 1:
                return None
            raw = base64.b64decode(t + "=" * (-len(t) % 4))
        return raw.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


def _looks_like_text(t):
    ok = sum(1 for c in t if c.isprintable() or c.isspace())
    return len(t) >= 8 and ok / len(t) >= 0.95 and sum(c.isalpha() for c in t) >= 4


def _url_findings(text, url, start, is_image):
    out = []
    for m in SLOT_RE.finditer(url):
        out.append(_f(text, "exfil-slot", "BLOCK", start + m.start(), "template slot in a link or image URL"))
    q = re.search(r"[?#]", url)
    if q:
        for m in VALUE_RE.finditer(url, q.end()):
            d = _decode(m.group())
            if d is not None and _looks_like_text(d):
                out.append(_f(text, "exfil-blob", "BLOCK" if is_image else "QUARANTINE", start + m.start(),
                              "encoded text in a URL query or fragment"))
    return out


def detect_exfil(text):
    out = []
    for m in MD_URL.finditer(text):
        out += _url_findings(text, m.group(2), m.start(2), m.group(1) == "!")
    for m in HTML_URL.finditer(text):
        out += _url_findings(text, m.group(2), m.start(2), m.group(1).lower() == "img")
    return out


def _confusable(ch):
    return ord(ch) > 127 and unicodedata.name(ch, "").startswith(CONFUSABLE_SCRIPTS)


def _mixed(tok, minimum):
    return any(_confusable(c) for c in tok) and sum(c.isascii() and c.isalpha() for c in tok) >= minimum


def detect_homoglyph(text):
    out, seen = [], set()
    for m in HOST_RE.finditer(text):
        if any(ord(c) > 127 for c in m.group(1)):
            out.append(_f(text, "homoglyph-host", "BLOCK", m.start(1), "non-ASCII characters in a URL host"))
            seen.add(m.start(1))
    pos, in_fence, fence_lang = 0, False, None
    for line in text.splitlines(keepends=True):
        fm = FENCE.match(line)
        body = line.strip()
        cmd = None
        if fm:
            in_fence = not in_fence
            fence_lang = fm.group(1).lower() if in_fence else None
        elif fence_lang in SHELL_LANGS and body and not body.startswith("#"):
            cmd = 0
        elif PROMPT.match(line):
            cmd = PROMPT.match(line).end()
        if cmd is not None:
            first = True
            for t in re.finditer(r"\S+", line):
                if t.start() < cmd:
                    continue
                tok = t.group()
                if _mixed(tok, 1) or (first and any(_confusable(c) for c in tok)):
                    out.append(_f(text, "homoglyph-cmd", "BLOCK", pos + t.start(), "look-alike letters in a shell command"))
                    seen.add(pos + t.start())
                first = False
        pos += len(line)
    for t in re.finditer(r"\S+", text):
        if t.start() not in seen and _mixed(t.group(), 3):
            out.append(_f(text, "homoglyph-mixed", "QUARANTINE", t.start(), "Latin letters mixed with look-alike letters"))
    return out


def _decoded_instruction(s, depth=0):
    d = _decode(s)
    if d is None:
        return False
    if _instruction(_norm(d)[0]):
        return True
    if depth < 2:
        return any(_decoded_instruction(m.group(), depth + 1) for m in B64_RUN.finditer(d))
    return False


def detect_encoded(text):
    out = []
    for run in (B64_RUN, HEX_RUN):
        for m in run.finditer(text):
            if _decoded_instruction(m.group()):
                out.append(_f(text, "encoded-instruction", "BLOCK", m.start(), "encoded run decodes to an instruction"))
    return out


# ---- v2 canonicalization: scan a canonical copy of the text next to the raw text -------------------
# Order: strip extra invisibles, decode one level of URL / hex-escape / hex-dump text, _norm (NFKC, casefold,
# base confusable fold), extra confusable fold, join single-letter runs, drop punctuation inside words.
# Every step keeps an index map back to the raw text, so finding offsets point into the raw input.
INVISIBLE_V2 = (frozenset({0x34F, 0x61C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x200E, 0x200F,
                           0x2061, 0x2062, 0x2063, 0x2064, 0x3164, 0xFFA0})
                | frozenset(range(0xFE00, 0xFE10)) | frozenset(range(0xE0100, 0xE01F0)))
# TR39 confusables not already in FOLD: dotless i, IPA a and g, Cyrillic d h l q w v, and Cyrillic/Greek k m h t b.
CONFUSABLES_V2 = {ord(a): b for a, b in zip("\u0131\u0251\u0261\u0501\u04bb\u04cf\u051b\u051d\u0475\u043a\u043c\u043d\u0442\u0432\u03ba",
                                           "iagdhlqwvkmhtbk")}
SPACED_RUN = re.compile(r"(?<![a-z0-9])[a-z](?:[ .\-_*|/\u00b7\u2022~^,;:'+][a-z]){3,}(?![a-z0-9])")
INWORD_PUNCT = re.compile(r"(?<=[a-z])[.\-*|\u00b7\u2022~^'+]+(?=[a-z])")
TOKEN = re.compile(r"\S+")
HEX_TEXT_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}|(?:0x[0-9A-Fa-f]{2}[ ,;:]*){4,}"
                          r"|(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}[ ,:;-]){7,}[0-9A-Fa-f]{2}(?![0-9A-Za-z])")
B64_RUN_V2 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{8,}={0,2}")
# Same wording as four override patterns with the whitespace made optional, used only where a join happened.
SQUASH_PATTERNS = tuple(re.compile(OVERRIDE_PATTERNS[i].pattern.replace(r"\s+", r"\s*")) for i in (0, 1, 3, 4))


def _printable(t):
    return bool(t) and all(c.isprintable() or c.isspace() for c in t)


def _decode_percent(tok):
    """Percent-decode one whitespace-free token holding three or more %XX groups, or None."""
    if len(re.findall(r"%[0-9A-Fa-f]{2}", tok)) < 3:
        return None
    try:
        d = urllib.parse.unquote(tok, errors="strict")
    except UnicodeDecodeError:
        return None
    return d if _printable(d) else None


def _decode_hex_text(run):
    """Decode a run of \\xNN escapes, 0xNN values or spaced hex pairs to printable text, or None."""
    h = re.sub(r"\\x|0x|[\s,;:-]", "", run)
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", h):
        return None
    try:
        d = bytes.fromhex(h).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return d if _printable(d) else None


def _pre(text):
    """Drop extra invisibles, then decode one level of URL, hex-escape and hex-dump text. Returns (text, idx)."""
    s, idx = [], []
    for i, ch in enumerate(text):
        if ord(ch) not in INVISIBLE_V2:
            s.append(ch)
            idx.append(i)
    s, idx = "".join(s), idx
    for regex, decode in ((TOKEN, _decode_percent), (HEX_TEXT_RUN, _decode_hex_text)):
        o, oi, pos = [], [], 0
        for m in regex.finditer(s):
            d = decode(m.group())
            if d is None:
                continue
            o.append(s[pos:m.start()])
            oi += idx[pos:m.start()]
            o.append(d)
            oi += [idx[m.start()]] * len(d)
            pos = m.end()
        o.append(s[pos:])
        oi += idx[pos:]
        s, idx = "".join(o), oi
    return s, idx


def _delete(n, idx, touched, drop, mark):
    keep = [k for k in range(len(n)) if k not in drop]
    return ("".join(n[k] for k in keep), [idx[k] for k in keep], [touched[k] or k in mark for k in keep])


def _join_letter_runs(n, idx, touched):
    """'i g n o r e' and 'i.g.n.o.r.e' become 'ignore'; every letter of a joined run is marked touched."""
    drop, mark = set(), set()
    for m in SPACED_RUN.finditer(n):
        drop.update(range(m.start() + 1, m.end(), 2))
        mark.update(range(m.start(), m.end()))
    return _delete(n, idx, touched, drop, mark)


def _strip_inword_punct(n, idx, touched):
    """'ig-nore' and 'ignore*previous' lose the punctuation between letters; the two neighbours are marked touched."""
    drop, mark = set(), set()
    for m in INWORD_PUNCT.finditer(n):
        drop.update(range(m.start(), m.end()))
        mark.update((m.start() - 1, m.end()))
    return _delete(n, idx, touched, drop, mark)


def _canon(text):
    """Canonical text, a map from each canonical char to its index in text, and a touched flag per char."""
    s, idx0 = _pre(text)
    n, idx1 = _norm(s)
    idx = [idx0[k] for k in idx1]
    n = n.translate(CONFUSABLES_V2)
    touched = [False] * len(n)
    n, idx, touched = _join_letter_runs(n, idx, touched)
    return _strip_inword_punct(n, idx, touched)


def _instruction_canon(text):
    n, _, touched = _canon(text)
    if any(p.search(n) for p in OVERRIDE_PATTERNS + EXEC_PATTERNS):
        return True
    return any(any(touched[m.start():m.end()]) for p in SQUASH_PATTERNS for m in p.finditer(n))


def detect_canonical(text):
    out = []
    n, idx, touched = _canon(text)
    for p in OVERRIDE_PATTERNS:
        for m in p.finditer(n):
            out.append(_f(text, "override", "BLOCK", idx[m.start()], "instruction override after canonicalization"))
    for p in SQUASH_PATTERNS:
        for m in p.finditer(n):
            if any(touched[m.start():m.end()]):
                out.append(_f(text, "override", "BLOCK", idx[m.start()], "instruction override after joining split letters"))
    for p in ROLE_PATTERNS[:3]:
        for m in p.finditer(n):
            out.append(_f(text, "role-spoof", "BLOCK", idx[m.start()], "role or tool-result marker after canonicalization"))
    return out


def _decoded_instruction_v2(s, depth=0):
    d = _decode(s)
    if d is None:
        return False
    if _instruction_canon(d):
        return True
    if depth < 2:
        return any(_decoded_instruction_v2(m.group(), depth + 1) for m in B64_RUN_V2.finditer(d))
    return False


def detect_encoded_v2(text):
    return [_f(text, "encoded-instruction", "BLOCK", m.start(), "encoded run decodes to an instruction")
            for m in B64_RUN_V2.finditer(text) if _decoded_instruction_v2(m.group())]


def _fail(name, rule, detail, offset=None):
    return {"input": name, "verdict": FAIL_VERDICT, "reason": rule, "offset": offset,
            "findings": [{"rule": rule, "severity": "BLOCK", "offset": offset, "detail": detail}]}


def scan_input(data, name="<input>"):
    try:
        if not isinstance(data, (bytes, bytearray)):
            return _fail(name, "fail-closed-error", "input is not bytes")
        if len(data) > MAX_BYTES:
            return _fail(name, "fail-closed-oversize", f"input is larger than {MAX_BYTES} bytes")
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            return _fail(name, "fail-closed-undecodable", "input is not valid UTF-8", e.start)
        found = []
        for detector in (detect_unicode, detect_override, detect_exfil, detect_homoglyph, detect_encoded,
                         detect_canonical, detect_encoded_v2):
            found += detector(text)
        found = list({(f["rule"], f["offset"]): f for f in reversed(found)}.values())[::-1]
        found.sort(key=lambda f: (f["severity"] != "BLOCK", f["offset"]))
        found = found[:MAX_FINDINGS]
        if not found:
            return {"input": name, "verdict": "PASS", "reason": None, "offset": None, "findings": []}
        return {"input": name, "verdict": found[0]["severity"], "reason": found[0]["rule"],
                "offset": found[0]["offset"], "findings": found}
    except Exception as e:  # fail closed: a crash is never a pass
        return _fail(name, "fail-closed-error", f"scanner error: {type(e).__name__}")


def scan_path(path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES + 1)
    except OSError as e:
        return _fail(str(path), "fail-closed-unreadable", f"cannot read input: {type(e).__name__}")
    return scan_input(data, str(path))


def main(argv):
    if not argv:
        print("usage: scanner.py FILE...", file=sys.stderr)
        return 3
    worst = 0
    for p in argv:
        v = scan_input(sys.stdin.buffer.read(), "-") if p == "-" else scan_path(p)
        print(json.dumps(v, ensure_ascii=True))
        worst = max(worst, {"PASS": 0, "QUARANTINE": 1, "BLOCK": 2}[v["verdict"]])
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
