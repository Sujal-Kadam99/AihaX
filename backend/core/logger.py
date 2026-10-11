import json
import logging
import re
import sys
from datetime import datetime, timezone

from backend.core.config import get_settings

REDACTED = "***REDACTED***"

_KEY = (
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"token|authorization|set-cookie|cookie|session[_-]?id)s?"
)
# Finds `password=`, `"token": `, `'cookie': ` and similar in already-formatted text.
_KEY_RE = re.compile(rf"(?i)(?P<key>{_KEY})(?P<sep>[\"']?\s*[:=]\s*)")
# For these keys an unquoted value runs to end of line: values may hold spaces or `;` separated pairs.
_LINE_VALUE_KEYS = ("password", "passwd", "secret", "authorization", "cookie", "set-cookie")
_PLAIN_VALUE = re.compile(r"[^\s,;}&]+")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_CLOSERS = {"[": "]", "{": "}"}


def _quoted_end(text: str, i: int) -> int:
    """Index just past the quoted string opening at `i`, honoring backslash escapes."""
    quote = text[i]
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == quote:
            return j + 1
        j += 1
    return len(text)


def _bracketed_end(text: str, i: int) -> int:
    """Index just past the balanced [...] / {...} block opening at `i`; end of text if unbalanced."""
    stack = [_CLOSERS[text[i]]]
    j = i + 1
    while j < len(text) and stack:
        ch = text[j]
        if ch in "\"'":
            j = _quoted_end(text, j)
            continue
        if ch in _CLOSERS:
            stack.append(_CLOSERS[ch])
        elif ch == stack[-1]:
            stack.pop()
        j += 1
    return j


def _value_end(text: str, i: int, key: str) -> int:
    if i >= len(text):
        return i
    if text[i] in _CLOSERS:
        return _bracketed_end(text, i)
    if text[i] in "\"'":
        return _quoted_end(text, i)
    if key.rstrip("s") in _LINE_VALUE_KEYS:
        newline = text.find("\n", i)
        return len(text) if newline == -1 else newline
    match = _PLAIN_VALUE.match(text, i)
    return match.end() if match else i


def redact_text(text: str) -> str:
    """Mask secrets that appear inside a formatted log message."""
    out = []
    pos = 0
    while True:
        match = _KEY_RE.search(text, pos)
        if not match:
            break
        start = match.end()
        end = _value_end(text, start, match.group("key").lower())
        if end <= start:
            out.append(text[pos:start])
            pos = start
            continue
        out.append(text[pos:start])
        out.append(REDACTED)
        pos = end
    out.append(text[pos:])
    return _BEARER.sub(f"Bearer {REDACTED}", "".join(out))


_SENSITIVE_PARTS = {
    "password", "passwd", "secret", "token", "authorization", "cookie",
    "session", "stripe", "apikey", "credential", "cred",
}


def _is_sensitive_key(key: object) -> bool:
    parts = [p for p in re.split(r"[^a-z0-9]+", str(key).lower()) if p]
    singular = [p[:-1] if p.endswith("s") else p for p in parts]
    return any(p in _SENSITIVE_PARTS for p in singular) or (bool(parts) and parts[-1] in ("key", "keys"))


def _redact_value(value):
    if isinstance(value, dict):
        return {k: REDACTED if _is_sensitive_key(k) else _redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_redact_value(v) for v in value)
    if isinstance(value, str):
        return redact_text(value)
    return value


class SensitiveDataFilter(logging.Filter):
    """Filter to prevent logging of sensitive information."""

    def _redact_dict(self, data: dict) -> dict:
        return _redact_value(data)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, dict):
                record.msg = self._redact_dict(record.msg)
            else:
                record.msg = redact_text(record.getMessage())
                record.args = ()
            if record.exc_info:
                record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
                record.exc_info = None
            elif record.exc_text:
                record.exc_text = redact_text(record.exc_text)
            if record.stack_info:
                record.stack_info = redact_text(record.stack_info)
        except Exception:
            # A logging call must never raise into the caller, and must never emit unredacted text.
            record.msg = "<log message withheld: redaction failed>"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


class JSONFormatter(logging.Formatter):
    """Formatter that outputs JSON strings for cloud logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        if record.exc_text:
            log_data["exception"] = record.exc_text
        elif record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)

_NOISY_LOGGERS = ("httpx", "httpcore", "urllib3", "asyncio", "chromadb", "watchfiles", "multipart")
_configured = False


def configure_logging() -> None:
    """Attach one redacting handler to the root logger so every module's logs reach it.

    Modules log through `logging.getLogger(__name__)`, so a handler on a single named logger
    drops their output. Safe to call more than once.
    """
    global _configured
    if _configured:
        return
    settings = get_settings()
    root = logging.getLogger()

    # Handlers installed before us (basicConfig, libraries) would otherwise print unredacted text.
    for existing in root.handlers:
        if not any(isinstance(f, SensitiveDataFilter) for f in existing.filters):
            existing.addFilter(SensitiveDataFilter())

    handler = logging.StreamHandler(sys.stdout)
    if settings.environment == "cloud":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
    handler.addFilter(SensitiveDataFilter())

    root.addHandler(handler)
    root.setLevel(logging.DEBUG if settings.debug else logging.INFO)
    for noisy in _NOISY_LOGGERS:
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True


def setup_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
