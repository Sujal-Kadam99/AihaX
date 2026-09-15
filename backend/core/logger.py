import json
import logging
import sys
from datetime import datetime

from backend.core.config import get_settings


class SensitiveDataFilter(logging.Filter):
    """Filter to prevent logging of sensitive information."""

    SENSITIVE_KEYS = {
        "password", "secret", "token", "key", "authorization",
        "cookie", "session", "stripe", "api_key"
    }

    def _redact_dict(self, data: dict) -> dict:
        redacted = {}
        for k, v in data.items():
            if any(sensitive in k.lower() for sensitive in self.SENSITIVE_KEYS):
                redacted[k] = "***REDACTED***"
            elif isinstance(v, dict):
                redacted[k] = self._redact_dict(v)
            else:
                redacted[k] = v
        return redacted

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, dict):
            record.msg = self._redact_dict(record.msg)
        return True

class JSONFormatter(logging.Formatter):
    """Formatter that outputs JSON strings for cloud logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)

def setup_logger(name: str) -> logging.Logger:
    settings = get_settings()
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)

        if settings.environment == "cloud":
            handler.setFormatter(JSONFormatter())
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)

        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO if not settings.debug else logging.DEBUG)

    return logger
