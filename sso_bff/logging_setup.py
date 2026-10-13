"""日志配置：全局脱敏过滤器——任何匹配 key/令牌形态的串一律打码。

PRD F2.3：响应与日志均不落 key 明文；AC-09：浏览器抓包不含平台级凭据。
"""
from __future__ import annotations

import logging
import re
import sys

_SECRET_PATTERNS = [
    # new-api key（48 位裸串或 sk- 前缀形态）
    re.compile(r"\b(sk-)?[A-Za-z0-9]{40,64}\b"),
    # JWT
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    # Fernet token
    re.compile(r"\bgAAAAA[A-Za-z0-9_\-=]+\b"),
]

_REDACTED = "«redacted»"


def _mask_message(msg: str) -> str:
    for pat in _SECRET_PATTERNS:
        msg = pat.sub(_REDACTED, msg)
    return msg


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _mask_message(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: _mask_message(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    _mask_message(a) if isinstance(a, str) else a for a in record.args
                )
        return True


_configured = False


def setup_logging(level: str = "INFO") -> None:
    global _configured
    if _configured:
        return
    # httpx 的 INFO 日志与脱敏过滤器格式不兼容且噪音大，直接压到 WARNING
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    _configured = True


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)
