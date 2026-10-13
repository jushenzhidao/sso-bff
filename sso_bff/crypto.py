"""敏感数据加解密：new-api sk- key 与 JIT 用户口令落库前必须经此层。

PRD 5.2：new_api_key_enc 为 sk- key 密文（KMS 或 Fernet）。
本实现用 Fernet（AES-128-CBC + HMAC），密钥来自 SSO_BFF_CRYPTO_KEY。
"""
from __future__ import annotations

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


class CryptoError(RuntimeError):
    pass


@lru_cache
def _fernet() -> Fernet:
    return Fernet(settings.resolve_crypto_key())


def encrypt(plaintext: str) -> str:
    """加密，返回可入库的 token 字符串。"""
    if plaintext is None:
        raise CryptoError("encrypt(None)")
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    """解密；失败抛 CryptoError（调用方按“数据损坏/密钥轮换”处理）。"""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise CryptoError("decrypt failed: invalid token") from e


def mask_key(key: str) -> str:
    """日志/响应脱敏：只留前 4 后 2。PRD F2.3：响应与日志均不落 key 明文。"""
    if not key or len(key) <= 8:
        return "***"
    return key[:4] + "*" * (len(key) - 6) + key[-2:]
