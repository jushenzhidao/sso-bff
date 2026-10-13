"""服务端会话存储（PRD F2.1：会话存 Redis，浏览器只拿 HttpOnly Cookie）。

- 会话 ID：256-bit 随机数（opaque），Cookie: HttpOnly + Secure(prod) + SameSite=Lax
- 会话内容：sub / 昵称 / 手机号掩码 / 头像 / IdP access+refresh token（Fernet 加密后存 Redis）
- 令牌只存服务端，绝不下发浏览器（PRD F2.1）
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import redis.asyncio as aioredis

from .config import settings
from .crypto import decrypt, encrypt

SESSION_PREFIX = "sso:sess:"
STATE_PREFIX = "sso:state:"  # OIDC state/nonce/PKCE
JIT_LOCK_PREFIX = "sso:jit:"  # JIT 并发锁
NEWAPI_ADMIN_TOKEN_KEY = "sso:newapi:admin_token"


@dataclass
class Session:
    sub: str
    name: str = ""
    phone_masked: str = ""
    phone_raw: str = ""  # 仅服务端使用（JIT 展示名/映射 phone 字段），永不下发
    picture: str = ""
    preferred_username: str = ""
    idp_access_token: str = ""  # 明文仅存在于本对象；落 Redis 前加密
    idp_refresh_token: str = ""
    idp_token_expires_at: float = 0.0  # unix ts
    created_at: float = field(default_factory=time.time)

    # ---------- 序列化（令牌加密后落库） ----------
    def to_redis(self) -> str:
        return json.dumps(
            {
                "sub": self.sub,
                "name": self.name,
                "phone_masked": self.phone_masked,
                "phone_raw": self.phone_raw,
                "picture": self.picture,
                "preferred_username": self.preferred_username,
                "at": encrypt(self.idp_access_token) if self.idp_access_token else "",
                "rt": encrypt(self.idp_refresh_token) if self.idp_refresh_token else "",
                "exp": self.idp_token_expires_at,
                "ca": self.created_at,
            },
            ensure_ascii=False,
        )

    @classmethod
    def from_redis(cls, raw: str) -> "Session":
        d = json.loads(raw)
        return cls(
            sub=d["sub"],
            name=d.get("name", ""),
            phone_masked=d.get("phone_masked", ""),
            phone_raw=d.get("phone_raw", ""),
            picture=d.get("picture", ""),
            preferred_username=d.get("preferred_username", ""),
            idp_access_token=decrypt(d["at"]) if d.get("at") else "",
            idp_refresh_token=decrypt(d["rt"]) if d.get("rt") else "",
            idp_token_expires_at=float(d.get("exp", 0)),
            created_at=float(d.get("ca", time.time())),
        )

    def idp_token_expired(self, skew_seconds: int = 300) -> bool:
        """临期判断（含 5 分钟安全边界，供静默续期使用）。"""
        if not self.idp_access_token:
            return True
        return time.time() + skew_seconds >= self.idp_token_expires_at


class SessionStore:
    def __init__(self, redis_url: str | None = None):
        self._redis: aioredis.Redis | None = None
        self._redis_url = redis_url or settings.redis_url

    @property
    def redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(self._redis_url, decode_responses=True)
        return self._redis

    async def ping(self) -> bool:
        try:
            return await self.redis.ping()
        except Exception:
            return False

    # ---------- 会话 ----------
    @staticmethod
    def new_session_id() -> str:
        return secrets.token_urlsafe(32)

    async def create(self, session: Session) -> str:
        sid = self.new_session_id()
        ttl = settings.session_ttl_hours * 3600
        await self.redis.setex(SESSION_PREFIX + sid, ttl, session.to_redis())
        return sid

    async def get(self, sid: str) -> Session | None:
        raw = await self.redis.get(SESSION_PREFIX + sid)
        if not raw:
            return None
        try:
            return Session.from_redis(raw)
        except Exception:
            await self.destroy(sid)
            return None

    async def save(self, sid: str, session: Session) -> None:
        """更新会话（如静默续期后写回新令牌），TTL 续期。"""
        ttl = settings.session_ttl_hours * 3600
        await self.redis.setex(SESSION_PREFIX + sid, ttl, session.to_redis())

    async def destroy(self, sid: str) -> None:
        await self.redis.delete(SESSION_PREFIX + sid)

    # ---------- OIDC state/nonce/PKCE ----------
    async def put_state(self, state: str, payload: dict[str, Any], ttl: int | None = None) -> None:
        await self.redis.setex(
            STATE_PREFIX + state,
            ttl or settings.state_ttl_seconds,
            json.dumps(payload, ensure_ascii=False),
        )

    async def pop_state(self, state: str) -> dict[str, Any] | None:
        raw = await self.redis.get(STATE_PREFIX + state)
        if not raw:
            return None
        await self.redis.delete(STATE_PREFIX + state)
        return json.loads(raw)

    # ---------- JIT 并发锁（PRD F2.2：并发请求去重） ----------
    async def acquire_jit_lock(self, sub: str, ttl: int = 30) -> bool:
        return bool(await self.redis.set(JIT_LOCK_PREFIX + sub, "1", nx=True, ex=ttl))

    async def release_jit_lock(self, sub: str) -> None:
        await self.redis.delete(JIT_LOCK_PREFIX + sub)

    # ---------- new-api admin 令牌缓存 ----------
    async def get_cached_admin_token(self) -> str | None:
        return await self.redis.get(NEWAPI_ADMIN_TOKEN_KEY)

    async def cache_admin_token(self, token: str, ttl_seconds: int) -> None:
        await self.redis.setex(NEWAPI_ADMIN_TOKEN_KEY, ttl_seconds, token)


store = SessionStore()
