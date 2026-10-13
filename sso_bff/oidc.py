"""OIDC 客户端（授权码 + PKCE，兼容 Casdoor 与任意标准 IdP）。

- 发现：/.well-known/openid-configuration（失败时回退标准端点拼装）
- id_token：JWKS 验签 + iss/aud/exp/nonce 校验（authlib.jose）
- userinfo：Bearer access_token
- 静默续期：refresh_token 换新（PRD F2.6）
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

import httpx
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError

from .config import settings
from .logging_setup import get_logger

log = get_logger("oidc")


class OIDCError(RuntimeError):
    pass


@dataclass
class OIDCDiscovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    end_session_endpoint: str = ""
    jwks_uri: str = ""

    @classmethod
    def fallback(cls, issuer: str) -> "OIDCDiscovery":
        base = issuer.rstrip("/")
        return cls(
            issuer=issuer,
            authorization_endpoint=f"{base}/authorize",
            token_endpoint=f"{base}/token",
            userinfo_endpoint=f"{base}/userinfo",
            end_session_endpoint=f"{base}/logout",
            jwks_uri=f"{base}/.well-known/jwks.json",
        )


@dataclass
class OIDCUserInfo:
    sub: str
    name: str = ""
    phone: str = ""
    picture: str = ""
    preferred_username: str = ""


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str
    id_token: str
    expires_at: float


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class OIDCClient:
    def __init__(self) -> None:
        self._discovery: OIDCDiscovery | None = None
        self._jwks: Any = None
        self._jwks_fetched_at: float = 0.0

    # ---------------- 发现与 JWKS ----------------
    async def discovery(self, refresh: bool = False) -> OIDCDiscovery:
        if self._discovery and not refresh:
            return self._discovery
        url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=10) as c:
                resp = await c.get(url)
                if resp.status_code == 200:
                    d = resp.json()
                    self._discovery = OIDCDiscovery(
                        issuer=d.get("issuer", settings.oidc_issuer),
                        authorization_endpoint=d["authorization_endpoint"],
                        token_endpoint=d["token_endpoint"],
                        userinfo_endpoint=d.get("userinfo_endpoint", ""),
                        end_session_endpoint=d.get("end_session_endpoint", ""),
                        jwks_uri=d.get("jwks_uri", ""),
                    )
                    return self._discovery
        except Exception as e:  # noqa: BLE001 - 发现失败回退标准端点
            log.warning("OIDC discovery failed (%s), fallback to standard endpoints", e)
        self._discovery = OIDCDiscovery.fallback(settings.oidc_issuer)
        return self._discovery

    async def _get_jwks(self) -> Any:
        if self._jwks and time.time() - self._jwks_fetched_at < 3600:
            return self._jwks
        disc = await self.discovery()
        jwks_uri = disc.jwks_uri or settings.oidc_issuer.rstrip("/") + "/.well-known/jwks.json"
        async with httpx.AsyncClient(trust_env=False, timeout=10) as c:
            resp = await c.get(jwks_uri)
            resp.raise_for_status()
            self._jwks = resp.json()
            self._jwks_fetched_at = time.time()
        return self._jwks

    # ---------------- 授权 URL ----------------
    async def build_authorize_url(self, state: str, nonce: str, code_verifier: str) -> str:
        disc = await self.discovery()
        params = {
            "client_id": settings.oidc_client_id,
            "response_type": "code",
            "scope": settings.oidc_scope,
            "redirect_uri": settings.redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": _s256_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
        from urllib.parse import urlencode

        return disc.authorization_endpoint + "?" + urlencode(params)

    @staticmethod
    def new_pkce() -> tuple[str, str]:
        verifier = secrets.token_urlsafe(48)
        return verifier, _s256_challenge(verifier)

    # ---------------- 换票 / 刷新 ----------------
    async def exchange_code(self, code: str, code_verifier: str) -> TokenSet:
        disc = await self.discovery()
        async with httpx.AsyncClient(trust_env=False, timeout=15) as c:
            resp = await c.post(
                disc.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.redirect_uri,
                    "client_id": settings.oidc_client_id,
                    "client_secret": settings.oidc_client_secret,
                    "code_verifier": code_verifier,
                },
                headers={"Accept": "application/json"},
            )
        return self._parse_token_response(resp)

    async def refresh(self, refresh_token: str) -> TokenSet:
        disc = await self.discovery()
        async with httpx.AsyncClient(trust_env=False, timeout=15) as c:
            resp = await c.post(
                disc.token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": settings.oidc_client_id,
                    "client_secret": settings.oidc_client_secret,
                },
                headers={"Accept": "application/json"},
            )
        return self._parse_token_response(resp)

    def _parse_token_response(self, resp: httpx.Response) -> TokenSet:
        if resp.status_code != 200:
            raise OIDCError(f"token endpoint HTTP {resp.status_code}: {resp.text[:200]}")
        d = resp.json()
        if "error" in d:
            raise OIDCError(f"token endpoint error: {d['error']} {d.get('error_description', '')}")
        expires_in = int(d.get("expires_in", 3600))
        return TokenSet(
            access_token=d.get("access_token", ""),
            refresh_token=d.get("refresh_token", ""),
            id_token=d.get("id_token", ""),
            expires_at=time.time() + expires_in,
        )

    # ---------------- 令牌校验与用户信息 ----------------
    async def validate_id_token(self, id_token: str, nonce: str) -> dict:
        """JWKS 验签 + iss/aud/exp/nonce。返回 claims。"""
        try:
            jwks = await self._get_jwks()
            jwt = JsonWebToken(["HS256", "RS256", "ES256", "PS256"])
            claims = jwt.decode(id_token, jwks)
            claims.validate(leeway=60)
        except JoseError as e:
            raise OIDCError(f"id_token validation failed: {e}") from e
        if claims.get("iss") not in (settings.oidc_issuer, settings.oidc_issuer.rstrip("/")):
            raise OIDCError(f"id_token issuer mismatch: {claims.get('iss')}")
        aud = claims.get("aud")
        aud_list = aud if isinstance(aud, list) else [aud]
        if settings.oidc_client_id not in aud_list:
            raise OIDCError("id_token audience mismatch")
        if nonce and claims.get("nonce") != nonce:
            raise OIDCError("id_token nonce mismatch")
        return dict(claims)

    async def userinfo(self, access_token: str) -> OIDCUserInfo:
        disc = await self.discovery()
        async with httpx.AsyncClient(trust_env=False, timeout=15) as c:
            resp = await c.get(
                disc.userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}
            )
        if resp.status_code != 200:
            raise OIDCError(f"userinfo HTTP {resp.status_code}")
        d = resp.json()
        return OIDCUserInfo(
            sub=str(d.get("sub", "")),
            name=d.get("name", "") or d.get("preferred_username", ""),
            phone=d.get("phone_number", "") or d.get("phone", ""),
            picture=d.get("picture", ""),
            preferred_username=d.get("preferred_username", ""),
        )

    # ---------------- 登出 ----------------
    async def end_session_url(self, post_logout_redirect_uri: str, id_token_hint: str = "") -> str:
        disc = await self.discovery()
        if not disc.end_session_endpoint:
            return ""
        from urllib.parse import urlencode

        params: dict[str, str] = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        return disc.end_session_endpoint + "?" + urlencode(params)


def mask_phone(phone: str) -> str:
    """手机号掩码（PRD F2.4：返回用户基本资料含手机号掩码）。"""
    if not phone or len(phone) < 7:
        return phone
    return phone[:3] + "****" + phone[-4:]


oidc = OIDCClient()
