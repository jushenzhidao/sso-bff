"""控制台绑定（AC-06）：把 Casdoor sub 绑定到 JIT 开通的 new-api 账户。

背景约束（new-api v1.0.0-rc.42 实证）：
- 管理 API 不能写 oidc_id；只有 new-api 自己的 OAuth 登录/绑定流程能写。
- 绑定需“用户本人会话 + 安全证明（password 重验）”。
- 绑定回调走面板会话（Authorization 头，非 Cookie）。

本模块的方案（全部服务端 + 一次浏览器静默跳转）：
1. BFF 以该用户身份登录 new-api（JIT 时派生的口令），
2. POST /api/verify（method=password, scope=account.bind）拿 proof，
3. POST /api/oauth/state（provider=oidc, intent=bind）+ X-Security-Proof 拿 flow_token，
4. 浏览器跳 Casdoor authorize（console app，redirect_uri 指向 **BFF 自己的回调**）——
   Casdoor 换票不校验 redirect_uri（实证：仅校验 client/PKCE/过期），
   而 new-api 侧 OIDC 配置的 client_id/secret 不变，故码可被 new-api 正常兑换；
   浏览器因已登录应用持有 Casdoor SSO 会话，此跳转静默无感。
5. Casdoor 302 回 BFF /console-connect/callback?code&state，
6. BFF 以用户会话调 new-api GET /api/oauth/oidc?code&state ⇒ oidc_id 绑定完成。

此后用户从 new-api 控制台 OIDC 登录，按 oidc_id 落到同一账户（无双胞胎）。
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from .config import settings
from .crypto import decrypt
from .db import IdentityMapping, get_sessionmaker
from .jit import derive_username, get_mapping
from .logging_setup import get_logger
from .newapi import NewApiError, _client, _check
from .sessions import store

log = get_logger("console_connect")

ACCOUNT_BIND_SCOPE = "account.binding.bind"  # new-api rc.42 的 VerificationScopeAccountBind 常量真值
CONSOLE_APP_CLIENT_ID = "new-api-console-app"  # Casdoor 里控制台专用 Application


class ConsoleConnectError(RuntimeError):
    pass


@dataclass
class BindStart:
    authorize_url: str
    flow_token: str


async def _user_session_for(sub: str) -> tuple[str, str, str]:
    """以该用户身份登录 new-api，返回 (username, password, user_token)。"""
    from sqlalchemy import select

    async with get_sessionmaker()() as s:
        mapping = (
            await s.execute(select(IdentityMapping).where(IdentityMapping.casdoor_sub == sub))
        ).scalar_one_or_none()
        if mapping is None:
            raise ConsoleConnectError("identity mapping not found")
        password = decrypt(mapping.new_api_password_enc)
        username = mapping.new_api_username
    from .newapi import newapi

    token = await newapi.login_as_user(username, password)
    return username, password, token


async def start_bind(sub: str) -> BindStart:
    """发起绑定：拿 proof + flow_token，返回浏览器要跳转的 authorize URL。"""
    username, password, user_token = await _user_session_for(sub)

    # 1) 安全证明：密码重验（BFF-created 用户有密码、无 2FA ⇒ password 方式可用）
    async with _client() as c:
        resp = await c.post(
            "/api/verify",
            json={
                "method": "password",
                "scope": ACCOUNT_BIND_SCOPE,
                "context": {"provider": "oidc"},
                "password": password,
            },
            headers={"Authorization": f"Bearer {user_token}"},
        )
        data = _check(resp, "verify")
    proof = (data.get("data") or {}).get("proof_token", "")
    if not proof:
        raise ConsoleConnectError("verify: empty proof_token")

    # 2) 发起绑定流程
    async with _client() as c:
        resp = await c.post(
            "/api/oauth/state",
            json={"provider": "oidc", "intent": "bind"},
            headers={
                "Authorization": f"Bearer {user_token}",
                "X-Security-Proof": proof,
            },
        )
        data = _check(resp, "oauth state bind")
    flow_token = (data.get("data") or {}).get("flow_token", "")
    if not flow_token:
        raise ConsoleConnectError("oauth/state: empty flow_token")

    # 3) 浏览器跳转的 Casdoor authorize URL（console app + BFF 回调）
    params = {
        "client_id": CONSOLE_APP_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.base_url.rstrip("/") + "/console-connect/callback",
        "scope": "openid profile email",  # Casdoor 仅在含 email scope 时返回 email claim
        "state": flow_token,
    }
    authorize_url = settings.oidc_issuer.rstrip("/") + "/login/oauth/authorize?" + urlencode(params)
    # 关键：new-api 的 AuthFlow 绑定了发起时的会话（UserId+SessionID），
    # 回调必须用**同一个** new-api 会话 ⇒ 把用户令牌缓存到 Redis 供回调复用。
    await store.redis.setex(f"sso:console_bind:{sub}", 600, user_token)
    log.info("console bind started for sub=%s…", sub[:8])
    return BindStart(authorize_url=authorize_url, flow_token=flow_token)


async def complete_bind(sub: str, code: str, state: str) -> str:
    """BFF 回调：以**发起时同一**用户会话完成 new-api 的绑定。返回状态描述。"""
    user_token = await store.redis.get(f"sso:console_bind:{sub}")
    if user_token:
        await store.redis.delete(f"sso:console_bind:{sub}")
    else:
        # 缓存丢失（极端情况）：退化为重新登录（此时 SessionID 已变，
        # new-api 会以 state 不匹配拒绝——调用方应引导用户重新发起绑定）
        _username, _password, user_token = await _user_session_for(sub)
    async with _client() as c:
        resp = await c.get(
            "/api/oauth/oidc",
            params={"code": code, "state": state},
            headers={"Authorization": f"Bearer {user_token}"},
        )
        try:
            data = _check(resp, "oauth bind callback")
        except NewApiError as e:
            # 已绑定过（幂等重跑）按成功处理
            if "already been bound" in str(e):
                log.info("console bind: already bound for sub=%s…", sub[:8])
                return "already_bound"
            raise
    log.info("console bind complete for sub=%s…", sub[:8])
    return "bound"


async def bind_status(sub: str) -> dict:
    """核对 new-api 侧该用户的 oidc_id 是否已等于 sub（控制台将落到同一账户）。"""
    from sqlalchemy import select

    from .newapi import newapi

    async with get_sessionmaker()() as s:
        mapping = (
            await s.execute(select(IdentityMapping).where(IdentityMapping.casdoor_sub == sub))
        ).scalar_one_or_none()
        if mapping is None:
            return {"bound": False, "reason": "no_mapping"}
    try:
        user = await newapi.find_user_by_username(mapping.new_api_username)
    except NewApiError as e:
        return {"bound": False, "reason": str(e)}
    if user is None:
        return {"bound": False, "reason": "user_missing"}
    # 用户列表接口返回 oidc_id 字段；重新拉一次带全字段的详情
    async with _client() as c:
        from .newapi import newapi as _na

        token = await _na.admin_token()
        resp = await c.get(
            f"/api/user/{user.id}", headers={"Authorization": f"Bearer {token}"}
        )
        data = _check(resp, "get user")
    oidc_id = (data.get("data") or {}).get("oidc_id", "")
    return {
        "bound": oidc_id == sub,
        "oidc_id_prefix": oidc_id[:8] + "…" if oidc_id else "",
        "new_api_user_id": user.id,
        "username": user.username,
    }
