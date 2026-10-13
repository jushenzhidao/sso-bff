"""本地 mock OIDC IdP —— 替代尚未部署的 Casdoor，供 sso-bff 端到端验证。

特性（对齐标准 OIDC / Casdoor 行为）：
- 发现文档 + JWKS（RS256 真实密钥对，启动时生成）
- 授权码流程 + PKCE(S256) + state/nonce 防重放
- /token：authorization_code 与 refresh_token 两种 grant
- /userinfo：Bearer access_token
- /logout：end_session_endpoint（接受 id_token_hint / post_logout_redirect_uri）
- /admin/*：禁用/启用/列举用户（封禁级联轮询的数据源，对应 Casdoor 管理 API）
- 登录页用按钮选择模拟用户（对应微信扫码/手机验证码登录的结果态）

仅用于开发与测试，禁止上生产。
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import uvicorn
from authlib.jose import JsonWebKey, jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

MOCK_PORT = 9000
ISSUER = f"http://localhost:{MOCK_PORT}"
CLIENTS = {"sso-bff-app": "change-me", "sso-bff-mock-app": "change-me"}


@dataclass
class MockUser:
    sub: str
    name: str
    phone: str
    picture: str = ""
    disabled: bool = False


@dataclass
class AuthCode:
    sub: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    nonce: str
    expires_at: float
    consumed: bool = False


@dataclass
class State:
    users: dict[str, MockUser] = field(default_factory=dict)
    codes: dict[str, AuthCode] = field(default_factory=dict)
    access_tokens: dict[str, str] = field(default_factory=dict)  # token -> sub
    refresh_tokens: dict[str, str] = field(default_factory=dict)  # token -> sub
    rsa_key: object = None
    jwks: dict = field(default_factory=dict)
    kid: str = "mock-key-1"


state = State()


def _seed_users() -> None:
    state.users = {
        "wechat-user-alice": MockUser(
            sub="wechat-user-alice", name="爱丽丝（微信用户）", phone="13800138000",
            picture="https://api.dicebear.com/7.x/adventurer/svg?seed=alice",
        ),
        "phone-user-bob": MockUser(
            sub="phone-user-bob", name="鲍勃（手机用户）", phone="13912345678",
        ),
    }


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _init_keys() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    state.rsa_key = key
    numbers = key.public_key().public_numbers()
    state.jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": state.kid,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    _seed_users()
    _init_keys()
    yield


app = FastAPI(title="mock-idp", lifespan=lifespan)

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>mock IdP 登录</title>
<style>body{{font-family:system-ui;max-width:420px;margin:60px auto;padding:0 16px}}
button{{display:block;width:100%;margin:10px 0;padding:12px;font-size:15px;cursor:pointer;
border:1px solid #d0d7de;border-radius:8px;background:#f6f8fa}}button:hover{{background:#eef}}
.note{{color:#666;font-size:13px}}</style></head><body>
<h2>mock IdP 登录</h2>
<p class="note">模拟 Casdoor 登录态：选择用户即完成认证（对应微信扫码/手机验证码的结果）。</p>
<form method="post" action="/authorize">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="nonce" value="{nonce}">
<input type="hidden" name="code_challenge" value="{code_challenge}">
{buttons}
</form></body></html>"""


@app.get("/.well-known/openid-configuration")
async def discovery() -> dict:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "end_session_endpoint": f"{ISSUER}/logout",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "phone"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@app.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return state.jwks


@app.get("/authorize")
async def authorize_get(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query(...),
    state: str = Query(...),
    nonce: str = Query(default=""),
    code_challenge: str = Query(default=""),
    scope: str = Query(default="openid"),
):
    if response_type != "code":
        raise HTTPException(400, "only response_type=code supported")
    if client_id not in CLIENTS:
        raise HTTPException(400, "unknown client_id")
    buttons = "".join(
        f'<button type="submit" name="sub" value="{u.sub}">{u.name}</button>'
        for u in state.users.values()
    )
    return HTMLResponse(
        LOGIN_PAGE.format(
            state=state, redirect_uri=redirect_uri, client_id=client_id,
            nonce=nonce, code_challenge=code_challenge, buttons=buttons,
        )
    )


@app.post("/authorize")
async def authorize_post(
    sub: str = Form(...),
    state: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    nonce: str = Form(default=""),
    code_challenge: str = Form(default=""),
):
    user = state.users.get(sub)
    if user is None:
        raise HTTPException(404, "unknown user")
    if user.disabled:
        raise HTTPException(403, "account disabled at IdP")
    code = secrets.token_urlsafe(24)
    state.codes[code] = AuthCode(
        sub=sub, client_id=client_id, redirect_uri=redirect_uri,
        code_challenge=code_challenge, nonce=nonce,
        expires_at=time.time() + 300,
    )
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}", status_code=302)


def _issue_tokens(sub: str, nonce: str = "") -> dict:
    now = int(time.time())
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)
    state.access_tokens[access_token] = sub
    state.refresh_tokens[refresh_token] = sub
    header = {"alg": "RS256", "kid": state.kid, "typ": "JWT"}
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "aud": "sso-bff-app",
        "iat": now,
        "exp": now + 3600,
        "nonce": nonce,
    }
    id_token = jwt.encode(header, claims, state.rsa_key).decode()
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": refresh_token,
        "id_token": id_token,
        "expires_in": 3600,
        "scope": "openid profile phone",
    }


@app.post("/token")
async def token(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type")
    client_id = form.get("client_id", "")
    if client_id and client_id not in CLIENTS:
        raise HTTPException(401, "invalid client")
    if grant_type == "authorization_code":
        code = form.get("code", "")
        entry = state.codes.get(code)
        if entry is None or entry.consumed or entry.expires_at < time.time():
            raise HTTPException(400, "invalid or expired code")
        if form.get("redirect_uri") != entry.redirect_uri:
            raise HTTPException(400, "redirect_uri mismatch")
        verifier = form.get("code_verifier", "")
        if entry.code_challenge:
            expected = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            if expected != entry.code_challenge:
                raise HTTPException(400, "PKCE verification failed")
        entry.consumed = True
        return _issue_tokens(entry.sub, entry.nonce)
    if grant_type == "refresh_token":
        rt = form.get("refresh_token", "")
        sub = state.refresh_tokens.get(rt)
        if sub is None:
            raise HTTPException(400, "invalid refresh token")
        state.refresh_tokens.pop(rt, None)
        return _issue_tokens(sub)
    raise HTTPException(400, f"unsupported grant_type {grant_type}")


@app.get("/userinfo")
async def userinfo(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    sub = state.access_tokens.get(token)
    if sub is None:
        raise HTTPException(401, "invalid access token")
    user = state.users[sub]
    return {
        "sub": user.sub,
        "name": user.name,
        "phone_number": user.phone,
        "picture": user.picture,
        "preferred_username": user.sub,
    }


@app.get("/logout")
async def logout(
    id_token_hint: str = Query(default=""),
    post_logout_redirect_uri: str = Query(default=""),
):
    # mock 无浏览器会话可清；真实 Casdoor 在此注销 SSO 会话
    return RedirectResponse(post_logout_redirect_uri or "/", status_code=302)


# ---------------- 管理端（封禁级联数据源） ----------------
@app.get("/admin/users")
async def admin_users() -> dict:
    return {
        "users": [
            {"sub": u.sub, "name": u.name, "phone": u.phone, "disabled": u.disabled}
            for u in state.users.values()
        ]
    }


@app.post("/admin/disable")
async def admin_disable(sub: str = Query(...)):
    user = state.users.get(sub)
    if user is None:
        raise HTTPException(404, "unknown user")
    user.disabled = True
    return {"ok": True, "sub": sub, "disabled": True}


@app.post("/admin/enable")
async def admin_enable(sub: str = Query(...)):
    user = state.users.get(sub)
    if user is None:
        raise HTTPException(404, "unknown user")
    user.disabled = False
    return {"ok": True, "sub": sub, "disabled": False}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=MOCK_PORT, log_level="info")
