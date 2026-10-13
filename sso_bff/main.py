"""sso-bff 主应用（PRD 第五章接口契约）。

端点（PRD 5.1）：
  GET  /auth/login            发起登录，跳转 Casdoor 授权页
  GET  /auth/callback         授权码回调：换票、验签、建会话、JIT 开通
  POST /auth/logout           清会话并联动 Casdoor 注销 SSO
  GET  /api/me                返回当前用户资料（昵称/手机号掩码/头像）
  GET  /api/credential        返回本人 key 与过期时间（仅本人；响应与日志不落明文）
  POST /api/credential/rotate 作废旧 key 并签发新 key
  GET  /healthz /readyz       存活 / 就绪（依赖检查）
"""
from __future__ import annotations

import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from . import __version__, console_connect as console_connect_mod
from .config import settings
from .console_connect import ConsoleConnectError
from .crypto import mask_key
from .db import close_db, init_db
from .jit import (
    JITError,
    get_active_key,
    get_or_provision,
    rotate,
    touch_last_login,
)
from .logging_setup import get_logger, setup_logging
from .newapi import NewApiError
from .oidc import OIDCUserInfo, mask_phone, oidc
from .redirects import safe_redirect
from .sessions import Session, store
from .tasks import background

log = get_logger("main")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
COOKIE_MAX_AGE = settings.session_ttl_hours * 3600


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging("DEBUG" if not settings.is_prod else "INFO")
    await init_db()
    if not await store.ping():
        log.error("Redis 不可达（%s）——会话/JIT 锁/令牌缓存依赖它", settings.redis_url)
    background.start()
    log.info(
        "sso-bff started env=%s base_url=%s newapi=%s idp=%s",
        settings.env, settings.base_url, settings.newapi_base_url, settings.oidc_issuer,
    )
    yield
    await background.stop()
    await close_db()


app = FastAPI(title="sso-bff", version=__version__, lifespan=lifespan)

if settings.demo_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.demo_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ---------------- 会话依赖（含静默续期，PRD F2.6） ----------------
async def current_session(request: Request) -> Session | None:
    sid = request.cookies.get(settings.session_cookie)
    if not sid:
        return None
    session = await store.get(sid)
    if session is None:
        return None
    # 静默续期：access token 临期且持有 refresh token ⇒ 服务端换新，前端无感知
    if session.idp_token_expired() and session.idp_refresh_token:
        try:
            tokens = await oidc.refresh(session.idp_refresh_token)
            session.idp_access_token = tokens.access_token
            session.idp_refresh_token = tokens.refresh_token or session.idp_refresh_token
            session.idp_token_expires_at = tokens.expires_at
            await store.save(sid, session)
            log.info("idp token silently renewed for sub=%s…", session.sub[:8])
        except Exception as e:  # noqa: BLE001 - 换新失败不阻塞请求，由调用方按未登录处理
            log.warning("silent renewal failed for sub=%s…: %s", session.sub[:8], e)
    request.state.session_id = sid
    return session


async def require_session(request: Request) -> Session:
    session = await current_session(request)
    if session is None:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return session


def _set_session_cookie(resp: Response, sid: str) -> None:
    resp.set_cookie(
        settings.session_cookie,
        sid,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=settings.is_prod,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(resp: Response) -> None:
    resp.delete_cookie(settings.session_cookie, path="/")


def _session_profile(session: Session) -> OIDCUserInfo:
    return OIDCUserInfo(
        sub=session.sub,
        name=session.name,
        phone=session.phone_raw,
        picture=session.picture,
        preferred_username=session.preferred_username,
    )


# ---------------- 健康检查 ----------------
@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> JSONResponse:
    redis_ok = await store.ping()
    db_ok = True
    try:
        from sqlalchemy import text

        from .db import get_sessionmaker

        async with get_sessionmaker()() as s:
            await s.execute(text("SELECT 1"))
    except Exception as e:  # noqa: BLE001
        db_ok = False
        log.warning("readyz db check failed: %s", e)
    ok = redis_ok and db_ok
    return JSONResponse(
        {"status": "ready" if ok else "degraded", "redis": redis_ok, "db": db_ok},
        status_code=200 if ok else 503,
    )


# ---------------- F2.1 登录发起与回调 ----------------
@app.get("/auth/login")
async def auth_login(redirect: str = Query(default="/", description="登录完成后回跳地址")):
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier, _challenge = oidc.new_pkce()
    # 防开放重定向：只接受站内路径或白名单内的绝对 URL（见 redirects.safe_redirect）。
    # 不校验的话 /auth/login?redirect=https://evil.com 能把刚登录成功的用户弹到任意站点。
    safe = safe_redirect(redirect, settings.redirect_origins)
    await store.put_state(state, {"nonce": nonce, "verifier": verifier, "redirect": safe})
    url = await oidc.build_authorize_url(state=state, nonce=nonce, code_verifier=verifier)
    return RedirectResponse(url, status_code=302)


@app.get("/auth/callback")
async def auth_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    error: str = Query(default=""),
):
    if error:
        return HTMLResponse(f"<h3>登录失败：{error}</h3>", status_code=400)
    payload = await store.pop_state(state)
    if payload is None:
        return HTMLResponse("<h3>state 无效或已过期（防重放）</h3>", status_code=400)

    try:
        tokens = await oidc.exchange_code(code, payload["verifier"])
        claims = await oidc.validate_id_token(tokens.id_token, payload["nonce"])
        profile = await oidc.userinfo(tokens.access_token)
    except Exception as e:  # noqa: BLE001
        log.error("callback token exchange failed: %s", e)
        return HTMLResponse("<h3>登录失败：令牌校验未通过</h3>", status_code=400)

    if not profile.sub:
        profile = OIDCUserInfo(sub=str(claims.get("sub", "")), name=claims.get("name", ""))

    session = Session(
        sub=profile.sub,
        name=profile.name,
        phone_masked=mask_phone(profile.phone),
        phone_raw=profile.phone,
        picture=profile.picture,
        preferred_username=profile.preferred_username,
        idp_access_token=tokens.access_token,
        idp_refresh_token=tokens.refresh_token,
        idp_token_expires_at=tokens.expires_at,
    )
    sid = await store.create(session)

    # JIT 开通（PRD F2.2）：失败不阻塞登录，应用侧凭 error 参数走自愈重试
    jit_error = ""
    try:
        await get_or_provision(session.sub, profile)
        await touch_last_login(session.sub)
    except (JITError, NewApiError) as e:
        jit_error = "jit_failed"
        log.error("JIT at callback failed for sub=%s…: %s", session.sub[:8], e)

    # 纵深防御：state 可能由旧版本写入，或将来有别的入口写它，这里再收敛一次。
    redirect_to = safe_redirect(payload.get("redirect"), settings.redirect_origins)
    sep = "&" if "?" in redirect_to else "?"
    if jit_error:
        redirect_to += f"{sep}error={jit_error}"
    resp = RedirectResponse(redirect_to, status_code=302)
    _set_session_cookie(resp, sid)
    return resp


@app.post("/auth/logout")
async def auth_logout(request: Request, session: Session | None = Depends(current_session)):
    sid = getattr(request.state, "session_id", None)
    if sid:
        await store.destroy(sid)
    logout_url = ""
    if session and session.idp_access_token:
        logout_url = await oidc.end_session_url(
            post_logout_redirect_uri=settings.base_url.rstrip("/") + "/logged-out",
            id_token_hint=session.idp_access_token,
        )
    resp = RedirectResponse(logout_url or "/logged-out", status_code=303)
    _clear_session_cookie(resp)
    return resp


@app.get("/logged-out", response_class=HTMLResponse)
async def logged_out() -> str:
    return "<h3>已登出</h3><p>所有应用与控制台将在下次访问时回落未登录态。</p>"


# ---------------- F2.4 当前用户 ----------------
@app.get("/api/me")
async def api_me(session: Session = Depends(require_session)):
    return {
        "sub": session.sub,
        "name": session.name,
        "phone_masked": session.phone_masked,
        "picture": session.picture,
    }


# ---------------- F2.3 取钥匙与轮换 ----------------
@app.get("/api/credential")
async def api_credential(session: Session = Depends(require_session)):
    """返回本人 key 与过期时间。仅可取本人 key；日志不落明文（脱敏过滤器兜底）。"""
    try:
        mapping, key = await get_active_key(session.sub)
    except JITError:
        # 自愈：回调时 JIT 失败过的账户，在此按 sub 幂等补登
        try:
            await get_or_provision(session.sub, _session_profile(session))
            mapping, key = await get_active_key(session.sub)
            log.info("lazy JIT recovery succeeded for sub=%s…", session.sub[:8])
        except (JITError, NewApiError) as e:
            return JSONResponse({"detail": f"credential not ready: {e}"}, status_code=409)
    return {
        "key": key,
        "key_masked": mask_key(key),
        "expired_time": settings.newapi_default_expired_time,
        "new_api_user_id": mapping.new_api_user_id,
        "token_id": mapping.new_api_token_id,
    }


@app.post("/api/credential/rotate")
async def api_credential_rotate(session: Session = Depends(require_session)):
    try:
        new_key = await rotate(session.sub)
    except (JITError, NewApiError) as e:
        return JSONResponse({"detail": str(e)}, status_code=409)
    return {"key": new_key, "key_masked": mask_key(new_key)}


# ---------------- 演示前端（F3，同源托管保证会话 Cookie 生效） ----------------
_DEMO_DIR = _PROJECT_ROOT / "demo"
if _DEMO_DIR.is_dir():
    app.mount("/demo", StaticFiles(directory=str(_DEMO_DIR), html=True), name="demo")


# ---------------- 控制台绑定（AC-06：单账户闭环） ----------------
CONSOLE_CONNECT_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>连接 new-api 控制台</title>
<style>body{font-family:system-ui;max-width:560px;margin:60px auto;padding:0 16px;color:#1f2328}
.card{border:1px solid #d0d7de;border-radius:10px;padding:20px;margin:14px 0}
button{padding:9px 16px;border-radius:6px;border:1px solid #d0d7de;background:#f6f8fa;cursor:pointer;font-size:14px}
button.primary{background:#0969da;color:#fff;border-color:#0969da}
.mut{color:#59636e;font-size:13px}.ok{color:#1a7f37}.err{color:#cf222e}</style></head><body>
<h2>连接 new-api 控制台</h2>
<p class="mut">把当前登录身份绑定到 JIT 开通的 new-api 账户。绑定后，从 new-api 控制台登录将落到同一账户，
用量、余额、日志与 API 调用完全一致（无双胞胎账户）。此跳转经 Casdoor SSO 静默完成，无需再次登录。</p>
<div class="card" id="c1">
  <button class="primary" onclick="startBind()">开始绑定</button>
  <span class="mut" id="st"></span>
</div>
<div class="card" id="c2" hidden>
  <span id="done" class="ok"></span>
  <p><a href="https://newapi-0to1.livetest.cn/console" target="_blank" rel="noopener">进入 new-api 控制台</a></p>
</div>
<script>
const params = new URLSearchParams(location.search);
if (params.get('done') === '1') {
  document.getElementById('c1').hidden = true;
  document.getElementById('c2').hidden = false;
  document.getElementById('done').textContent = '✓ 绑定完成。控制台登录将落到本账户。';
} else if (params.get('error')) {
  document.getElementById('st').textContent = '绑定失败：' + params.get('error');
  document.getElementById('st').className = 'err';
}
async function startBind() {
  const st = document.getElementById('st');
  st.textContent = '正在发起…'; st.className = 'mut';
  try {
    const resp = await fetch('/api/console-connect/start', { method: 'POST', credentials: 'include' });
    const d = await resp.json();
    if (!resp.ok) { st.textContent = '失败：' + (d.detail || resp.status); st.className = 'err'; return; }
    location.href = d.authorize_url;   // Casdoor 静默授权后回到 /console-connect/callback
  } catch (e) { st.textContent = '网络错误：' + e.message; st.className = 'err'; }
}
</script></body></html>"""


@app.get("/console-connect", response_class=HTMLResponse)
async def console_connect_page(session: Session | None = Depends(current_session)):
    if session is None:
        return RedirectResponse("/auth/login?redirect=/console-connect", status_code=302)
    return CONSOLE_CONNECT_PAGE


@app.post("/api/console-connect/start")
async def console_connect_start(session: Session = Depends(require_session)):
    try:
        start = await console_connect_mod.start_bind(session.sub)
    except (ConsoleConnectError, NewApiError) as e:
        return JSONResponse({"detail": str(e)}, status_code=409)
    return {"authorize_url": start.authorize_url}


@app.get("/console-connect/callback")
async def console_connect_callback(
    code: str = Query(...),
    state: str = Query(...),
    session: Session = Depends(require_session),
):
    try:
        result = await console_connect_mod.complete_bind(session.sub, code, state)
    except (ConsoleConnectError, NewApiError) as e:
        return RedirectResponse(f"/console-connect?error={e}", status_code=302)
    return RedirectResponse("/console-connect?done=1", status_code=302)


@app.get("/api/console-connect/status")
async def console_connect_status(session: Session = Depends(require_session)):
    try:
        return await console_connect_mod.bind_status(session.sub)
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"bound": False, "reason": str(e)}, status_code=500)


# ---------------- 调试辅助（dev only） ----------------
@app.get("/api/debug/session")
async def debug_session(session: Session | None = Depends(current_session)):
    if settings.is_prod:
        return JSONResponse({"detail": "not found"}, status_code=404)
    if session is None:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "sub": session.sub[:8] + "…",
        "name": session.name,
        "idp_token_expires_in": int(session.idp_token_expires_at - time.time()),
    }
