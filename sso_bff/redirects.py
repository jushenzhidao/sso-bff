"""登录后回跳目标的安全校验（防开放重定向）。

规则：
  - 站内相对路径（以**单个** `/` 开头，且不是 `//host` 这种协议相对 URL）⇒ 放行
  - 绝对 URL ⇒ 仅当 origin 在白名单内才放行
  - 其余（空 / javascript: / 陌生域名 / 协议相对）一律回落 `/`

为什么需要：`/auth/login?redirect=` 的值会随 OIDC state 存到服务端，回调时直接
`RedirectResponse(redirect_to)`。不校验的话 `/auth/login?redirect=https://evil.com`
能把**刚登录成功**的用户弹到任意站点 —— 现成的钓鱼跳板（且链接挂在可信域名下）。
"""
from __future__ import annotations

from urllib.parse import urlparse

FALLBACK = "/"


def safe_redirect(target: str | None, allowed_origins: list[str]) -> str:
    """把用户提供的回跳目标收敛到「站内路径」或「白名单内的绝对 URL」。"""
    if not target:
        return FALLBACK
    t = target.strip()
    if not t:
        return FALLBACK

    # 站内相对路径。必须排掉 "//host"：浏览器会把协议相对 URL 当成外部站点。
    if t.startswith("/") and not t.startswith("//"):
        return t

    parsed = urlparse(t)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        origin = f"{parsed.scheme}://{parsed.netloc}"
        allow = {o.strip().rstrip("/") for o in allowed_origins if o.strip()}
        if origin in allow:
            return t

    return FALLBACK
