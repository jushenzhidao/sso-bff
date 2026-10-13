"""new-api 管理/用户客户端 —— 全部按 v1.0.0-rc.42 实证能力构建。

实证结论（2026-10-13，对 https://newapi-0to1.livetest.cn 实测 + 源码核对）：
1. 管理员会话可：登录、建用户（username/password/display_name/role，**不能写 oidc_id**）、
   搜用户、改用户资料、add_quota。
2. rc.42 的 ManageUser 对 disable/enable/delete/promote 一律要求安全验证（X-Security-Proof），
   root 未登记 2FA/passkey/email ⇒ **管理 API 无法禁用/删除用户**。
   ⇒ 封禁级联改为：以用户本人会话吊销其全部令牌（DeleteToken 无需证明），API 访问即时中断。
3. 令牌操作（AddToken/ListTokens/GetTokenKey/DeleteToken/UpdateToken）仅在**用户本人会话**可用，
   管理员无法代管他人令牌 ⇒ JIT 必须“以该用户身份登录后代发”。
4. AddToken 响应不含 key，需先列表按 name 找 id，再 POST /api/token/:id/key 取明文。
5. 该部署 key 为 48 位裸串（无 sk- 前缀），代码不得假设前缀。
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from .config import settings
from .logging_setup import get_logger
from .sessions import store

log = get_logger("newapi")


class NewApiError(RuntimeError):
    def __init__(self, message: str, status: int = 0, payload: Any = None):
        super().__init__(message)
        self.status = status
        self.payload = payload


@dataclass
class NewApiToken:
    id: int
    name: str
    status: int
    remain_quota: int
    unlimited_quota: bool
    expired_time: int


@dataclass
class NewApiUser:
    id: int
    username: str
    display_name: str
    status: int
    role: int
    quota: int
    used_quota: int


def _client() -> httpx.AsyncClient:
    # trust_env=False：沙箱/生产环境都可能误设 HTTP_PROXY，禁用环境代理（内网 + 公网双场景）
    return httpx.AsyncClient(
        base_url=settings.newapi_base_url,
        timeout=httpx.Timeout(20.0, connect=10.0),
        trust_env=False,
    )


def _check(resp: httpx.Response, action: str) -> dict:
    try:
        data = resp.json()
    except Exception:
        raise NewApiError(f"{action}: non-JSON response HTTP {resp.status_code}", resp.status_code)
    if resp.status_code >= 400 or not data.get("success", False):
        msg = data.get("message") or f"HTTP {resp.status_code}"
        raise NewApiError(f"{action}: {msg}", resp.status_code, data)
    return data


async def _with_retry(fn, attempts: int = 3):
    """传输层瞬时错误（连接超时/重置）重试；业务错误直接抛。"""
    import asyncio

    last: Exception | None = None
    for i in range(attempts):
        try:
            return await fn()
        except (httpx.ConnectTimeout, httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
            last = e
            log.warning("new-api 传输层错误（第 %d/%d 次）：%s", i + 1, attempts, e)
            await asyncio.sleep(0.5 * (i + 1))
    raise NewApiError(f"transport error after {attempts} attempts: {last}")


class NewApiClient:
    """封装 admin 与 user 两级会话。admin 令牌缓存 Redis，过期自动重登。"""

    def __init__(self) -> None:
        self._admin_token: str | None = None
        self._admin_expires_at: float = 0.0

    # ---------------- admin 会话 ----------------
    async def admin_token(self) -> str:
        if self._admin_token and time.time() < self._admin_expires_at - 60:
            return self._admin_token
        cached = await store.get_cached_admin_token()
        if cached:
            self._admin_token = cached
            # 缓存 TTL 由 Redis 管，这里保守按 15 分钟（实测 access_token 寿命 900s）
            self._admin_expires_at = time.time() + 14 * 60
            return cached
        return await self.admin_login()

    async def admin_login(self) -> str:
        async with _client() as c:
            resp = await c.post(
                "/api/user/login",
                json={
                    "username": settings.newapi_admin_username,
                    "password": settings.newapi_admin_password,
                },
            )
            data = _check(resp, "admin login")
        token = data["data"]["access_token"]
        self._admin_token = token
        self._admin_expires_at = time.time() + 14 * 60
        await store.cache_admin_token(token, 14 * 60)
        log.info("new-api admin session established")
        return token

    async def _admin_call(self, method: str, path: str, **kwargs: Any) -> dict:
        """带 401 自动重登重试一次的 admin 调用；传输层错误重试。"""

        async def _once() -> dict:
            token = await self.admin_token()
            async with _client() as c:
                resp = await c.request(
                    method, path, headers={"Authorization": f"Bearer {token}"}, **kwargs
                )
                if resp.status_code == 401:
                    token = await self.admin_login()
                    resp = await c.request(
                        method, path, headers={"Authorization": f"Bearer {token}"}, **kwargs
                    )
                return _check(resp, f"admin {method} {path}")

        return await _with_retry(_once)

    # ---------------- 用户管理（admin） ----------------
    async def create_user(self, username: str, password: str, display_name: str) -> int:
        """建用户，返回 user id。注意：rc.42 不接受 oidc_id 字段（静默丢弃）。

        重复用户名（上次建号后响应丢失的残留）⇒ 直接收养该账户。
        """
        try:
            await self._admin_call(
                "POST",
                "/api/user/",
                json={
                    "username": username,
                    "password": password,
                    "display_name": display_name,
                    "role": 1,  # 普通用户
                },
            )
        except NewApiError as e:
            if "Duplicate" not in str(e):
                raise
            log.info("create_user: %s 已存在（残留收养）", username)
        user = await self.find_user_by_username(username)
        if not user:
            raise NewApiError(f"create_user: user {username!r} not found after creation")
        log.info("new-api user ready: id=%s username=%s", user.id, username)
        return user.id

    async def find_user_by_username(self, username: str) -> NewApiUser | None:
        data = await self._admin_call(
            "GET", "/api/user/search", params={"keyword": username, "p": 1, "size": 20}
        )
        for item in data.get("data", {}).get("items", []):
            if item.get("username") == username:
                return NewApiUser(
                    id=item["id"],
                    username=item["username"],
                    display_name=item.get("display_name", ""),
                    status=item.get("status", 1),
                    role=item.get("role", 1),
                    quota=item.get("quota", 0),
                    used_quota=item.get("used_quota", 0),
                )
        return None

    async def list_all_users(self) -> list[NewApiUser]:
        """分页拉全量用户（对账用；万级用户可改流式）。"""
        users: list[NewApiUser] = []
        page = 1
        while True:
            data = await self._admin_call("GET", "/api/user/", params={"p": page, "size": 100})
            payload = data.get("data", {})
            items = payload.get("items", [])
            for item in items:
                users.append(
                    NewApiUser(
                        id=item["id"],
                        username=item["username"],
                        display_name=item.get("display_name", ""),
                        status=item.get("status", 1),
                        role=item.get("role", 1),
                        quota=item.get("quota", 0),
                        used_quota=item.get("used_quota", 0),
                    )
                )
            if len(users) >= payload.get("total", 0) or not items:
                break
            page += 1
            if page > 200:  # 安全阀
                break
        return users

    async def rename_user(self, user_id: int, username: str, display_name: str) -> None:
        await self._admin_call(
            "PUT",
            "/api/user/",
            json={"id": user_id, "username": username, "display_name": display_name},
        )

    # ---------------- 用户会话（JIT 发钥匙/轮换/封禁级联） ----------------
    async def login_as_user(self, username: str, password: str) -> str:
        async def _once() -> str:
            async with _client() as c:
                resp = await c.post(
                    "/api/user/login", json={"username": username, "password": password}
                )
                data = _check(resp, f"user login {username!r}")
            return data["data"]["access_token"]

        return await _with_retry(_once)

    async def _user_call(self, user_token: str, method: str, path: str, **kwargs: Any) -> dict:
        async def _once() -> dict:
            async with _client() as c:
                resp = await c.request(
                    method, path, headers={"Authorization": f"Bearer {user_token}"}, **kwargs
                )
                return _check(resp, f"user {method} {path}")

        return await _with_retry(_once)

    async def add_token(
        self,
        user_token: str,
        name: str,
        remain_quota: int,
        expired_time: int,
        unlimited_quota: bool,
    ) -> None:
        await self._user_call(
            user_token,
            "POST",
            "/api/token/",
            json={
                "name": name,
                "remain_quota": remain_quota,
                "expired_time": expired_time,
                "unlimited_quota": unlimited_quota,
            },
        )

    async def list_user_tokens(self, user_token: str) -> list[NewApiToken]:
        data = await self._user_call(user_token, "GET", "/api/token/", params={"p": 1, "size": 100})
        out: list[NewApiToken] = []
        for item in data.get("data", {}).get("items", []):
            out.append(
                NewApiToken(
                    id=item["id"],
                    name=item.get("name", ""),
                    status=item.get("status", 1),
                    remain_quota=item.get("remain_quota", 0),
                    unlimited_quota=item.get("unlimited_quota", False),
                    expired_time=item.get("expired_time", -1),
                )
            )
        return out

    async def get_token_key(self, user_token: str, token_id: int) -> str:
        data = await self._user_call(user_token, "POST", f"/api/token/{token_id}/key", json={})
        key = data.get("data", {}).get("key", "")
        if not key:
            raise NewApiError(f"get_token_key: empty key for token {token_id}")
        return key

    async def delete_token(self, user_token: str, token_id: int) -> None:
        await self._user_call(user_token, "DELETE", f"/api/token/{token_id}")

    # ---------------- 模型面（验证 key 可用性，免费端点） ----------------
    async def verify_key_models(self, key: str) -> int:
        """用用户 key 调 GET /v1/models（免费，不计费），返回 HTTP 状态码。"""
        async with _client() as c:
            resp = await c.get(
                "/v1/models", headers={"Authorization": f"Bearer {key}"}
            )
        return resp.status_code


newapi = NewApiClient()
