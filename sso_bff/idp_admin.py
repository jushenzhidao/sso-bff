"""IdP 管理接口抽象——封禁级联轮询“哪些用户在 IdP 侧被禁用”。

- casdoor：Casdoor 管理 API（GET /api/get-users，Bearer admin token）
- mock：本地 mock IdP 的 /admin/users（端到端测试用）
"""
from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from .config import settings
from .logging_setup import get_logger

log = get_logger("idp_admin")


class IdPAdmin(ABC):
    @abstractmethod
    async def list_disabled_subs(self) -> set[str]:
        """返回 IdP 侧已被禁用的用户 sub 集合。"""

    @abstractmethod
    async def healthy(self) -> bool:
        """管理接口可用性（对账任务依赖）。"""

    @abstractmethod
    async def ensure_user_email(self, sub: str, email: str) -> bool:
        """用户无邮箱时补写占位邮箱（new-api OIDC userinfo 强制 email 非空）。

        返回是否发生了写入。
        """


class CasdoorAdmin(IdPAdmin):
    """Casdoor：管理员登录（Cookie 会话）后拉取组织用户列表。

    用户禁用状态取 user.isDisabled；sub 与 OIDC userinfo 的 sub 对齐（org/name）。
    """

    def __init__(self) -> None:
        self._endpoint = settings.idp_admin_endpoint
        self._organization = settings.idp_admin_organization or "built-in"
        self._username = settings.idp_admin_username
        self._password = settings.idp_admin_password
        self._cookies: dict[str, str] = {}

    async def _login(self) -> dict[str, str]:
        async with httpx.AsyncClient(trust_env=False, timeout=15) as c:
            resp = await c.post(
                settings.oidc_issuer.rstrip("/") + "/api/login",
                json={
                    "type": "login",
                    "username": self._username,
                    "password": self._password,
                    "application": "app-built-in",
                    "organization": "built-in",
                    "signinMethod": "password",
                },
            )
            if resp.status_code != 200 or resp.json().get("status") != "ok":
                raise RuntimeError(f"casdoor admin login failed: HTTP {resp.status_code}")
            self._cookies = dict(resp.cookies)
        return self._cookies

    async def list_disabled_subs(self) -> set[str]:
        if not self._cookies:
            await self._login()
        disabled: set[str] = set()
        page = 1
        while True:
            async with httpx.AsyncClient(
                trust_env=False, timeout=15, cookies=self._cookies
            ) as c:
                resp = await c.get(
                    self._endpoint,
                    params={
                        "owner": self._organization,
                        "p": page,
                        "pageSize": 100,
                    },
                )
                if resp.status_code == 401:
                    await self._login()
                    continue
                if resp.status_code != 200:
                    raise RuntimeError(f"casdoor admin API HTTP {resp.status_code}")
                payload = resp.json()
            for user in payload.get("data", []):
                # Casdoor 的禁用标记是 isForbidden（isDisabled 不存在）
                if user.get("isForbidden"):
                    disabled.add(str(user.get("id", "")))
            if len(payload.get("data", [])) < 100:
                break
            page += 1
            if page > 100:
                break
        return disabled

    async def ensure_user_email(self, sub: str, email: str) -> bool:
        if not self._cookies:
            await self._login()
        base = settings.oidc_issuer.rstrip("/")
        async with httpx.AsyncClient(trust_env=False, timeout=15, cookies=self._cookies) as c:
            # 按组织分页找 sub（UUID）对应的用户；update-user 需要 owner/name 格式的 id
            page = 1
            user = None
            while user is None and page <= 50:
                resp = await c.get(
                    f"{base}/api/get-users",
                    params={"owner": self._organization, "p": page, "pageSize": 100},
                )
                if resp.status_code != 200:
                    raise RuntimeError(f"get-users HTTP {resp.status_code}")
                data = resp.json().get("data") or []
                user = next((u for u in data if u.get("id") == sub), None)
                if len(data) < 100:
                    break
                page += 1
            if user is None:
                raise RuntimeError(f"user {sub[:8]}… not found in org {self._organization}")
            if user.get("email"):
                return False
            user["email"] = email
            resp = await c.post(
                f"{base}/api/update-user?id={user['owner']}/{user['name']}",
                json=user,
            )
            if resp.status_code != 200 or resp.json().get("status") != "ok":
                raise RuntimeError(f"update-user email failed: {resp.text[:150]}")
            log.info("casdoor user %s… email ensured", sub[:8])
            return True

    async def healthy(self) -> bool:
        try:
            await self.list_disabled_subs()
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("casdoor admin unhealthy: %s", e)
            return False


class MockIdPAdmin(IdPAdmin):
    """mock IdP：GET {endpoint}/admin/users → {"users":[{"sub":..,"disabled":bool}]}"""

    def __init__(self) -> None:
        self._endpoint = settings.idp_admin_endpoint.rstrip("/")

    async def list_disabled_subs(self) -> set[str]:
        async with httpx.AsyncClient(trust_env=False, timeout=10) as c:
            resp = await c.get(self._endpoint + "/admin/users")
            resp.raise_for_status()
            payload = resp.json()
        return {u["sub"] for u in payload.get("users", []) if u.get("disabled")}

    async def ensure_user_email(self, sub: str, email: str) -> bool:
        return False  # mock 不需要邮箱补齐

    async def healthy(self) -> bool:
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=10) as c:
                resp = await c.get(self._endpoint + "/admin/users")
                return resp.status_code == 200
        except Exception:  # noqa: BLE001
            return False


def get_idp_admin() -> IdPAdmin:
    if settings.idp_admin_type.lower() == "mock":
        return MockIdPAdmin()
    return CasdoorAdmin()


idp_admin = get_idp_admin()
