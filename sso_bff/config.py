"""sso-bff 配置：pydantic-settings，全部经环境变量注入。"""
from __future__ import annotations

import base64
import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SSO_BFF_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # ---- BFF 自身 ----
    env: str = "dev"
    base_url: str = "http://localhost:8800"
    session_cookie: str = "sso_session"
    session_ttl_hours: int = 168
    state_ttl_seconds: int = 600

    # ---- Redis ----
    redis_url: str = "redis://127.0.0.1:6379/0"

    # ---- 数据库 ----
    database_url: str = "sqlite+aiosqlite:///./sso_bff.db"

    # ---- 加密 ----
    crypto_key: str = ""

    # ---- OIDC ----
    oidc_issuer: str = "http://localhost:9000"
    oidc_client_id: str = "sso-bff-app"
    oidc_client_secret: str = "change-me"
    oidc_scope: str = "openid profile phone"
    oidc_redirect_path: str = "/auth/callback"

    # ---- IdP 管理（封禁级联）----
    idp_admin_type: str = "casdoor"  # casdoor / mock
    idp_admin_endpoint: str = ""
    idp_admin_token: str = ""
    idp_admin_organization: str = "built-in"
    idp_admin_username: str = ""
    idp_admin_password: str = ""

    # ---- new-api ----
    newapi_base_url: str = "https://newapi-0to1.livetest.cn"
    newapi_admin_username: str = "root"
    newapi_admin_password: str = ""
    newapi_default_quota: int = 500000
    newapi_default_expired_time: int = -1
    newapi_default_unlimited_quota: bool = True
    newapi_token_name: str = "sso-bff"
    newapi_user_prefix: str = "sso_"
    #: 新开通用户在 new-api 落的分组。
    #: ⚠️ rc.42 的 CreateUser **不接受 group**（源码 cleanUser 只含 Username/Password/
    #: DisplayName/Role，group 被静默丢弃）⇒ 必须建号后单独 PUT /api/user/ 设置。
    #: 不设则用户 group 落成空串 ⇒ 匹配不到任何 ability ⇒ /v1/models 空、调用无渠道可用。
    newapi_default_group: str = "default"

    # ---- 后台任务 ----
    ban_cascade_interval_seconds: int = 60
    reconcile_interval_seconds: int = 3600
    background_tasks: bool = True

    # ---- 演示前端 ----
    demo_allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    #: 允许作为登录后回跳目标的 origin（逗号分隔，如 https://appdemo.1task.cn）。
    #: 站内相对路径恒允许；绝对 URL 仅白名单内允许，其余回落 /。
    allowed_redirect_origins: str = ""

    @property
    def redirect_uri(self) -> str:
        return self.base_url.rstrip("/") + self.oidc_redirect_path

    @property
    def is_prod(self) -> bool:
        return self.env.lower() == "prod"

    @property
    def demo_origins(self) -> list[str]:
        return [o.strip() for o in self.demo_allowed_origins.split(",") if o.strip()]

    @property
    def redirect_origins(self) -> list[str]:
        """允许作为登录回跳目标的 origin（防开放重定向，见 redirects.safe_redirect）。"""
        return [o.strip() for o in self.allowed_redirect_origins.split(",") if o.strip()]

    def resolve_crypto_key(self) -> bytes:
        """Fernet key。生产必须显式配置；dev 缺省自动生成并落盘（仅开发用）。"""
        if self.crypto_key:
            return self.crypto_key.encode()
        if self.is_prod:
            raise RuntimeError("SSO_BFF_CRYPTO_KEY 未设置（生产环境禁止自动生成）")
        keyfile = _PROJECT_ROOT / ".dev_fernet_key"
        if keyfile.exists():
            return keyfile.read_bytes().strip()
        from cryptography.fernet import Fernet

        key = Fernet.generate_key()
        keyfile.write_bytes(key)
        keyfile.chmod(0o600)
        return key


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
