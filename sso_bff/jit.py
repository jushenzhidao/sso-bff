"""JIT 自动开通编排（PRD F2.2，本系统核心）。

设计要点（对 new-api v1.0.0-rc.42 实证适配）：
1. 幂等：以 casdoor_sub 为唯一锚点；Redis 分布式锁防并发重入；双重检查 mapping。
2. 失败无半成品：顺序为 建用户→登录→发令牌→**最后**写 mapping。
   任一步失败不产生 mapping 行，下次登录重试（PRD F2.2）。
3. 孤儿回收：建号成功但后续失败的残留用户，下次登录按用户名找回——
   口令由 crypto_key + sub 确定性派生（HMAC-SHA256），无需记住当次随机值。
4. 用户名 = sso_ + base32(sub) 前 11 位（new-api 上限 20 字符）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .crypto import CryptoError, decrypt, encrypt, mask_key
from .db import IdentityMapping, get_sessionmaker
from .logging_setup import get_logger
from .newapi import NewApiError, newapi
from .oidc import OIDCUserInfo
from .sessions import store

log = get_logger("jit")

USERNAME_MAX = 20


class JITError(RuntimeError):
    pass


@dataclass
class ProvisionResult:
    mapping: IdentityMapping
    created: bool  # True=本次新建，False=复用已有


def derive_password(sub: str) -> str:
    """确定性派生 new-api 用户口令（24 字符，满足 min=8/max=128）。

    同一把 crypto_key + 同一 sub ⇒ 同一口令，使孤儿账户可回收。
    crypto_key 本身就是最高机密（加密所有 key），同信任边界内不扩大暴露面。
    """
    mac = hmac.new(
        settings.resolve_crypto_key(), f"newapi-password:{sub}".encode(), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()[:24]


def derive_username(sub: str) -> str:
    digest = base64.b32encode(sub.encode()).decode().rstrip("=")
    return (settings.newapi_user_prefix + digest)[:USERNAME_MAX]


def _safe_display_name(profile: OIDCUserInfo, username: str) -> str:
    name = (profile.name or profile.preferred_username or username).strip()
    return (name or username)[:20]


async def get_mapping(session: AsyncSession, sub: str) -> IdentityMapping | None:
    result = await session.execute(
        select(IdentityMapping).where(IdentityMapping.casdoor_sub == sub)
    )
    return result.scalar_one_or_none()


async def get_or_provision(sub: str, profile: OIDCUserInfo) -> ProvisionResult:
    """主入口：取映射，无则开通。并发安全、失败无半成品。"""
    sm = get_sessionmaker()
    async with sm() as session:
        existing = await get_mapping(session, sub)
        if existing:
            return ProvisionResult(mapping=existing, created=False)

    if not await store.acquire_jit_lock(sub):
        # 并发开通中：短暂等待后重读（对方成功后这里直接复用）
        import asyncio

        for _ in range(10):
            await asyncio.sleep(0.3)
            async with sm() as session:
                existing = await get_mapping(session, sub)
                if existing:
                    return ProvisionResult(mapping=existing, created=False)
        raise JITError("concurrent provisioning did not settle in time")

    try:
        # 锁内双重检查
        async with sm() as session:
            existing = await get_mapping(session, sub)
            if existing:
                return ProvisionResult(mapping=existing, created=False)

        username = derive_username(sub)
        password = derive_password(sub)
        display_name = _safe_display_name(profile, username)
        phone_masked = profile.phone[:3] + "****" + profile.phone[-4:] if len(profile.phone) >= 7 else profile.phone

        # 1) 建用户（或回收孤儿）
        user = await newapi.find_user_by_username(username)
        if user is None:
            user_id = await newapi.create_user(username, password, display_name)
            log.info("JIT created new-api user id=%s username=%s", user_id, username)
        else:
            user_id = user.id
            log.info("JIT adopting existing new-api user id=%s username=%s", user_id, username)

        # 2) 以该用户身份登录（rc.42：令牌仅本人会话可发）
        user_token = await newapi.login_as_user(username, password)

        # 3) 签发令牌（按名复用：重试/孤儿回收不重复发）
        tokens = await newapi.list_user_tokens(user_token)
        token = next((t for t in tokens if t.name == settings.newapi_token_name), None)
        if token is None:
            await newapi.add_token(
                user_token,
                name=settings.newapi_token_name,
                remain_quota=settings.newapi_default_quota,
                expired_time=settings.newapi_default_expired_time,
                unlimited_quota=settings.newapi_default_unlimited_quota,
            )
            tokens = await newapi.list_user_tokens(user_token)
            token = next((t for t in tokens if t.name == settings.newapi_token_name), None)
        if token is None:
            raise JITError(f"token {settings.newapi_token_name!r} not found after issuance")
        key = await newapi.get_token_key(user_token, token.id)

        # 3.5) new-api OIDC 强制 userinfo 的 email 非空 ⇒ 无邮箱用户补占位邮箱
        try:
            from .idp_admin import idp_admin

            await idp_admin.ensure_user_email(sub, f"sso-{sub[:8]}@users.1task.cn")
        except Exception as e:  # noqa: BLE001 - 邮箱补齐失败不阻塞开通
            log.warning("ensure_user_email failed for sub=%s…: %s", sub[:8], e)

        # 4) 最后一步：写映射（前面失败都不会留下 mapping）
        async with sm() as session:
            async with session.begin():
                mapping = IdentityMapping(
                    casdoor_sub=sub,
                    phone=profile.phone,
                    new_api_user_id=user_id,
                    new_api_username=username,
                    new_api_token_id=token.id,
                    new_api_key_enc=encrypt(key),
                    new_api_password_enc=encrypt(password),
                    status="active",
                )
                session.add(mapping)
        log.info(
            "JIT provisioning complete: sub=%s… user_id=%s token_id=%s key=%s",
            sub[:8], user_id, token.id, mask_key(key),
        )
        async with sm() as session:
            saved = await get_mapping(session, sub)
            assert saved is not None
            return ProvisionResult(mapping=saved, created=True)
    except (NewApiError, JITError) as e:
        log.error("JIT provisioning failed for sub=%s…: %s", sub[:8], e)
        raise JITError(str(e)) from e
    finally:
        await store.release_jit_lock(sub)


async def get_active_key(sub: str) -> tuple[IdentityMapping, str]:
    """取当前用户的 key（明文，仅在内部分发，禁落日志）。"""
    sm = get_sessionmaker()
    async with sm() as session:
        mapping = await get_mapping(session, sub)
        if mapping is None:
            raise JITError("identity mapping not found (provisioning required)")
        if mapping.status != "active":
            raise JITError(f"identity is {mapping.status}")
        try:
            key = decrypt(mapping.new_api_key_enc)
        except CryptoError as e:
            raise JITError(f"key decryption failed: {e}") from e
        return mapping, key


async def rotate(sub: str) -> str:
    """轮换（PRD F2.3）：作废旧 key、签发新 key 并同步映射表。"""
    sm = get_sessionmaker()
    async with sm() as session:
        mapping = await get_mapping(session, sub)
        if mapping is None or mapping.status != "active":
            raise JITError("identity not active")
        old_token_id = mapping.new_api_token_id

    password = await _load_password(sub)
    user_token = await newapi.login_as_user(derive_username(sub), password)

    await newapi.add_token(
        user_token,
        name=settings.newapi_token_name,
        remain_quota=settings.newapi_default_quota,
        expired_time=settings.newapi_default_expired_time,
        unlimited_quota=settings.newapi_default_unlimited_quota,
    )
    tokens = await newapi.list_user_tokens(user_token)
    new_token = next(
        (t for t in tokens if t.name == settings.newapi_token_name and t.id != old_token_id),
        None,
    )
    if new_token is None:
        raise JITError("rotated token not found")
    new_key = await newapi.get_token_key(user_token, new_token.id)
    await newapi.delete_token(user_token, old_token_id)

    async with sm() as session:
        async with session.begin():
            mapping = await get_mapping(session, sub)
            assert mapping is not None
            mapping.new_api_token_id = new_token.id
            mapping.new_api_key_enc = encrypt(new_key)
    log.info("key rotated: sub=%s… token %s→%s key=%s", sub[:8], old_token_id, new_token.id, mask_key(new_key))
    return new_key


async def _load_password(sub: str) -> str:
    sm = get_sessionmaker()
    async with sm() as session:
        mapping = await get_mapping(session, sub)
        if mapping is None:
            raise JITError("identity mapping not found")
        try:
            return decrypt(mapping.new_api_password_enc)
        except CryptoError as e:
            raise JITError(f"password decryption failed: {e}") from e


async def revoke_all_tokens(sub: str) -> int:
    """封禁级联动作：吊销该用户 new-api 侧全部令牌，映射置 disabled。

    返回吊销的令牌数。API 访问即时中断（PRD 6.5 步骤 3）。
    """
    password = await _load_password(sub)
    username = derive_username(sub)
    try:
        user_token = await newapi.login_as_user(username, password)
        tokens = await newapi.list_user_tokens(user_token)
        for t in tokens:
            await newapi.delete_token(user_token, t.id)
    except NewApiError as e:
        log.error("revoke_all_tokens failed for sub=%s…: %s", sub[:8], e)
        raise
    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            mapping = await get_mapping(session, sub)
            if mapping is not None:
                mapping.status = "disabled"
    log.info("ban cascade: sub=%s… revoked %d token(s)", sub[:8], len(tokens))
    return len(tokens)


async def reactivate(sub: str) -> None:
    """IdP 侧恢复后：重新签发令牌，映射回 active。"""
    password = await _load_password(sub)
    username = derive_username(sub)
    user_token = await newapi.login_as_user(username, password)
    tokens = await newapi.list_user_tokens(user_token)
    token = next((t for t in tokens if t.name == settings.newapi_token_name), None)
    if token is None:
        await newapi.add_token(
            user_token,
            name=settings.newapi_token_name,
            remain_quota=settings.newapi_default_quota,
            expired_time=settings.newapi_default_expired_time,
            unlimited_quota=settings.newapi_default_unlimited_quota,
        )
        tokens = await newapi.list_user_tokens(user_token)
        token = next((t for t in tokens if t.name == settings.newapi_token_name), None)
    if token is None:
        raise JITError("reactivation: token not found after issuance")
    key = await newapi.get_token_key(user_token, token.id)
    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            mapping = await get_mapping(session, sub)
            if mapping is not None:
                mapping.new_api_token_id = token.id
                mapping.new_api_key_enc = encrypt(key)
                mapping.status = "active"
    log.info("reactivated: sub=%s… token_id=%s", sub[:8], token.id)


async def touch_last_login(sub: str) -> None:
    from datetime import datetime, timezone

    sm = get_sessionmaker()
    async with sm() as session:
        async with session.begin():
            mapping = await get_mapping(session, sub)
            if mapping is not None:
                mapping.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
