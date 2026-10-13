"""后台任务（PRD F5.2 封禁级联 / F5.3 定期对账）。

- 封禁级联：分钟级轮询 IdP 用户状态；发现映射账户在 IdP 被禁用 ⇒ 吊销其 new-api 令牌、
  映射置 disabled；IdP 恢复 ⇒ 重新签发令牌回 active。全程无人工介入，失败重试 + 告警。
- 定期对账：比对 identity_mapping 与 new-api 实际用户/令牌，输出差异报告
  （孤儿账户、失效 key、状态不一致），防止脏数据积累。

注意（rc.42 实证）：new-api 管理 API 的 disable/delete 用户需要安全验证（root 未登记），
因此级联采用“吊销令牌”而非“禁用用户”——对 API 访问的效果等价且立即可用。
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from sqlalchemy import select

from .config import settings
from .db import IdentityMapping, get_sessionmaker
from .idp_admin import idp_admin
from .jit import (
    derive_username,
    get_mapping,
    reactivate,
    revoke_all_tokens,
)
from .logging_setup import get_logger
from .newapi import NewApiError, newapi

log = get_logger("tasks")


@dataclass
class CascadeReport:
    checked: int = 0
    revoked: list[str] = field(default_factory=list)   # sub 前缀
    reactivated: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def ban_cascade_once() -> CascadeReport:
    """单轮封禁级联。"""
    report = CascadeReport()
    try:
        disabled_subs = await idp_admin.list_disabled_subs()
    except Exception as e:  # noqa: BLE001 - IdP 不可用时本轮跳过，下轮重试
        report.errors.append(f"idp admin unavailable: {e}")
        log.warning("ban cascade skipped: %s", e)
        return report

    sm = get_sessionmaker()
    async with sm() as session:
        result = await session.execute(select(IdentityMapping))
        mappings = list(result.scalars().all())

    for mapping in mappings:
        report.checked += 1
        try:
            if mapping.casdoor_sub in disabled_subs and mapping.status == "active":
                n = await revoke_all_tokens(mapping.casdoor_sub)
                report.revoked.append(f"{mapping.casdoor_sub[:8]}…({n} tokens)")
            elif mapping.casdoor_sub not in disabled_subs and mapping.status == "disabled":
                await reactivate(mapping.casdoor_sub)
                report.reactivated.append(f"{mapping.casdoor_sub[:8]}…")
        except Exception as e:  # noqa: BLE001 - 单账户失败不阻塞整轮，下轮重试
            report.errors.append(f"{mapping.casdoor_sub[:8]}…: {e}")
            log.error("cascade action failed for sub=%s…: %s", mapping.casdoor_sub[:8], e)
    if report.revoked or report.reactivated or report.errors:
        log.info(
            "ban cascade round: checked=%d revoked=%d reactivated=%d errors=%d",
            report.checked, len(report.revoked), len(report.reactivated), len(report.errors),
        )
    return report


@dataclass
class ReconcileReport:
    mappings: int = 0
    newapi_users: int = 0
    orphan_accounts: list[str] = field(default_factory=list)   # new-api 有、映射无
    missing_accounts: list[str] = field(default_factory=list)  # 映射有、new-api 无
    token_mismatch: list[str] = field(default_factory=list)    # 映射 token 在 new-api 不存在
    errors: list[str] = field(default_factory=list)


async def reconcile_once() -> ReconcileReport:
    """单轮对账（PRD F5.3：孤儿账户、失效 key、额度异常）。"""
    report = ReconcileReport()
    sm = get_sessionmaker()
    async with sm() as session:
        result = await session.execute(select(IdentityMapping))
        mappings = list(result.scalars().all())
    report.mappings = len(mappings)

    try:
        users = await newapi.list_all_users()
    except NewApiError as e:
        report.errors.append(f"list users failed: {e}")
        return report
    report.newapi_users = len(users)
    users_by_name = {u.username: u for u in users}
    mapped_usernames = {m.new_api_username for m in mappings}

    for m in mappings:
        user = users_by_name.get(m.new_api_username)
        if user is None:
            report.missing_accounts.append(f"{m.casdoor_sub[:8]}…({m.new_api_username})")
            continue
        # 令牌核对：以用户本人会话列出令牌，确认映射 token 仍在
        try:
            from .crypto import decrypt

            password = decrypt(m.new_api_password_enc)
            user_token = await newapi.login_as_user(m.new_api_username, password)
            tokens = await newapi.list_user_tokens(user_token)
            if not any(t.id == m.new_api_token_id for t in tokens):
                report.token_mismatch.append(f"{m.casdoor_sub[:8]}…(token {m.new_api_token_id})")
        except Exception as e:  # noqa: BLE001
            report.errors.append(f"token check {m.casdoor_sub[:8]}…: {e}")

    # 孤儿账户：new-api 里带管理前缀但没有映射的账户
    for name, user in users_by_name.items():
        if name.startswith(settings.newapi_user_prefix) and name not in mapped_usernames:
            report.orphan_accounts.append(f"{name}(id={user.id}, status={user.status})")

    log.info(
        "reconcile: mappings=%d newapi_users=%d orphans=%d missing=%d token_mismatch=%d errors=%d",
        report.mappings, report.newapi_users, len(report.orphan_accounts),
        len(report.missing_accounts), len(report.token_mismatch), len(report.errors),
    )
    return report


class BackgroundTasks:
    """APScheduler 生命周期封装（失败自动下轮重试）。"""

    def __init__(self) -> None:
        self._scheduler = None

    def start(self) -> None:
        if not settings.background_tasks:
            log.info("background tasks disabled by config")
            return
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        self._scheduler = AsyncIOScheduler()
        self._scheduler.add_job(
            ban_cascade_once, "interval",
            seconds=settings.ban_cascade_interval_seconds,
            id="ban_cascade", max_instances=1, coalesce=True,
        )
        self._scheduler.add_job(
            reconcile_once, "interval",
            seconds=settings.reconcile_interval_seconds,
            id="reconcile", max_instances=1, coalesce=True,
        )
        self._scheduler.start()
        log.info(
            "background tasks started (cascade=%ds, reconcile=%ds)",
            settings.ban_cascade_interval_seconds, settings.reconcile_interval_seconds,
        )

    async def stop(self) -> None:
        if self._scheduler:
            self._scheduler.shutdown(wait=False)


background = BackgroundTasks()
