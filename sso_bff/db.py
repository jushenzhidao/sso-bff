"""identity_mapping 表（PRD 5.2）与数据库访问层。

dev：SQLite（aiosqlite）；prod：MySQL（aiomysql），连接串经 SSO_BFF_DATABASE_URL 切换。
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Integer, String, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .config import settings


class Base(DeclarativeBase):
    pass


class IdentityMapping(Base):
    """Casdoor sub ↔ new-api 用户/令牌 的身份映射。sub 是全局唯一锚点（PRD D3）。"""

    __tablename__ = "identity_mapping"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    casdoor_sub: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    phone: Mapped[str] = mapped_column(String(32), default="", index=True)
    new_api_user_id: Mapped[int] = mapped_column(Integer, index=True)
    new_api_username: Mapped[str] = mapped_column(String(64), default="")
    new_api_token_id: Mapped[int] = mapped_column(Integer)
    new_api_key_enc: Mapped[str] = mapped_column(String(512))
    # JIT 用户口令密文：轮换/封禁级联需以该用户身份登录 new-api（rc.42 令牌仅本人会话可操作）
    new_api_password_enc: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)  # active / disabled
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    last_login_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:  # 永不打印密文
        return (
            f"<IdentityMapping sub={self.casdoor_sub[:8]}… user_id={self.new_api_user_id} "
            f"token_id={self.new_api_token_id} status={self.status}>"
        )


_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def init_db() -> None:
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
