"""sso-bff 单元测试（离线部分：派生逻辑、加解密、脱敏）。

端到端验证见 scripts/e2e_test.py（真实 Casdoor × 真实 new-api）。
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault("SSO_BFF_ENV", "dev")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sso_bff.crypto import decrypt, encrypt, mask_key  # noqa: E402
from sso_bff.jit import derive_password, derive_username  # noqa: E402
from sso_bff.logging_setup import _mask_message  # noqa: E402
from sso_bff.oidc import mask_phone  # noqa: E402
from sso_bff.redirects import safe_redirect  # noqa: E402


def test_crypto_roundtrip():
    secret = "sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    assert decrypt(encrypt(secret)) == secret


def test_mask_key():
    assert mask_key("AbCdEfGh1234567890") == "AbCd************90"
    assert mask_key("short") == "***"
    assert mask_key("") == "***"


def test_mask_phone():
    assert mask_phone("13800138000") == "138****8000"
    assert mask_phone("123") == "123"


def test_derive_password_deterministic():
    a, b = derive_password("sub-abc"), derive_password("sub-abc")
    assert a == b and len(a) >= 20
    assert derive_password("sub-abc") != derive_password("sub-xyz")


def test_derive_username_length():
    for sub in ["a", "builtin/admin", "x" * 200]:
        u = derive_username(sub)
        assert u.startswith("sso_")
        assert len(u) <= 20


ALLOW = ["https://appdemo.1task.cn"]


def test_safe_redirect_keeps_site_relative_paths():
    assert safe_redirect("/demo", ALLOW) == "/demo"
    assert safe_redirect("/console-connect?x=1", ALLOW) == "/console-connect?x=1"


def test_safe_redirect_allows_whitelisted_origin():
    assert safe_redirect("https://appdemo.1task.cn/", ALLOW) == "https://appdemo.1task.cn/"
    assert safe_redirect("https://appdemo.1task.cn/a/b", ALLOW) == "https://appdemo.1task.cn/a/b"


def test_safe_redirect_blocks_open_redirect():
    # 开放重定向的核心用例：陌生域名必须回落站内
    for evil in (
        "https://evil.com",
        "https://evil.com/path",
        "http://appdemo.1task.cn",          # scheme 不匹配（白名单是 https）
        "https://appdemo.1task.cn.evil.com",  # 后缀伪装
        "https://1task.cn",
        "//evil.com",                        # 协议相对 URL
        "//evil.com/x",
        "javascript:alert(1)",
        "data:text/html,<script>1</script>",
        "",
        None,
    ):
        assert safe_redirect(evil, ALLOW) == "/", f"{evil!r} 未被拦截"


def test_safe_redirect_without_whitelist_blocks_all_absolute():
    assert safe_redirect("https://appdemo.1task.cn/", []) == "/"
    assert safe_redirect("/demo", []) == "/demo"


def test_log_redaction_masks_keys_and_jwt():
    msg = "got key AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefgh and jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigpart"
    masked = _mask_message(msg)
    assert "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefgh" not in masked
    assert "«redacted»" in masked
