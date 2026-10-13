#!/usr/bin/env python3
"""W4：把 new-api 的 OIDC 登录指向 Casdoor（控制台 SSO 落到同一账户）。

幂等：重复执行安全。用法：python scripts/setup_newapi_oidc.py [--dry-run]
前置：scripts/setup_casdoor.py 已建 new-api-console-app。
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

BASE = "https://newapi-0to1.livetest.cn"
CASDOOR = "https://casdoor.1task.cn"
CONSOLE_CLIENT_ID = "new-api-console-app"


def load_console_secret() -> str:
    """优先环境变量；否则读本机 livetest-ai 机密库（不入库）。"""
    import os
    if os.environ.get("SSO_BFF_CONSOLE_CLIENT_SECRET"):
        return os.environ["SSO_BFF_CONSOLE_CLIENT_SECRET"]
    path = "/Users/betterme/PycharmProjects/AI/livetest-ai/secrets/casdoor-ai-prod.txt"
    for line in open(path):
        if line.startswith("NEWAPI_CONSOLE_APP_CLIENT_SECRET="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("SSO_BFF_CONSOLE_CLIENT_SECRET 未设置且机密库不可读")

OIDC_OPTIONS = {
    "oidc.client_id": CONSOLE_CLIENT_ID,
    "oidc.client_secret": load_console_secret(),
    "oidc.authorization_endpoint": f"{CASDOOR}/login/oauth/authorize",
    "oidc.token_endpoint": f"{CASDOOR}/api/login/oauth/access_token",
    "oidc.user_info_endpoint": f"{CASDOOR}/api/userinfo",
    "oidc.well_known": f"{CASDOOR}/.well-known/openid-configuration",
    "oidc.display_name": "Casdoor 统一登录",
    # 必须最后设置：new-api 要求先有 client_id/secret 才允许启用
    "oidc.enabled": "true",
}


def load_admin_pass() -> str:
    path = "/Users/betterme/PycharmProjects/AI/livetest-ai/.env.local"
    for line in open(path):
        if line.startswith("LIVETEST_NEWAPI_0TO1_ADMIN_PASSWORD="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"admin password not found in {path}")


def req(method: str, path: str, body=None, token: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    st, d = req("POST", "/api/user/login", {"username": "root", "password": load_admin_pass()})
    if st != 200 or not d.get("success"):
        sys.exit(f"[FAIL] admin login: {d}")
    token = d["data"]["access_token"]
    print("[ok] new-api admin login")

    for key, value in OIDC_OPTIONS.items():
        if args.dry_run:
            print(f"[dry-run] PUT /api/option/ {key}={value[:40]}")
            continue
        st, d = req("PUT", "/api/option/", {"key": key, "value": value}, token)
        ok = st == 200 and d.get("success")
        print(f"[{'ok' if ok else 'FAIL'}] {key} = {value[:50]}")
        if not ok:
            sys.exit(f"[FAIL] set {key}: {d}")

    # 回读验证
    st, d = req("GET", "/api/option/", None, token)
    opts = {o["key"]: o.get("value") for o in d["data"]}
    print("\n当前 OIDC 配置：")
    for key in OIDC_OPTIONS:
        print(f"  {key} = {opts.get(key)}")
    print("\nServerAddress =", opts.get("ServerAddress"), "（必须为 https://newapi-0to1.livetest.cn）")
    if opts.get("oidc.enabled") != "true":
        sys.exit("[FAIL] oidc.enabled 未生效")


if __name__ == "__main__":
    main()
