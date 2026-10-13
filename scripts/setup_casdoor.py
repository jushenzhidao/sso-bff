#!/usr/bin/env python3
"""Casdoor 初始化（PRD F1.1）：单一 Organization + 两个 Application。

- sso-bff-app：BFF 的 OIDC 客户端（授权码 + PKCE）
- new-api-console-app：new-api 控制台专用（W4，回调 https://newapi-0to1.livetest.cn/oauth/oidc）

幂等：已存在则跳过创建（clientSecret 打印一次后请妥善保管）。
用法：python scripts/setup_casdoor.py [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.request
import http.cookiejar

BASE = "https://casdoor.1task.cn"
ORG = "livetest"  # PRD F1.1：单一组织，平台所有主体归属其下

BFF_APP = {
    "owner": "admin",
    "name": "sso-bff-app",
    "organization": ORG,
    "displayName": "sso-bff 统一登录",
    "description": "多应用统一认证 BFF 身份服务（OIDC 客户端）",
    "homepageUrl": "https://sso.1task.cn",
    "clientId": "sso-bff-app",
    "redirectUris": ["http://localhost:8800/auth/callback", "https://sso.1task.cn/auth/callback"],
    "grantTypes": ["authorization_code", "refresh_token"],
    "responseTypes": ["code"],
    "scopes": [
        {"name": "openid", "displayName": "OpenID"},
        {"name": "profile", "displayName": "Profile"},
        {"name": "phone", "displayName": "Phone"},
        {"name": "email", "displayName": "Email"},   # new-api GetUserInfo 强制 email 非空
    ],
    "tokenFormat": "JWT",
    "enablePassword": True,
    "enableSignin": True,
    "expireInHours": 168,         # access token 7 天（0 ⇒ userinfo 报 Access token expired）
    "refreshExpireInHours": 720,  # refresh token 30 天
    "signinMethods": [{"name": "Password", "displayName": "Password", "rule": ""}],
    "signupItems": [{"name": "Username", "visible": False}, {"name": "Password", "visible": False},
                    {"name": "Display name", "visible": False}, {"name": "Phone", "visible": True}],
    "signinItems": [{"name": "Username", "visible": True}, {"name": "Password", "visible": True}],
}

CONSOLE_APP = {
    "owner": "admin",
    "name": "new-api-console-app",
    "organization": ORG,
    "displayName": "new-api 控制台",
    "description": "new-api 控制台 OIDC 登录（W4，匹配 oidc_id 落到同一账户）",
    "homepageUrl": "https://newapi-0to1.livetest.cn",
    "clientId": "new-api-console-app",
    "redirectUris": [
        "https://newapi-0to1.livetest.cn/oauth/oidc",
        "http://localhost:8800/console-connect/callback",   # BFF 绑定回调（Casdoor 换票不校验 redirect_uri）
        "https://sso.1task.cn/console-connect/callback",
    ],
    "grantTypes": ["authorization_code", "refresh_token"],
    "responseTypes": ["code"],
    "scopes": [
        {"name": "openid", "displayName": "OpenID"},
        {"name": "profile", "displayName": "Profile"},
        {"name": "phone", "displayName": "Phone"},
        {"name": "email", "displayName": "Email"},   # new-api GetUserInfo 强制 email 非空
    ],
    "tokenFormat": "JWT",
    "enablePassword": True,
    "enableSignin": True,
    "expireInHours": 168,         # access token 7 天（0 ⇒ userinfo 报 Access token expired）
    "refreshExpireInHours": 720,  # refresh token 30 天
    "signinMethods": [{"name": "Password", "displayName": "Password", "rule": ""}],
}


def load_secret(name: str) -> str:
    path = "/Users/betterme/PycharmProjects/AI/livetest-ai/secrets/casdoor-ai-prod.txt"
    for line in open(path):
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"{name} not found in {path}")


class Casdoor:
    def __init__(self) -> None:
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self._login()

    def _login(self) -> None:
        body = json.dumps({
            "type": "login", "username": "admin",
            "password": load_secret("CASDOOR_ADMIN_PASSWORD"),
            "application": "app-built-in", "organization": "built-in",
            "signinMethod": "password",
        }).encode()
        req = urllib.request.Request(BASE + "/api/login", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with self.opener.open(req, timeout=15) as r:
            d = json.loads(r.read().decode())
        if d.get("status") != "ok":
            raise SystemExit(f"casdoor admin login failed: {d}")

    def call(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(req, timeout=20) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return {"http_error": e.code, "body": e.read().decode()[:300]}

    def get(self, path: str) -> dict:
        return self.call("GET", path)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    c = Casdoor()
    print("[ok] casdoor admin login")

    # 1) 组织（PRD F1.1 单一组织）
    orgs = c.get("/api/get-organizations").get("data", [])
    if any(o.get("name") == ORG for o in orgs):
        print(f"[skip] organization {ORG} exists")
    else:
        org = {
            "owner": "admin", "name": ORG, "displayName": "统一认证平台",
            "enablePassword": True, "enableSignUp": True,
            "passwordType": "plain", "passwordSalt": "",
            "defaultAvatar": "https://api.dicebear.com/7.x/adventurer/svg?seed=casdoor",
        }
        r = c.call("POST", "/api/add-organization", org)
        print(f"[{'ok' if r.get('status') == 'ok' else 'FAIL'}] create organization {ORG}: {str(r)[:200]}")
        if r.get("status") != "ok" and not args.dry_run:
            sys.exit(1)

    # 2) 两个应用
    apps = c.get("/api/get-applications?owner=admin").get("data", [])
    existing = {a.get("name") for a in apps}
    for app in (BFF_APP, CONSOLE_APP):
        name = app["name"]
        if name in existing:
            print(f"[skip] application {name} exists")
            continue
        if args.dry_run:
            print(f"[dry-run] would create application {name}")
            continue
        payload = dict(app)
        payload["clientSecret"] = secrets.token_urlsafe(24)
        r = c.call("POST", "/api/add-application", payload)
        ok = r.get("status") == "ok"
        print(f"[{'ok' if ok else 'FAIL'}] create application {name}: {str(r)[:200]}")
        if ok:
            print(f"    client_id={payload['clientId']}")
            print(f"    client_secret={payload['clientSecret']}  ← 仅此次显示，请妥善保管")

    # 3) 汇总
    apps = c.get("/api/get-applications?owner=admin").get("data", [])
    for a in apps:
        if a.get("name") in ("sso-bff-app", "new-api-console-app"):
            print(f"  - {a['name']}: clientId={a.get('clientId')} redirect={a.get('redirectUris')}")


if __name__ == "__main__":
    main()
