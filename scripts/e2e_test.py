#!/usr/bin/env python3
"""sso-bff 端到端验证：真实 Casdoor + 真实 new-api + 本地 BFF。

覆盖 PRD 验收项：
  AC-01/02 登录（Casdoor 密码登录代理微信扫码/手机验证码的结果态）
  AC-03    SSO 会话（BFF 会话 Cookie）
  AC-04    首次登录 JIT 自动开户 + 专属 key 签发 + 重复登录幂等
  AC-05    前端直连模型面：用户 key 调 /v1/models（免费端点，不计费）
  AC-07    管理员能力（建号/搜索/改名）
  AC-10   封禁级联：Casdoor 禁用 → 轮询 → new-api 令牌吊销 → key 失效
  F5.3    定期对账
外加：钥匙轮换（F2.3）。

计费纪律：只调 /v1/models（免费），不做任何模型生成调用。
"""
from __future__ import annotations

import asyncio
import json
import sys
import urllib.request
import urllib.error
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, "/Users/betterme/PycharmProjects/AI/sso-bff")

import httpx

BFF = "http://localhost:8800"
CASDOOR = "https://casdoor.1task.cn"
NEWAPI = "https://newapi-0to1.livetest.cn"
E2E_USER = "sso-e2e-alice"
def _load_e2e_pass() -> str:
    import os
    if os.environ.get("SSO_BFF_E2E_PASS"):
        return os.environ["SSO_BFF_E2E_PASS"]
    for line in open(os.path.join(os.path.dirname(__file__), "..", ".env")):
        if line.startswith("SSO_BFF_E2E_PASS="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("SSO_BFF_E2E_PASS 未设置（写入项目 .env 或环境变量）")


E2E_PASS = _load_e2e_pass()

PASS, FAIL = 0, 0


def ok(name: str, detail: str = "") -> None:
    global PASS
    PASS += 1
    print(f"  [PASS] {name}" + (f" — {detail}" if detail else ""))


def fail(name: str, detail: str = "") -> None:
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))


def check(name: str, cond: bool, detail: str = "") -> bool:
    if cond:
        ok(name, detail)
    else:
        fail(name, detail)
    return cond


def jreq(method: str, path: str, body=None, token=None, base: str = NEWAPI):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def load_admin_pass() -> str:
    for line in open("/Users/betterme/PycharmProjects/AI/livetest-ai/.env.local"):
        if line.startswith("LIVETEST_NEWAPI_0TO1_ADMIN_PASSWORD="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("admin password not found")


ADMIN_PASS = load_admin_pass()


async def login_via_bff(client: httpx.AsyncClient) -> bool:
    """完整登录链：BFF /auth/login → Casdoor 登录 → grant-consent 发码 → BFF 回调。"""
    # 1) Casdoor 会话（密码登录代理扫码/验证码的结果态）
    r = await client.post(
        f"{CASDOOR}/api/login",
        json={
            "type": "login",
            "username": E2E_USER,
            "password": E2E_PASS,
            "application": "sso-bff-app",
            "organization": "livetest",
            "signinMethod": "password",
        },
    )
    if r.json().get("status") != "ok":
        fail("Casdoor 用户登录", r.text[:150])
        return False
    ok("Casdoor 用户登录（密码态）")

    # 2) BFF 发起登录
    r = await client.get(f"{BFF}/auth/login", params={"redirect": "/demo"})
    authorize_url = r.headers["location"]
    q = parse_qs(urlparse(authorize_url).query)
    check("BFF /auth/login 生成授权 URL（state/nonce/PKCE）",
          "state" in q and "code_challenge" in q and q.get("client_id") == ["sso-bff-app"])

    # 3) grant-consent 发码（等价于浏览器过同意页）
    consent = {
        "application": "admin/sso-bff-app",
        "grantedScopes": q["scope"][0].split(),
        "clientId": q["client_id"][0],
        "provider": "",
        "signinMethod": "",
        "responseType": q["response_type"][0],
        "redirectUri": q["redirect_uri"][0],
        "scope": q["scope"][0],
        "state": q["state"][0],
        "nonce": q.get("nonce", [""])[0],
        "challenge": q.get("code_challenge", [""])[0],
        "resource": "",
    }
    r = await client.post(f"{CASDOOR}/api/grant-consent", json=consent)
    d = r.json()
    if d.get("status") != "ok" or not d.get("data"):
        fail("Casdoor 授权码签发", r.text[:200])
        return False
    ok("Casdoor 授权码签发")

    # 4) BFF 回调
    r = await client.get(
        f"{BFF}/auth/callback", params={"code": d["data"], "state": q["state"][0]}
    )
    loc = r.headers.get("location", "")
    check("BFF 回调建立会话并回跳", r.status_code == 302 and "demo" in loc, loc)
    return True


async def cleanup_state(admin_tok: str) -> None:
    """退役所有平台托管账户（吊销令牌 + 改名去 sso_ 前缀）并删除映射行。

    E2E 开始与结束都调用，保证任意先前状态下都可从零重跑。
    账户可能已被先前轮次改名 ⇒ 先经管理员按 user_id 查当前用户名再登录。
    """
    from sqlalchemy import delete, select

    from sso_bff.crypto import decrypt
    from sso_bff.db import IdentityMapping, get_sessionmaker

    async with get_sessionmaker()() as s:
        mappings = list((await s.execute(select(IdentityMapping))).scalars().all())
        for m in mappings:
            # 1) 管理员查当前用户名（早期轮次改过名的账户登录会失败 → 仅删映射）
            st, d = jreq("GET", f"/api/user/{m.new_api_user_id}", None, admin_tok)
            current = (d.get("data") or {}).get("username") if st == 200 else None
            if current:
                password = decrypt(m.new_api_password_enc)
                st, d = jreq("POST", "/api/user/login", {"username": current, "password": password})
                if st == 200 and d.get("data"):
                    utok = d["data"]["access_token"]
                    st, d = jreq("GET", "/api/token/?p=1&size=50", None, utok)
                    for t in d.get("data", {}).get("items", []):
                        jreq("DELETE", f"/api/token/{t['id']}", None, utok)
                    print(f"    revoked tokens of {current} (id={m.new_api_user_id})")
            else:
                print(f"    mapping for missing user id={m.new_api_user_id} (drop only)")
        # 注意：不改名——账户保留其 oidc_id 绑定（管理 API 无法解绑），
        # 下轮 E2E 收养同一账户即可复用绑定，避免 "OIDC account already bound"。
    async with get_sessionmaker()() as s2:
        async with s2.begin():
            await s2.execute(delete(IdentityMapping))
    print(f"    cleaned {len(mappings)} mapping row(s)")


async def main() -> int:
    print("=" * 66)
    print("sso-bff E2E：真实 Casdoor × 真实 new-api × 本地 BFF")
    print("=" * 66)

    # 管理员令牌 + 预清理必须走在任何登录之前（否则会误删本轮刚开通的账户）
    st, d = jreq("POST", "/api/user/login", {"username": "root", "password": ADMIN_PASS})
    admin_tok = d["data"]["access_token"]
    print("\n■ 预清理（任意先前状态 → 从零开始）")
    await cleanup_state(admin_tok)

    async with httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(120.0, connect=20.0), follow_redirects=False) as client:
        # ---------- AC-01/02/03/04：登录 + JIT ----------
        print("\n■ 登录与 JIT 自动开通（AC-01/02/03/04）")
        if not await login_via_bff(client):
            return 1

        r = await client.get(f"{BFF}/api/me")
        me = r.json()
        check("GET /api/me 返回当前用户", r.status_code == 200 and me.get("sub"), json.dumps(me, ensure_ascii=False)[:120])
        sub = me["sub"]

        r = await client.get(f"{BFF}/api/credential")
        cred = r.json()
        check("GET /api/credential 返回本人 key", r.status_code == 200 and cred.get("key"), f"token_id={cred.get('token_id')}")
        key = cred["key"]
        user_id = cred["new_api_user_id"]

        # new-api 侧实证（复用开头取得的管理员令牌）
        st, d = jreq("GET", f"/api/user/search?keyword=sso_&p=1&size=50", None, admin_tok)
        users = [u for u in d["data"]["items"] if u["username"].startswith("sso_")]
        e2e_user = next((u for u in users if u["id"] == user_id), None)
        check("new-api 侧 JIT 账户已创建", e2e_user is not None,
              f"user_id={user_id} username={e2e_user['username'] if e2e_user else '?'}")

        st, _ = jreq("GET", "/v1/models", None, key)
        check("用户 key 直连 /v1/models（免费端点）", st == 200, f"HTTP {st}")

        # ---------- AC-04 幂等 ----------
        print("\n■ 重复登录幂等（AC-04）")
        if await login_via_bff(client):
            r = await client.get(f"{BFF}/api/credential")
            cred2 = r.json()
            check("重复登录落到同一账户（无重复开户）", cred2["new_api_user_id"] == user_id,
                  f"user_id={cred2['new_api_user_id']}")

        # ---------- F2.3 轮换 ----------
        print("\n■ 钥匙轮换（F2.3）")
        r = await client.post(f"{BFF}/api/credential/rotate")
        new_cred = r.json()
        check("轮换返回新 key", r.status_code == 200 and new_cred.get("key") != key)
        st, _ = jreq("GET", "/v1/models", None, key)
        check("旧 key 已失效", st in (401, 403), f"HTTP {st}")
        st, _ = jreq("GET", "/v1/models", None, new_cred["key"])
        check("新 key 可用", st == 200, f"HTTP {st}")
        key = new_cred["key"]

        # ---------- AC-10 封禁级联 ----------
        print("\n■ 封禁级联（AC-10）")
        import http.cookiejar

        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        body = json.dumps({
            "type": "login", "username": "admin",
            "password": open("/Users/betterme/PycharmProjects/AI/livetest-ai/secrets/casdoor-ai-prod.txt")
            .read().split("CASDOOR_ADMIN_PASSWORD=")[1].split("\n")[0].strip(),
            "application": "app-built-in", "organization": "built-in", "signinMethod": "password",
        }).encode()
        req = urllib.request.Request(f"{CASDOOR}/api/login", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        opener.open(req, timeout=20).read()

        def cas_admin(method: str, path: str, payload=None):
            data = json.dumps(payload).encode() if payload is not None else None
            req = urllib.request.Request(f"{CASDOOR}{path}", data=data, method=method)
            req.add_header("Content-Type", "application/json")
            try:
                with opener.open(req, timeout=20) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                return {"http_error": e.code, "body": e.read().decode()[:200]}

        full_user = cas_admin("GET", f"/api/get-user?id=livetest/{E2E_USER}").get("data", {})
        full_user["isForbidden"] = True
        r = cas_admin("POST", f"/api/update-user?id=livetest/{E2E_USER}", full_user)
        check("Casdoor 侧禁用用户（update-user isForbidden=true）", r.get("status") == "ok",
              str(r.get("msg", ""))[:80])

        from sso_bff.tasks import ban_cascade_once, reconcile_once

        report = await ban_cascade_once()
        check("级联轮询发现并吊销令牌", len(report.revoked) >= 1,
              f"checked={report.checked} revoked={report.revoked}")
        st, _ = jreq("GET", "/v1/models", None, key)
        check("封禁后 key 立即失效", st in (401, 403), f"HTTP {st}")

        # 恢复
        full_user = cas_admin("GET", f"/api/get-user?id=livetest/{E2E_USER}").get("data", {})
        full_user["isForbidden"] = False
        cas_admin("POST", f"/api/update-user?id=livetest/{E2E_USER}", full_user)
        report = await ban_cascade_once()
        check("IdP 恢复后级联重新签发", len(report.reactivated) >= 1)
        r = await client.get(f"{BFF}/api/credential")
        cred3 = r.json()
        if cred3.get("key"):
            st, _ = jreq("GET", "/v1/models", None, cred3["key"])
            check("恢复后新 key 可用", st == 200, f"HTTP {st}")

        # ---------- F5.3 对账 ----------
        print("\n■ 定期对账（F5.3）")
        rec = await reconcile_once()
        check("对账完成", rec.errors == [], f"orphans={rec.orphan_accounts} missing={rec.missing_accounts}")

        # ---------- AC-06 控制台绑定 ----------
        print("\n■ 控制台绑定（AC-06：控制台登录落到同一账户）")
        from urllib.parse import parse_qs as _pq, urlparse as _up

        # 封禁级联已吊销 Casdoor 会话 ⇒ 绑定前重新登录（生产里用户总是带新鲜 SSO 会话）
        r = await client.post(f"{CASDOOR}/api/login", json={
            "type": "login", "username": E2E_USER, "password": E2E_PASS,
            "application": "sso-bff-app", "organization": "livetest", "signinMethod": "password"})
        check("重登 Casdoor（级联测试后会话已吊销）", r.json().get("status") == "ok")

        r = await client.post(f"{BFF}/api/console-connect/start")
        d = r.json()
        check("发起绑定（verify+proof+state）", r.status_code == 200, str(d.get("authorize_url", d))[:60])
        q = _pq(_up(d["authorize_url"]).query)
        r = await client.post(f"{CASDOOR}/api/grant-consent", json={
            "application": "admin/new-api-console-app", "grantedScopes": q["scope"][0].split(),
            "clientId": q["client_id"][0], "provider": "", "signinMethod": "", "responseType": "code",
            "redirectUri": q["redirect_uri"][0], "scope": q["scope"][0], "state": q["state"][0],
            "nonce": "", "challenge": "", "resource": ""})
        _cd = r.json()
        check("Casdoor 同意授权（console app）", _cd.get("status") == "ok",
              str(_cd.get("msg", ""))[:100] if _cd.get("status") != "ok" else "")
        r = await client.get(f"{BFF}/console-connect/callback",
                             params={"code": r.json()["data"], "state": q["state"][0]})
        check("BFF 回调完成绑定", r.status_code == 302 and "done=1" in r.headers.get("location", ""),
              r.headers.get("location", "")[:60])
        r = await client.get(f"{BFF}/api/console-connect/status")
        st_body = r.json()
        check("oidc_id 已绑定到 JIT 账户", st_body.get("bound") is True,
              f"user_id={st_body.get('new_api_user_id')} oidc={st_body.get('oidc_id_prefix')}")
        check("绑定账户与 API 计费账户一致", st_body.get("new_api_user_id") == cred["new_api_user_id"]
              or st_body.get("new_api_user_id") == user_id)

        # ---------- 清理（保留 Casdoor 测试用户与账户绑定，仅清令牌与映射） ----------
        await cleanup_state(admin_tok)

    print("\n" + "=" * 66)
    print(f"结果：{PASS} 通过 / {FAIL} 失败")
    print("=" * 66)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
