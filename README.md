# sso-bff —— 多应用统一认证与计费打通

> 按《多应用统一认证与计费打通PRD》构建的 **BFF 身份服务**（仓库命名遵循 PRD 附录 A.3）。
> 架构：**Casdoor 统一认证 × sso-bff 身份服务 × new-api 计费到人**，模型流量前端直连。

## 状态：核心链路已在真实环境端到端验证 ✅

| 能力 | 验证 |
|---|---|
| OIDC 登录（授权码 + PKCE，真实 Casdoor v4.20.0） | ✅ E2E |
| JIT 自动开通（建 new-api 用户 + 签发专属 key，幂等、无半成品） | ✅ E2E |
| 前端直连 `/v1/models`（Bearer key，计费到人） | ✅ E2E（免费端点） |
| 重复登录幂等（同 sub 同账户） | ✅ E2E |
| 钥匙轮换（作废旧 key、签发新 key） | ✅ E2E |
| 封禁级联（Casdoor 禁用 → 分钟级轮询 → 吊销令牌 → API 即时中断；恢复自动重签） | ✅ E2E |
| 定期对账（孤儿账户/失效 key/差异报告） | ✅ E2E |
| 控制台绑定（AC-06：`oidc_id` 落到 JIT 同一账户，无双胞胎） | ✅ 实测 |
| new-api 控制台 OIDC（W4：指向同一 Casdoor） | ✅ 已启用 |

复跑验证：`python scripts/e2e_test.py`（22 项断言，需 .env 就绪）。

## 快速开始

```bash
python -m venv venv && source venv/bin/activate
pip install -e .[dev]
cp .env.example .env           # 按环境填写（含 new-api 管理员口令、Casdoor client_secret）
redis-server &                 # 或指向已有 Redis
uvicorn sso_bff.main:app --host 127.0.0.1 --port 8800
# 浏览器打开 http://localhost:8800/demo
```

初始化（幂等，可重复执行）：

```bash
python scripts/setup_casdoor.py        # F1.1：组织 livetest + sso-bff-app + new-api-console-app
python scripts/setup_newapi_oidc.py    # W4：new-api OIDC 选项指向 Casdoor
```

## 接口（PRD 5.1 契约）

| 端点 | 说明 |
|---|---|
| `GET /auth/login?redirect=` | 发起登录，302 跳 Casdoor |
| `GET /auth/callback` | 回调：换票、验签（state/nonce/PKCE）、建会话（Redis + HttpOnly Cookie）、JIT 开通、回跳 |
| `POST /auth/logout` | 清 BFF 会话并跳 Casdoor 注销 SSO |
| `GET /api/me` | 当前用户（昵称 / 手机号掩码 / 头像） |
| `GET /api/credential` | 本人 key + 过期时间（仅本人；日志脱敏） |
| `POST /api/credential/rotate` | 轮换 key |
| `GET /console-connect` | 控制台绑定引导页 |
| `POST /api/console-connect/start` | 发起绑定，返回 Casdoor authorize URL |
| `GET /console-connect/callback` | 绑定回调（Casdoor 302 落回，服务端完成 new-api 绑定） |
| `GET /api/console-connect/status` | 绑定状态（核对 new-api `oidc_id`） |
| `GET /healthz` / `/readyz` | 存活 / 就绪 |

## 架构

```
浏览器 ──/auth/login──> sso-bff ──OIDC──> Casdoor（微信扫码 / 手机验证码 / 密码）
浏览器 <─Cookie──── sso-bff <─code────── Casdoor
       │
       ├─ JIT：new-api 建用户(sso_xxx) + 以该用户身份发 sk-key ──> identity_mapping（Fernet 密文）
浏览器 ──/api/credential──> key（仅内存，禁 localStorage）
浏览器 ──Bearer key──> new-api /v1/*（直连，按 key 归属计费到人）
       │
       └─ 控制台：/console-connect 绑定 oidc_id ──> 控制台 OIDC 登录落到同一账户
后台任务：封禁级联（分钟轮询 Casdoor isForbidden → 吊销令牌）、定期对账（孤儿/失效 key 报告）
```

## 与 PRD 的关键偏差（均为对 new-api v1.0.0-rc.42 的实证适配）

1. **`oidc_id` 不能由管理 API 写入**：`CreateUser`/`UpdateUser` 均白名单丢弃该字段，只有 new-api 自己的 OAuth 流程能写。
   → **控制台绑定模块**（`/console-connect`）：BFF 以用户身份走 new-api 原生 OAuth **bind** 流程
   （密码重验拿 proof → `POST /api/oauth/state` bind → Casdoor 静默授权 → BFF 回调完成绑定）。
   关键机制：Casdoor 换票**不校验 redirect_uri**（实证），故码可落回 BFF 自己的回调、由 new-api 正常兑换。
2. **rc.42 管理操作要求安全验证**（`ManageUser` disable/enable/delete、删用户均需 `X-Security-Proof`）：
   → 封禁级联改为**吊销该用户全部令牌**（`DeleteToken` 免验证，API 访问即时中断），效果等价。
3. **该部署 key 为 48 位裸串**（非 `sk-` 前缀）：代码不假设前缀。
4. **new-api OIDC `GetUserInfo` 强制 email 非空**：扫码/手机用户无邮箱 ⇒ JIT 时为无邮箱的 Casdoor
   用户补确定性占位邮箱（`sso-<sub8>@users.1task.cn`）。
5. **Casdoor 应用必须设 `expireInHours`**（=0 时 access token 立即过期，userinfo 报
   `Access token has expired`）。setup 脚本已固化 168h/720h。
6. **WeChat 扫码 / 手机验证码**：Casdoor Provider 已就位，但需企业主体微信开放平台资质与短信签名
   审核（PRD 11.1 外部依赖）——当前以密码登录态做结果等价验证，Provider 配好后零代码切换。

## 数据与安全

- `identity_mapping`：`casdoor_sub`(唯一锚点) / `new_api_user_id` / `new_api_token_id` /
  `new_api_key_enc`(Fernet) / `new_api_password_enc`(Fernet，HMAC 派生) / `status` / 审计字段。
- key 与口令全链路加密落库；日志过滤器对 key/JWT/Fernet 自动打码；响应仅本人可取。
- 会话：Redis 服务端会话，浏览器仅持 HttpOnly+Secure(prod)+SameSite=Lax Cookie；
  IdP 令牌只存服务端并加密。
- JIT 并发锁（Redis）、失败无半成品、孤儿账户自动收养（口令由 crypto_key+sub 确定性派生）。
- 计费纪律：仓库内所有验证只调 `/v1/models` 免费端点，不做模型生成调用。

## 仓库结构

```
sso_bff/            # 应用本体（config/crypto/db/sessions/oidc/newapi/jit/tasks/console_connect/main）
mock_idp/           # 本地 OIDC IdP（无 Casdoor 时的开发替身，含管理端禁用接口）
demo/index.html     # F3 演示 SPA（key 只进内存、直连 /v1/models、控制台绑定入口）
scripts/            # setup_casdoor / setup_newapi_oidc / e2e_test（22 断言）
deploy/             # systemd / nginx / docker-compose / Dockerfile
tests/              # pytest 单元测试
```

## 已知限制 / 后续

- **W1 微信/短信 Provider**：待企业资质与短信签名审核（Casdoor 侧配置，BFF 零改动）。
- **用户删除**：new-api 管理 API 删除需安全验证（root 未登记 2FA/passkey/email），BFF 不做删除，
  封禁用令牌吊销；控制台可人工禁用账户。
- **多前端应用**：PRD F1.1 每应用独立 Application——在 Casdoor 复制 `sso-bff-app` 模式注册即可，
  BFF 回调白名单已在 `sso-bff-app` 预置 `https://sso.1task.cn/auth/callback`。
- 部署：`deploy/` 模板 + `ai-prod-service-deploy` 流程可一键上 `sso.1task.cn`。
