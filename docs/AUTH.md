# AUTH.md — 账号体系与后台管理（App 内注册 + 密码登录 + `/admin`）

> 文档版本：v2.2 · 2026-10-20 11:40 (GMT+8)
> **定稿策略：全系统 + App 只允许「邮箱 + 密码」，手机号与第三方登录一律拒绝。**
> 对应代码：`xiaoyan-cloud/auth.py`、`xiaoyan-cloud/admin_web.py`、`xiaoyan-cloud/cloud4.py`（`POST /users` + 登录分支）
> 解决：`REVIEW.md` 的 **P0 —— 认证形同虚设**（知道账号名就能冒充）

---

## 1. 一页速览

| 项 | 内容 | 谁用 |
|---|---|---|
| 注册 | **小燕 App 登录页 → 「注册」**（填邮箱 + 自选密码） | 普通用户 |
| 登录 | App 登录页 → 邮箱 + 密码 | 普通用户 |
| 改密码 | App「我的」→「修改密码」（`PATCH /users/<uid>/password`） | 普通用户 |
| 后台 | `https://api.example.com/admin` | **只有管理员** |
| 密码存储 | `accounts.json`，PBKDF2-HMAC-SHA256 / 12 万轮 / 每账号独立盐 | — |
| 后台密码 | `admin.json`，首次启动生成 20 位随机密码（`admin_initial.txt`） | — |
| 数据文件 | `accounts.json`、`admin.json`、`admin_initial.txt`、`tokens.json`（全部 600） | — |
| 支持范围 | **只有邮箱 + 密码**；手机号 / 验证码 / 微信 / Google / Apple / QQ 全部拒绝 | — |

> ⚠️ **没有网页注册**。早期版本做过 `/register` 页面，按用户要求改成完全走 App 自带注册流程，该页面已删除。

---

## 2. 为什么做这一版

之前 `/users/authenticate` 来者不拒：不校验密码、不校验验证码，请求里带个账号名就发 token。
实测（2026-10-20 复盘）用 `credential:"完全瞎写的密码xyz"` 就登进了 `guest@example.com` 并看到它的 1 台网关。

也就是说 **知道账号名 = 完整冒充**。现在改成：账号必须在 App 里注册、密码必须对。

---

## 3. App 的注册流程（真机实测，2026-10-20 11:00）

App 落地页有三个按钮：`登录` / `局域网登录` / `注册`。点「注册」后：

1. 填 **手机号码/邮箱** →（输入框失去焦点后才会出现）**密码** 输入框
2. 勾选「我已阅读并同意《小燕隐私协议》」→「确定」变成可点
3. 点「确定」→ App 发 `POST /users`：

```json
{"id_type":"email", "id":"<邮箱>", "credential":"<用户自设密码>",
 "verification_code_id":"<邮箱本身>"}
```

4. 服务端建账号（`accounts.json`）→ 返回 `status_code: 20000`
5. App **紧接着自动登录**：`POST /users/authenticate`，`credential` = 刚才那个密码，
   `verification_code_id: null` → 密码校验通过 → 拿 token
6. App 继续 `PATCH /users/<uid>/name`、`/ws/mqtt`、`/users/~/roster`、`/users/<uid>/notification`
7. 新账号没有任何家庭中心 → App 显示「添加家庭中心」

实测日志（`cloud4.log`）：

```
10:54:17 HTTP POST /users      body={id_type:email, id:appui1@test.com, credential:appui12345, verification_code_id:appui1@test.com}
10:54:17 -> 注册 200 uid='appui1@test.com'
10:54:17 HTTP POST /users/authenticate  body={...credential:appui12345, verification_code_id:null}
10:54:17 -> authenticate 200 user='appui1@test.com'
10:54:19 HTTP GET /users/~/roster     → 空列表 → App 进「添加家庭中心」
```

### `POST /users` 的判定

| 情况 | 结果 |
|---|---|
| 格式合法（邮箱 / 11 位手机号）+ 密码≥8 位 + 未注册 | ✅ `20000`，账号写入 `accounts.json` |
| 账号已存在 | ❌ `40100`「该账号已注册，请直接登录」 |
| 密码不足 8 位 | ❌ `40100`「密码至少 8 位」 |
| 账号格式不对 | ❌ `40100`「账号格式不对」 |
| 同一 IP 10 分钟内 ≥8 次 | ❌ `40100`「操作太频繁」 |

> `verification_code_id` 在注册请求里是**邮箱本身**（不是 vc- id），服务端不校验它 ——
> 本服务器没有短信/邮件通道，注册的「账号归属」靠域名不公开 + IP 限速来守；密码才是真正的门禁。

---

## 4. 登录判定（`/users/authenticate`）

| 情况 | 结果 |
|---|---|
| 账号存在 + 密码正确（`verification_code_id` 为空） | ✅ `20000` + token |
| 密码错 | ❌ `40100` |
| 账号存在 + 带 `verification_code_id`（验证码登录） | ❌ `40100`「请改用密码登录」 |
| 未注册 / 没设密码 | ❌ `40100`「请先到 App 注册」 |
| 账号被停用 | ❌ `40100` |
| 同 IP 10 分钟内失败 ≥8 次 | ❌ `40100` 限速（先于密码计算，防 PBKDF2 被刷） |

### ⚠️ 只允许邮箱（2026-10-20 用户定稿）

App 对**邮箱**给密码框，对**手机号**只给「获取验证码」。我们没有短信通道，验证码发不出去，
所以手机号账号注册完就再也登不进来。与其留一堆「能注册、不能登录」的死账号，
不如从服务端直接堵死：

| 入口 | 行为 |
|---|---|
| 手机号登录 | `40100`「本服务器只支持邮箱登录，请用邮箱账号」（在密码校验之前就拒，不做 PBKDF2 计算） |
| 手机号注册 | `40100`「本服务器只支持邮箱登录，请填邮箱（手机号收不到验证码）」 |
| 验证码登录（任何账号） | `40100`「本服务器只支持邮箱+密码登录，不发验证码」 |
| 微信 / Google / Apple / QQ 登录 | 这些路径最终都打 `/users/authenticate`，账号不含 `@` → 同样 `40100` |

代码落点：`auth.EMAIL_ONLY` / `auth.uid_problem()` / `cloud4.py` 登录分支的 `"@" not in who` 判断。
后台「新建账号」也走同一套校验，只能填邮箱。

---

## 5. 账号模型

`accounts.json`（**用后台改，别手工编辑**）：

```jsonc
{
  "_readme": "账号 -> 密码哈希（PBKDF2-SHA256）…",
  "owner@example.com": {
    "pw": "pbkdf2_sha256$120000$<salt>$<digest>",
    "created": 1792466400, "last_login": 1792467000,
    "nickname": "owner@example.com", "enabled": true, "must_change": false
  }
}
```

与 `tenants.json` 分工：
- `accounts.json` → 能不能登录
- `tenants.json` → 登录后能看到哪几台网关（会被自动认领 / 后台改写）

---

## 6. 后台 `/admin`（只给管理员）

| Tab | 能干什么 |
|---|---|
| 概览 | 账号数 / 已归属家庭中心 / 在线网关 / 未认领网关 + 网关状态表 |
| 账号 | **新建账号、改密、删除、解绑**；把网关绑定给账号 |
| 网关 | 在线状态、公网 IP、归属、**锁定**（不参与自动认领）、改名 |
| 设置 | 自动认领开关 / 时间窗口 / 保留列表、改管理员密码、后台来源 IP 限制 |
| 日志 | `cloud4.log` 最近 300 行 |

安全：写操作全校验 CSRF；会话 Cookie `HttpOnly` + `SameSite=Strict`（8 小时，存内存）；
密码错误按 IP 限速；`admin.json` 可配 `"ip_allow": ["1.2.3.4"]` 只允许指定 IP 进后台。

### 初始密码

```bash
ssh root@203.0.113.10 "cat /opt/xiaoyan-cloud/admin_initial.txt"
```

登录后到「设置」改掉，然后 `rm /opt/xiaoyan-cloud/admin_initial.txt`。
忘了密码：删掉 `admin.json` 里的 `pw` 字段并重启，会重新生成。

---

## 7. 改密码（App「我的 → 修改密码」）

App 发的是 **`PATCH /users/<uid>/password`**（不是 POST，早期只放行 POST 时被 404 挡掉了）：

```json
{"username":"owner@example.com", "current_password":"旧", "new_password":"新"}
```

- 字段名兼容 `current_password` / `old_password` / `oldPassword` / `credential`
- 已有密码时必须给对旧密码，否则 `40100`
- 实测：改成 `xxx8` 后旧密码立即 `40100`、新密码 `20000`（已改回）

---

## 8. token 持久化（顺带修的一个坑）

`TOKENS`（access token → uid）原本只在内存。服务一重启，App 手里那个 token 就还原不出 uid
→ `roster` 返回空列表 → **首页变空**，而且 App 不会自己重新认证。

现在写 `tokens.json`（600，最多 800 条），启动时加载。实测：登录 → 重启服务 → 同一 token 取 roster 仍 1 台。

> 另外身份解析还有一层「来源 IP 短期记忆」，**做测试时注意它会串**：
> 我从本机（与手机同一公网 IP）用 `test@test.com` 登录过几次，
> 手机 App 的旧 token 就被解析成了 `test@test.com`。调试完记得确认 App 里显示的是谁的账号。

---

## 8.5 App 界面文案已对齐（2026-10-20，`patch_text.py`）

中文在 Dart 快照里是 **TwoByteString（UTF-16LE，每字 2 字节）**，所以只能做**字符数完全一致**的替换 ——
字数相同就是纯字节覆盖，长度头不动，快照结构零改动（和改主机名同一安全等级）。

| 位置 | 原文案 | 现文案 |
|---|---|---|
| 登录/注册输入框 | 请输入手机号码/邮箱 | 请输入完整的邮箱地址 |
| 注册页说明 | ，未注册的手机号将自动创建账号 | ，未注册的新邮箱会自动创建账号 |
| 手机号输入后 | 目前仅支持中国地区手机号 | 目前仅支持邮箱账号登录。 |
| 重复注册报错 | 手机号已被绑定至其他账号 | 该邮箱已注册，请直接登录 |
| 校验失败 | 请输入正确的手机号或邮箱 | 请输入有效的邮箱地址即可 |
| 账号页状态 | 未绑定手机 | 未绑定邮箱 |
| 登录页第三方区标题 | 其它登录方式 | 已停用的方式 |

打包：`patch_text.py` 由 `repack/build_apk.sh` 的 `TEXT_PATCH`（默认 1）自动调用；
`python3 patch_text.py --dry-run <apk>` 可先看命中数。**字数不等会被脚本拒绝**（不做手术）。

仍然保留、但功能不可用的入口：

| 入口 | 现状 |
|---|---|
| 「忘记密码」 | 走验证码重置，本服务器不发码 → 实际不可用，改密码请用「我的 → 修改密码」或后台 |
| 第三方登录图标（微信/QQ/Google/Apple） | 服务端一律 `40100`，标题已改成「已停用的方式」 |
| 手机号「获取验证码」 | 服务端拒绝；输入框提示已引导用邮箱 |

---

## 9. 老账号迁移（一次性）

自注册上线前存在的账号没有密码，会被校验挡住。用服务器上的脚本补齐：

```bash
cd /opt/xiaoyan-cloud
python3 seed_accounts.py                 # 只补缺密码的
python3 seed_accounts.py --email-alias   # 额外给手机号账号建邮箱兜底账号
```

**2026-10-20 实际执行结果**（密码只打印过一次，这里记档）：

| 账号 | 密码 | 说明 |
|---|---|---|
| `owner@example.com` | `zWrezGtnbQw7` | **主账号**（手机 App 当前登录的），绑 3 台网关 |
| `guest@example.com` | `XyQ4a3CucuMq` | 朋友，1 台 |

迁移时还建过 `13800000000`（手机号）与 `test@test.com`（测试），
改成「只允许邮箱」后**两个都已删除**，它们的网关归属已并到 `owner@example.com`。
`accounts.json` 现在只有上面两个账号。

---

## 10. 待办 / 已知限制

| 项 | 说明 |
|---|---|
| 手机号 / 第三方登录 | **已按设计封死**（服务端拒绝），不是缺陷 |
| 忘记密码 | App 有「忘记密码」入口，但走的是验证码 → 实际不可用；只能管理员在后台改 |
| 注册无验证码 | 靠域名不公开 + IP 限速；理论上可被慢速刷垃圾账号，后台可删 |
| 账号停用 | `auth.set_enabled` 已实现，后台 UI 还没放按钮 |
| 会话不持久 | 后台会话在内存，服务重启后要重新登录（刻意的） |

---

## 11. 部署与回滚

```bash
scp xiaoyan-cloud/cloud4.py xiaoyan-cloud/auth.py xiaoyan-cloud/admin_web.py \
    root@203.0.113.10:/opt/xiaoyan-cloud/
ssh root@203.0.113.10 "cd /opt/xiaoyan-cloud \
  && python3 -m py_compile cloud4.py auth.py admin_web.py \
  && systemctl restart xiaoyan-cloud"
```

回滚：`cloud4.py.bak.<ts>` 在同目录；若 `import auth, admin_web` 失败，
`cloud4.py` 会自动降级（`HAS_WEB=False`）并打日志
`⚠ auth 模块未加载，登录校验被跳过` —— **回滚后务必确认没有这行**。

> 回滚会让认证退回「不校验」状态，只应作为临时手段。

---

## 12. 验收清单（本次实测结果）

| 用例 | 期望 | 实测 |
|---|---|---|
| **App 内注册（邮箱 + 自选密码）** | 建号 + 自动登录 + 进「添加家庭中心」 | ✅ 真机跑通 |
| App 自动登录（注册后） | 20000 | ✅ `credential` = 自设密码 |
| App 修改密码（PATCH） | 旧密码失效、新密码生效 | ✅ |
| 正确密码登录 | 20000 + 应得网关（3 / 1 台） | ✅ |
| 瞎写密码 | 40100 | ✅ |
| 验证码登录 | 40100 | ✅ |
| 未注册邮箱 | 40100 | ✅ |
| **手机号登录** | 40100「只支持邮箱登录」 | ✅ |
| **手机号注册** | 40100「请填邮箱」 | ✅ |
| 第三方登录（微信/Google/Apple/QQ） | 40100 | ✅（账号不含 @） |
| 重复注册 / 弱密码 / 格式错 | 40100 + 中文原因 | ✅ |
| 后台登录 + 五页渲染 | 200 | ✅ |
| 后台建号/改密/删号/改设置 | 302 + 落盘 | ✅ |
| CSRF 错误 | 拒绝 | ✅ |
| 服务重启后 App 身份不丢 | `tokens.json` 生效 | ✅ |
