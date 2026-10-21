# ADMIN_UI.md —— 管理后台前端（SPA）架构与 API 契约

> 2026-10-21 建立。后台从「纯服务端渲染」升级为 **SPA + JSON API**，旧页面保留为 classic 兜底。
> 前端三件套在 `xiaoyan-cloud/admin_assets/`（index.html / app.css / app.js，零依赖原生 JS）。
> 路由入口仍是 `https://api.example.com/admin`，未登录时也返回 SPA 外壳（JS 内渲染登录页）。

---

## 1. 路由总览（全部由 cloud4.py 转给 admin_web.handle）

| 路径 | 方法 | 鉴权 | 说明 |
|---|---|---|---|
| `/admin` | GET | 无（外壳不含数据） | SPA 外壳 index.html；`?ui=classic` 仍渲染旧服务端页面 |
| `/admin/classic` | GET | 会话 | 302 → `/admin?ui=classic` |
| `/admin/login` | GET/POST | — | 旧版登录页/表单登录（兜底，保留） |
| `/admin/logout`、`/admin/logout-form` | GET/POST | — | 旧版登出（兜底，保留） |
| `/admin/do` | POST | 会话 + 表单 csrf | 旧版表单写操作（兜底，保留） |
| `/admin/assets/<file>` | GET | 无 | 静态资源，**白名单**：仅 index.html / app.css / app.js |
| `/admin/api/login` | POST | IP 限速 | 登录，Body `{"pw":"..."}` |
| `/admin/api/logout` | POST | 会话 + CSRF 头 | 登出 |
| `/admin/api/whoami` | GET | 会话 | `{"ok":true,"csrf":"..."}`；无会话 401（SPA 启动探活用） |
| `/admin/api/snapshot` | GET | 会话 | 脱敏快照（见 §3） |
| `/admin/api/logs?n=300` | GET | 会话 | `{"ok":true,"text":"...","lines":[...]}`，n 钳制 50–2000 |
| `/admin/api/do` | POST | 会话 + `X-CSRF-Token` 头 | 写操作，见 §4 |

**统一约定**：`/admin/api/*` 一律返回 JSON，**从不重定向**；失败统一 `{"ok":false,"err":"..."}`。
IP 白名单（admin.json `ip_allow`）对 API 与页面同样生效，API 路径返回 JSON 403。

## 2. 鉴权细节

- 会话 Cookie：`td_admin`，HttpOnly + SameSite=Strict + Secure，8 小时（与旧版一致）。
- CSRF：由 sid 派生（`sha256("csrf:"+sid)[:32]`），SPA 启动时经 `whoami` 取得，
  之后每个写请求带 `X-CSRF-Token` 头。旧表单的隐藏域 csrf 流程不变。
- 登录限速：`auth.throttled("admin:"+ip)`，与旧表单登录共用计数器。
- 静态资源不含任何数据，允许未登录加载（登录页自身需要 css/js）。

## 3. snapshot 脱敏（安全要点）

`/admin/api/snapshot` 在 `be.snapshot()` 基础上：
- **删掉 accounts 里的 `pw` 哈希**，只留 `{"enabled","last_login","nickname","has_pw"}`
- 追加 `ip_allow`（来自 admin.json）

## 4. do 动作契约（与旧表单一一对应，`do_action()` 单实现）

| action | 字段 | 说明 |
|---|---|---|
| `acct_create` | uid, pw | 建账号（仅邮箱，≥8 位） |
| `acct_pw` | uid, pw | 改密码 |
| `acct_del` | uid | 删账号 + 清归属 |
| `acct_bind` / `acct_unbind` | uid, hc | 绑定/解绑家庭中心 |
| `gw_reserve` / `gw_unreserve` | hc | 保留列表开关 |
| `gw_rename` | hc, name | 网关改名 |
| `set_all` | auto_claim(bool\|"1"/"0"), claim_window(分钟, ""=不限), reserved(文本) | 认领设置 |
| `admin_pw` | old, pw | 改管理员密码 |
| `admin_ip` | ip_allow(字符串或数组) | 后台 IP 白名单 |

`auto_claim` 同时接受布尔与 "1"/"0" 字符串（表单/JSON 双兼容，`_as_bool` 归一化）。

## 5. SPA 说明（app.js，766 行，原生 JS）

- hash 路由：`#/overview` `#/accounts` `#/gateways` `#/settings` `#/logs`；兼容旧表单跳转的 `?tab=`/`?msg=`/`?err=`
- 五个视图 + 登录视图；概览 5s / 日志 3s 自动刷新（页面隐藏时暂停），`destroy()` 清定时器
- 交互：Toast、确认/输入模态框（Esc/遮罩关闭）、账号与网关搜索过滤、按钮 busy 态、空态
- 响应式：≥900px 侧栏常驻；<900px 侧栏转抽屉 + 顶栏汉堡；<720px 表格转堆叠卡片（`td::before` 显示 data-label）
- 安全：所有插值经 `esc()`；日志用 `textContent` 渲染；无任何外部 CDN/字体依赖

## 6. 排障

- 想用旧界面：`https://api.example.com/admin?ui=classic`（或任一页 Classic 链接）
- API 401 `未登录`：会话过期，SPA 会自动跳登录页
- API 403 `CSRF 校验失败`：刷新页面（whoami 会重新取 token）
- 改了 app.js/css 后浏览器仍旧：响应头是 `no-store`，强制刷新即可；确认 `/admin/assets/app.js` 返回 200 且 `application/javascript`
