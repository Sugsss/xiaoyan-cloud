# -*- coding: utf-8 -*-
"""
家庭云 Web 后台 + 自助注册页（纯 stdlib，Python 3.6 兼容）
==========================================================
两个入口，都由 cloud4.py 的 HTTP 分支转进来：

  GET  /admin        管理后台：概览 / 账号 / 网关 / 设置 / 日志

鉴权：
  · 后台用一个独立的 admin.json 存**管理员密码的哈希**
    （首次启动自动生成 20 位随机密码，写进日志和 admin_initial.txt，chmod 600）
  · 登录后发 HttpOnly + SameSite=Strict 的会话 Cookie，默认 8 小时过期
  · 所有写操作都校验 CSRF（会话内随机 token）
  · 密码错误按 IP 限速（复用 auth.throttled / note_fail）
  · admin.json 里可配 "ip_allow": ["1.2.3.4"] 只允许指定 IP 进后台（默认不限制）

约定：
  · handle() 只负责「渲染 + 表单解析」，数据读写全部委托给 be（cloud4 注入）与 auth。
  · 返回 (status:int, headers:dict, body:bytes)，由 cloud4 原样写回 socket。
"""
import html
import json
import os
import secrets
import threading
import time

import auth

BASE = os.path.dirname(os.path.abspath(__file__))
ADMIN_FILE = os.environ.get("ADMIN_FILE", os.path.join(BASE, "admin.json"))
INITIAL_PW_FILE = os.path.join(BASE, "admin_initial.txt")

COOKIE = "td_admin"
SESSION_TTL = 8 * 3600

_LOCK = threading.Lock()
_SESSIONS = {}       # sid -> {"exp": ts}
_CFG = None


# ============================================================ 管理员口令
def _hash(pw):
    return auth.hash_pw(pw)


def load_cfg(force=False):
    global _CFG
    with _LOCK:
        if _CFG is not None and not force:
            return _CFG
        cfg = {}
        if os.path.exists(ADMIN_FILE):
            try:
                cfg = json.load(open(ADMIN_FILE, encoding="utf-8")) or {}
            except Exception:
                cfg = {}
        _CFG = cfg
        return _CFG


def save_cfg():
    with _LOCK:
        try:
            tmp = ADMIN_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(_CFG or {}, f, ensure_ascii=False, indent=2)
                f.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, ADMIN_FILE)
            return True
        except Exception as e:
            auth.log("写 %s 失败: %s" % (ADMIN_FILE, e))
            return False


def ensure_admin():
    """首次运行生成随机管理员密码。返回 (generated_password or None)。"""
    cfg = load_cfg()
    if cfg.get("pw"):
        return None
    pw = auth.gen_password(20)
    cfg["pw"] = _hash(pw)
    cfg["created"] = int(time.time())
    cfg.setdefault("ip_allow", [])
    save_cfg()
    try:
        with open(INITIAL_PW_FILE, "w", encoding="utf-8") as f:
            f.write("小燕家庭云 · 后台初始密码\n"
                    "地址: https://api.example.com/admin\n"
                    "密码: %s\n"
                    "登录后请到「设置」里改掉，并删除本文件。\n" % pw)
        os.chmod(INITIAL_PW_FILE, 0o600)
    except Exception:
        pass
    auth.log("★ 已生成后台初始密码（见 %s）" % INITIAL_PW_FILE)
    return pw


def check_admin_pw(pw):
    cfg = load_cfg()
    return auth.check_pw(pw, cfg.get("pw", ""))


def set_admin_pw(pw):
    bad = auth.pw_problem(pw)
    if bad:
        return False, bad
    cfg = load_cfg()
    cfg["pw"] = _hash(pw)
    save_cfg()
    return True, "ok"


# ============================================================ 会话
def _new_session():
    sid = secrets.token_urlsafe(24)
    with _LOCK:
        _SESSIONS[sid] = {"exp": time.time() + SESSION_TTL}
        # 顺手清理过期会话，会话表只在内存里，不清会慢慢变胖
        now = time.time()
        for k in [k for k, v in _SESSIONS.items() if v["exp"] < now]:
            _SESSIONS.pop(k, None)
    return sid


def _csrf(sid):
    # 由会话 id 派生，避免额外状态；换会话即换 token
    import hashlib
    return hashlib.sha256(("csrf:" + sid).encode()).hexdigest()[:32]


def _session(headers):
    raw = headers.get("cookie") or ""
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE and v:
            with _LOCK:
                s = _SESSIONS.get(v)
                if s and s["exp"] > time.time():
                    return v
            return None
    return None


# ============================================================ 小工具
def esc(s):
    return html.escape("" if s is None else str(s), quote=True)


def fmt_ts(ts):
    if not ts:
        return "—"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts)))
    except Exception:
        return str(ts)


def fmt_dur(sec):
    sec = int(sec or 0)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, sec = divmod(sec, 60)
    if d:
        return "%d天%d小时" % (d, h)
    if h:
        return "%d小时%d分" % (h, m)
    return "%d分%d秒" % (m, sec)


def parse_qs(qs):
    out = {}
    for part in (qs or "").split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        try:
            out[_unquote(k)] = _unquote(v)
        except Exception:
            pass
    return out


def _unquote(s):
    from urllib.parse import unquote_plus
    return unquote_plus(s)


def parse_body(body):
    if not body:
        return {}
    try:
        txt = body.decode("utf-8", "replace")
    except Exception:
        return {}
    if txt.lstrip().startswith("{"):
        try:
            d = json.loads(txt)
            return d if isinstance(d, dict) else {}
        except Exception:
            return {}
    return parse_qs(txt)


# ============================================================ JSON API（SPA 用）
# 约定：
#   · 所有 /admin/api/* 一律返回 JSON（不重定向），方便 fetch 统一处理
#   · 读接口要求会话；写接口 additionally 要求 X-CSRF-Token 头
#   · snapshot 必须脱敏：accounts 里的 pw 哈希绝不下发
#   · 业务逻辑与旧表单完全共用（do_action），不产生第二套实现
ASSETS_DIR = os.environ.get("ADMIN_ASSETS", os.path.join(BASE, "admin_assets"))
ASSET_TYPES = {
    "index.html": "text/html; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
}


def _json(obj, status=200, headers=None):
    h = {"Content-Type": "application/json; charset=utf-8"}
    if headers:
        h.update(headers)
    return status, h, json.dumps(obj, ensure_ascii=False).encode("utf-8")


def _json_body(body):
    try:
        d = json.loads(body.decode("utf-8")) if body else {}
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _as_bool(v, default=True):
    """表单传来的是 "1"/"0" 字符串，JSON 可能直接是布尔值 —— 统一归一化。"""
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "on", "yes")


def _sanitize_snapshot(snap):
    """去掉 accounts 里的 pw 哈希后再下发（SPA 只需要 has_pw 布尔值）。"""
    out = dict(snap or {})
    acc = {}
    for uid, a in (snap.get("accounts") or {}).items():
        a = a or {}
        acc[uid] = {
            "enabled": a.get("enabled", True),
            "last_login": a.get("last_login"),
            "nickname": a.get("nickname") or "",
            "has_pw": bool(a.get("pw")),
        }
    out["accounts"] = acc
    return out


def _serve_asset(name):
    """静态资源白名单：只允许三个确切文件名，防路径穿越。"""
    ct = ASSET_TYPES.get(name)
    if not ct:
        return 404, {}, b"not found"
    path = os.path.join(ASSETS_DIR, name)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return 404, {}, b"not found"
    return 200, {"Content-Type": ct}, data


def do_action(be, act, f):
    """执行一个后台写操作。返回 (msg, err)。
    旧表单 /admin/do 与新的 /admin/api/do 共用这一套，不写两遍。"""
    msg = "ok"
    err = ""
    if act == "acct_create":
        ok, m = auth.create(f.get("uid"), f.get("pw"), nickname=f.get("uid"))
        if ok:
            be.ensure_tenant(auth.normalize(f.get("uid")))
            msg = "账号 %s 已创建" % auth.normalize(f.get("uid"))
        else:
            err = m
    elif act == "acct_pw":
        ok, m = auth.set_password(f.get("uid"), f.get("pw"))
        msg, err = ("密码已更新", "") if ok else ("", m)
    elif act == "acct_del":
        uid = auth.normalize(f.get("uid"))
        auth.delete(uid)
        be.drop_tenant(uid)
        msg = "账号 %s 已删除" % uid
    elif act == "acct_bind":
        be.bind(auth.normalize(f.get("uid")), f.get("hc") or "")
        msg = "已绑定"
    elif act == "acct_unbind":
        be.unbind(auth.normalize(f.get("uid")), f.get("hc") or "")
        msg = "已解绑"
    elif act == "dev_unbind":
        # 2026-10-24 新增：指纹 TTL 改成永久后，这是唯一的主动吊销入口。
        # 不传 uid = 解绑这个指纹下的所有账号，并强制断开它当前的连接。
        n, k = be.dev_unbind(f.get("fp") or "", f.get("uid") or "")
        if not n:
            err = "没找到这条绑定（可能已经解绑过了）"
        else:
            msg = "已解绑 %d 条、强制断开 %d 个连接" % (n, k)
    elif act == "gw_reserve":
        be.set_reserved(f.get("hc") or "", True)
        msg = "已加入保留列表"
    elif act == "gw_unreserve":
        be.set_reserved(f.get("hc") or "", False)
        msg = "已从保留列表移除"
    elif act == "gw_rename":
        be.rename(f.get("hc") or "", f.get("name") or "")
        msg = "已改名"
    elif act == "set_all":
        ac = _as_bool(f.get("auto_claim"), True)
        raw = f.get("claim_window")
        raw = "" if raw is None else str(raw).strip()
        window = None
        if raw != "":
            try:
                window = float(raw) * 60
            except ValueError:
                err = "时间窗口要填数字（分钟），或留空"
        if not err:
            if raw == "0":
                window = 0.0
            res = [x.strip() for x in (f.get("reserved") or "").replace(",", "\n").split("\n")
                   if x.strip()]
            be.save_settings(ac, window, res)
            msg = "设置已保存"
    elif act == "admin_pw":
        if not check_admin_pw(f.get("old") or ""):
            err = "当前密码不对"
        else:
            ok, m = set_admin_pw(f.get("pw") or "")
            msg, err = ("管理员密码已更新（本次会话保留）", "") if ok else ("", m)
    elif act == "admin_ip":
        raw = f.get("ip_allow")
        if isinstance(raw, list):
            ips = [str(x).strip() for x in raw if str(x).strip()]
        else:
            ips = [x.strip() for x in (raw or "").replace("，", ",").split(",") if x.strip()]
        c = load_cfg()
        c["ip_allow"] = ips
        save_cfg()
        msg = "来源限制已保存"
    else:
        err = "未知操作"
    return msg, err


# ============================================================ 样式
CSS = """
:root{
  --bg:#f4f5f7; --panel:#fff; --ink:#1b1f24; --muted:#6b7480;
  --line:#e3e6ea; --brand:#2f6fed; --brand-soft:#eaf1ff;
  --ok:#12a150; --warn:#c9820a; --bad:#d93a3a;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif}
a{color:var(--brand);text-decoration:none}
a:hover{text-decoration:underline}
header.top{background:#fff;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:9}
.top-in{max-width:1080px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.brand{font-weight:700;font-size:15px;letter-spacing:.2px}
.brand span{color:var(--brand)}
nav{display:flex;gap:4px;flex:1;flex-wrap:wrap}
nav a{padding:6px 12px;border-radius:8px;color:var(--muted);font-weight:500}
nav a:hover{background:#f0f2f5;text-decoration:none}
nav a.on{background:var(--brand-soft);color:var(--brand)}
.who{color:var(--muted);font-size:12px}
main{max-width:1080px;margin:22px auto 60px;padding:0 20px}
h1{font-size:19px;margin:0 0 4px}
h2{font-size:15px;margin:26px 0 10px}
.sub{color:var(--muted);font-size:13px;margin:0 0 18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:18px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.kpi .k{color:var(--muted);font-size:12px;margin-bottom:6px}
.kpi .v{font-size:24px;font-weight:700;letter-spacing:-.3px}
.kpi .v small{font-size:12px;color:var(--muted);font-weight:500}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:600;font-size:12px;white-space:nowrap}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:#fafbfc}
.mono{font-family:var(--mono);font-size:12.5px}
.tag{display:inline-block;padding:1px 7px;border-radius:6px;font-size:11.5px;font-weight:600}
.tag.ok{background:#e6f7ee;color:var(--ok)}
.tag.off{background:#f1f2f4;color:var(--muted)}
.tag.warn{background:#fdf3e2;color:var(--warn)}
.tag.bad{background:#fdeaea;color:var(--bad)}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px}
.dot.on{background:var(--ok);box-shadow:0 0 0 3px #e6f7ee}
.dot.off{background:#c6ccd4}
input[type=text],input[type=email],input[type=password],input[type=number],select{
  width:100%;padding:9px 11px;border:1px solid #d5dae1;border-radius:9px;font-size:14px;background:#fff;color:var(--ink)}
input:focus,select:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px rgba(47,111,237,.12)}
label.f{display:block;margin-bottom:12px}
label.f span{display:block;font-size:12.5px;color:var(--muted);margin-bottom:5px;font-weight:600}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.row>div{flex:1;min-width:180px}
button,.btn{display:inline-block;padding:9px 16px;border-radius:9px;border:1px solid transparent;
  background:var(--brand);color:#fff;font-size:13.5px;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.05)}
button.ghost{background:#fff;border-color:#d5dae1;color:var(--ink)}
button.ghost:hover{background:#f7f8fa}
button.danger{background:#fff;border-color:#f0c8c8;color:var(--bad)}
button.mini{padding:5px 10px;font-size:12.5px;border-radius:7px}
form.inline{display:inline-flex;gap:6px;align-items:center;margin:0}
.flash{padding:11px 14px;border-radius:10px;margin-bottom:16px;font-size:13.5px}
.flash.ok{background:#e9f8f0;color:#0d7d3f;border:1px solid #c6ecd8}
.flash.err{background:#fdeeee;color:#a82323;border:1px solid #f5d0d0}
.help{color:var(--muted);font-size:12.5px;margin-top:6px}
pre.log{background:#0f1419;color:#d6dee8;padding:16px;border-radius:10px;overflow:auto;
  max-height:640px;font:12px/1.6 var(--mono)}
.center{max-width:420px;margin:8vh auto;padding:0 20px}
.auth-card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:30px 28px;
  box-shadow:0 12px 32px rgba(20,30,50,.07)}
.auth-card h1{font-size:20px;margin-bottom:6px}
.auth-card .sub{margin-bottom:20px}
.auth-card button{width:100%;margin-top:6px;padding:11px}
.auth-card .alt{text-align:center;margin-top:16px;font-size:13px;color:var(--muted)}
.badge-line{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.sep{height:1px;background:var(--line);margin:18px 0}
code.k{font-family:var(--mono);background:#f1f3f6;padding:1px 6px;border-radius:5px;font-size:12.5px}
@media(max-width:640px){
  .top-in{padding:10px 14px;gap:10px}
  main{padding:0 14px;margin-top:16px}
  .card{padding:14px}
  th:nth-child(4),td:nth-child(4){display:none}
}
"""


def _page(title, body, active="", sid=None, extra_head=""):
    nav_items = [("overview", "/admin", "概览"),
                 ("accounts", "/admin?tab=accounts", "账号"),
                 ("gateways", "/admin?tab=gateways", "网关"),
                 ("devices", "/admin?tab=devices", "设备"),
                 ("settings", "/admin?tab=settings", "设置"),
                 ("logs", "/admin?tab=logs", "日志")]
    nav = "".join(
        '<a href="%s" class="%s">%s</a>' % (href, "on" if key == active else "", label)
        for key, href, label in nav_items)
    top = ""
    if sid:
        top = ('<header class="top"><div class="top-in">'
               '<div class="brand">小燕家庭云 <span>· 控制台</span></div>'
               '<nav>%s</nav>'
               '<div class="who"><a href="/admin/logout-form">退出</a></div>'
               '</div></header>') % nav
    return (("<!doctype html><html lang=zh-CN><head><meta charset=utf-8>"
             "<meta name=viewport content='width=device-width,initial-scale=1'>"
             "<title>%s · 小燕家庭云</title><style>%s</style>%s</head><body>%s"
             "<main>%s</main></body></html>") % (esc(title), CSS, extra_head, top, body)).encode("utf-8")


def _flash(q):
    out = ""
    if q.get("msg"):
        out += '<div class="flash ok">%s</div>' % esc(q["msg"])
    if q.get("err"):
        out += '<div class="flash err">%s</div>' % esc(q["err"])
    return out


def _redirect(loc, headers=None):
    h = {"Location": loc, "Content-Length": "0", "Cache-Control": "no-store"}
    if headers:
        h.update(headers)
    return 302, h, b""


# ============================================================ 登录页
def page_login(q, err=""):
    body = ('<div class="center"><div class="auth-card">'
            '<h1>管理后台</h1>'
            '<p class="sub">小燕家庭云 · 家庭中心归属与账号管理</p>'
            '%s'
            '<form method=post action="/admin/login">'
            '<label class="f"><span>管理员密码</span>'
            '<input type=password name=pw placeholder="初始密码见 admin_initial.txt" required autofocus></label>'
            '<button type=submit>登录</button>'
            '</form>'
            '<div class="alt">新用户在 App 里注册；本页只给管理员用</div>'
            '</div></div>') % (('<div class="flash err">%s</div>' % esc(err)) if err else "")
    return (401 if err else 200), {}, _page("登录", body)


# ============================================================ 概览
def page_overview(snap, sid, q):
    st = snap.get("stats") or {}
    accounts = snap.get("accounts") or {}
    tenants = snap.get("tenants") or {}
    gws = snap.get("gateways") or []
    online = [g for g in gws if g.get("online")]
    unclaimed = [g for g in gws if not g.get("owner")]
    cards = [
        ("账号数", str(len(accounts)), "已登记密码的账号"),
        ("已归属家庭中心", str(sum(1 for g in gws if g.get("owner"))), "共 %d 台" % len(gws)),
        ("在线网关", str(len(online)), "MQTT 长连接中"),
        ("未认领网关", str(len(unclaimed)), "可被同 IP 注册者认领"),
    ]
    kpis = "".join('<div class="kpi"><div class="k">%s</div><div class="v">%s</div></div>'
                   % (esc(k), v) for k, v, _ in cards)

    rows = ""
    for g in gws:
        rows += ('<tr><td class="mono">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
            esc(g.get("uuid")),
            '<span class="dot on"></span>在线' if g.get("online")
            else '<span class="dot off"></span>离线',
            esc(g.get("ip") or "—"),
            esc(g.get("owner") or "未认领")))
    if not rows:
        rows = '<tr><td colspan=4 style="color:var(--muted)">还没有网关连接过</td></tr>'

    body = ('<h1>概览</h1><p class="sub">服务已运行 %s</p>' % esc(fmt_dur(st.get("uptime"))))
    body += _flash(q)
    body += '<div class="grid">%s</div>' % kpis
    body += ('<div class="card"><h2 style="margin-top:0">网关状态</h2>'
             '<table><thead><tr><th>家庭中心 UUID</th><th>状态</th><th>公网 IP</th>'
             '<th>归属账号</th></tr></thead><tbody>%s</tbody></table></div>') % rows
    body += ('<div class="card"><h2 style="margin-top:0">运行信息</h2>'
             '<table><tbody>'
             '<tr><th style="width:190px">API 地址</th><td class="mono">https://api.example.com</td></tr>'
             '<tr><th>MQTT 长连接</th><td>%s 条</td></tr>'
             '<tr><th>自动认领</th><td>%s</td></tr>'
             '<tr><th>新用户注册</th><td>在小燕 App 登录页点「注册」（走 POST /users）</td></tr>'
             '</tbody></table></div>') % (esc(st.get("sessions", 0)),
                                          "开启" if snap.get("auto_claim") else "关闭")
    return 200, {}, _page("概览", body, "overview", sid)


# ============================================================ 账号
def page_accounts(snap, sid, q):
    accounts = snap.get("accounts") or {}
    tenants = snap.get("tenants") or {}
    gws = snap.get("gateways") or []
    hc_names = dict((g.get("uuid"), g.get("name")) for g in gws)

    uids = sorted(set(list(accounts.keys()) + list(tenants.keys())))
    rows = ""
    for uid in uids:
        a = accounts.get(uid) or {}
        hcs = tenants.get(uid) or []
        pw_tag = ('<span class="tag ok">已设密码</span>' if a.get("pw")
                  else '<span class="tag bad">无密码·无法登录</span>')
        if a and not a.get("enabled", True):
            pw_tag = '<span class="tag warn">已停用</span>'
        hc_txt = "<br>".join(
            '<span class="mono">%s</span> <span class="help">%s</span>'
            % (esc(h), esc(hc_names.get(h, ""))) for h in hcs) or \
            '<span style="color:var(--muted)">—</span>'
        unbind = "".join(
            '<form class="inline" method=post action="/admin/do">'
            '<input type=hidden name=csrf value="%s">'
            '<input type=hidden name=action value=acct_unbind>'
            '<input type=hidden name=uid value="%s">'
            '<input type=hidden name=hc value="%s">'
            '<button class="mini ghost" type=submit>解绑</button></form>'
            % (_csrf(sid), esc(uid), esc(h)) for h in hcs)
        rows += ('<tr><td class="mono">%s</td><td>%s</td><td>%s</td><td>%s</td>'
                 '<td class="help">%s</td><td nowrap>%s'
                 '<form class="inline" method=post action="/admin/do" onsubmit="return pw2(this)">'
                 '<input type=hidden name=csrf value="%s">'
                 '<input type=hidden name=action value=acct_pw>'
                 '<input type=hidden name=uid value="%s">'
                 '<input type=password name=pw placeholder="新密码" style="width:120px;padding:5px 8px" required>'
                 '<button class="mini ghost" type=submit>改密</button></form>'
                 # ★ 2026-10-21（AUDIT B5）：uid 嵌入 JS 字符串必须用 json.dumps
                 # （HTML 转义在 JS 字符串上下文里不防注入），不用字符串拼接。
                 '<form class="inline" method=post action="/admin/do" onsubmit="return confirm(%s)">'
                 '<input type=hidden name=csrf value="%s">'
                 '<input type=hidden name=action value=acct_del>'
                 '<input type=hidden name=uid value="%s">'
                 '<button class="mini danger" type=submit>删</button></form>'
                 '</td></tr>') % (
            esc(uid), pw_tag, esc(fmt_ts(a.get("last_login"))), hc_txt,
            esc(", ".join(a.get("nickname") or "")), unbind,
            _csrf(sid), json.dumps("确定删除账号 %s？" % uid), _csrf(sid), esc(uid))

    if not rows:
        rows = '<tr><td colspan=6 style="color:var(--muted)">还没有账号</td></tr>'

    hc_opts = "".join('<option value="%s">%s %s</option>'
                      % (esc(g.get("uuid")), esc(g.get("uuid")),
                         esc(g.get("name") or "")) for g in gws)

    body = '<h1>账号</h1><p class="sub">账号 = 登录 App 用的<b>邮箱</b>（只支持邮箱）；家庭中心决定它能看见哪几台网关</p>'
    body += _flash(q)
    body += ('<div class="card"><h2 style="margin-top:0">新建账号</h2>'
             '<form method=post action="/admin/do" class="row">'
             '<input type=hidden name=csrf value="%s">'
             '<input type=hidden name=action value=acct_create>'
             '<div><label class="f"><span>邮箱（只支持邮箱）</span>'
             '<input type=text name=uid placeholder="you@example.com" required></label></div>'
             '<div><label class="f"><span>密码</span>'
             '<input type=text name=pw placeholder="至少 8 位" required></label></div>'
             '<div style="flex:0 0 auto"><button type=submit>创建</button></div>'
             '</form>'
             '<p class="help">也可以让对方在小燕 App 登录页点「注册」自助开通。</p>'
             '</div>') % _csrf(sid)

    body += ('<div class="card"><h2 style="margin-top:0">已有账号</h2>'
             '<table><thead><tr><th>账号</th><th>密码状态</th><th>最后登录</th>'
             '<th>家庭中心</th><th>昵称</th><th>操作</th></tr></thead>'
             '<tbody>%s</tbody></table></div>') % rows

    body += ('<div class="card"><h2 style="margin-top:0">把网关绑定给账号</h2>'
             '<form method=post action="/admin/do" class="row">'
             '<input type=hidden name=csrf value="%s">'
             '<input type=hidden name=action value=acct_bind>'
             '<div><label class="f"><span>账号</span>'
             '<input type=text name=uid placeholder="you@example.com" required></label></div>'
             '<div><label class="f"><span>家庭中心</span>'
             '<select name=hc>%s</select></label></div>'
             '<div style="flex:0 0 auto"><button type=submit>绑定</button></div>'
             '</form></div>') % (_csrf(sid), hc_opts)
    body += ('<script>function pw2(f){var p=f.querySelector("input[name=pw]");'
             'if(p.value.length<8){alert("密码至少 8 位");p.focus();return false}return true}</script>')
    return 200, {}, _page("账号", body, "accounts", sid)


# ============================================================ 设备（MQTT 设备指纹）
def page_devices(snap, sid, q):
    devs = list(snap.get("dev_uids") or [])
    # 在线的排前面，其余按「最后一次在家认证」倒序
    devs.sort(key=lambda d: (not d.get("online"), -(float(d.get("ts") or 0))))

    rows = ""
    for d in devs:
        fp = d.get("fp") or ""
        uid = d.get("uid") or ""
        ip = d.get("ip") or ""
        online = bool(d.get("online"))
        st = ('<span class="tag ok">在线</span> <span class="mono help">%s</span>' % esc(ip)
              if online else '<span class="tag off">离线</span>')
        # ★ uid/fp 要进 JS 字符串（confirm）→ 必须用 json.dumps，HTML 转义在
        #   JS 字符串上下文里不防注入。
        warn = json.dumps(
            "确定解绑这台设备？\n\n账号：%s\n指纹：%s\n\n解绑后它会立刻掉线，"
            "并且除非重新在家里 WiFi 下打开一次 App，否则再也连不上。\n"
            "★ 如果这是你正在用的手机，解绑会让你自己立刻掉线。" % (uid, fp))
        rows += ('<tr><td class="mono">%s</td><td class="mono">%s</td>'
                 '<td class="help">%s</td><td>%s</td><td nowrap>'
                 '<form class="inline" method=post action="/admin/do" onsubmit="return confirm(%s)">'
                 '<input type=hidden name=csrf value="%s">'
                 '<input type=hidden name=action value=dev_unbind>'
                 '<input type=hidden name=fp value="%s">'
                 '<input type=hidden name=uid value="%s">'
                 '<button class="mini danger" type=submit>解绑</button></form>'
                 '</td></tr>') % (esc(fp), esc(uid), esc(fmt_ts(d.get("ts"))), st,
                                  warn, _csrf(sid), esc(fp), esc(uid))
    if not rows:
        rows = ('<tr><td colspan=5 style="color:var(--muted)">'
                '还没有设备完成绑定。App 在家里 WiFi 下打开一次，就会自动出现在这里。</td></tr>')

    body = ('<h1>设备</h1>'
            '<p class="sub">手机 App 每次连接会带一个<b>安装级设备指纹</b>（MQTT username 前 18 位）。'
            '它是在外网（4G / 别处 WiFi）也能用的凭据 —— 因为 App 的长连接本身不带账号密码。</p>')
    body += _flash(q)
    body += ('<div class="card"><h2 style="margin-top:0">已绑定的设备</h2>'
             '<table><thead><tr><th>设备指纹</th><th>绑定账号</th>'
             '<th>最后一次在家认证</th><th>状态</th><th>操作</th></tr></thead>'
             '<tbody>%s</tbody></table></div>') % rows
    body += ('<div class="card"><h2 style="margin-top:0">安全须知</h2>'
             '<p class="help" style="margin-top:0">指纹绑定<b>永久有效</b>，'
             '所以手机丢了、卖掉、淘汰之后必须手工解绑，否则那台设备仍然能看你家状态、'
             '控制你家的设备。</p>'
             '<p class="help">另一个自动吊销手段是<b>改账号密码</b>：'
             '改密会清掉该账号下所有指纹绑定并吊销 token，'
             '你自己的手机重连时会自动重新绑定，全程无感。</p>'
             '<p class="help">换新手机 / 重装 App / 清数据会让指纹变化，'
             '那台新设备必须先在家里 WiFi 下打开一次 App 完成绑定，之后才能在外网漫游。</p></div>')
    return 200, {}, _page("设备", body, "devices", sid)


# ============================================================ 网关
def page_gateways(snap, sid, q):
    gws = snap.get("gateways") or []
    reserved = set(snap.get("reserved") or [])
    rows = ""
    for g in gws:
        u = g.get("uuid") or ""
        is_res = u in reserved
        rows += ('<tr><td class="mono">%s<br><span class="help">%s</span></td>'
                 '<td>%s</td><td class="mono help">%s</td><td>%s</td><td>%s</td><td nowrap>%s</td></tr>') % (
            esc(u), esc(g.get("name") or ""),
            '<span class="tag ok">在线</span>' if g.get("online")
            else '<span class="tag off">离线</span>',
            esc(g.get("ip") or "—"),
            esc(g.get("owner") or "未认领"),
            '<span class="tag warn">已保留</span>' if is_res else '<span class="tag off">正常</span>',
            ('<form class="inline" method=post action="/admin/do">'
             '<input type=hidden name=csrf value="%s">'
             '<input type=hidden name=action value="%s">'
             '<input type=hidden name=hc value="%s">'
             '<button class="mini ghost" type=submit>%s</button></form>'
             '<form class="inline" method=post action="/admin/do">'
             '<input type=hidden name=csrf value="%s">'
             '<input type=hidden name=action value=gw_rename>'
             '<input type=hidden name=hc value="%s">'
             '<input type=text name=name placeholder="改名" style="width:110px;padding:5px 8px">'
             '<button class="mini ghost" type=submit>存</button></form>') % (
                _csrf(sid), "gw_unreserve" if is_res else "gw_reserve", esc(u),
                "取消保留" if is_res else "锁定",
                _csrf(sid), esc(u)))
    if not rows:
        rows = '<tr><td colspan=6 style="color:var(--muted)">还没有网关连上来</td></tr>'

    body = '<h1>网关</h1><p class="sub">「保留」= 不参与自动认领，只能由管理员手工绑定</p>'
    body += _flash(q)
    body += ('<div class="card"><table><thead><tr><th>家庭中心</th><th>状态</th>'
             '<th>公网 IP</th><th>归属</th><th>认领</th><th>操作</th></tr></thead>'
             '<tbody>%s</tbody></table></div>') % rows
    body += ('<div class="card"><h2 style="margin-top:0">认领规则</h2>'
             '<p class="help" style="margin-top:0">自动认领需要同时满足：网关在线 · 没被任何账号认领 · '
             '不在保留列表 · <b>网关连服务器时的公网 IP 与登录方完全一致</b>。'
             '时间窗口当前：%s。</p>'
             '<p class="help">想彻底关掉自动认领，去 <a href="/admin?tab=settings">设置</a>。</p>'
             '</div>') % (esc("不限时间" if snap.get("claim_window") is None
                              else ("已禁止" if (snap.get("claim_window") or 0) <= 0
                                    else "%d 秒" % snap.get("claim_window"))))
    return 200, {}, _page("网关", body, "gateways", sid)


# ============================================================ 设置
def page_settings(snap, sid, q):
    cfg = load_cfg()
    ip_allow = ", ".join(cfg.get("ip_allow") or [])
    cw = snap.get("claim_window")
    cw_val = "" if cw is None else str(int(cw // 60) if cw else 0)
    body = '<h1>设置</h1><p class="sub">改完立即生效，并写回 tenants.json / admin.json</p>'
    body += _flash(q)
    body += ('<div class="card"><h2 style="margin-top:0">自动认领</h2>'
             '<form method=post action="/admin/do">'
             '<input type=hidden name=csrf value="%s">'
             '<input type=hidden name=action value=set_all>'
             '<label class="f"><span>总开关</span>'
             '<select name=auto_claim>'
             '<option value=1 %s>开启（同一公网 IP 的注册者自动拿到未认领网关）</option>'
             '<option value=0 %s>关闭（只能由管理员手工绑定）</option>'
             '</select></label>'
             '<label class="f"><span>时间窗口（分钟）</span>'
             '<input type=text name=claim_window value="%s" placeholder="留空 = 不限时间">'
             '</label>'
             '<p class="help">留空表示不限制：只要公网 IP 对上就认领，适合「朋友切完服务器没立刻注册」的情况。'
             '填 0 = 禁止认领；填正数 = 只在该网关首次上线后的 N 分钟内允许。</p>'
             '<label class="f"><span>保留列表（每行一个 uuid，不参与自动认领）</span>'
             '<textarea name=reserved rows=4 style="width:100%%;padding:9px 11px;border:1px solid #d5dae1;'
             'border-radius:9px;font-family:var(--mono);font-size:12.5px">%s</textarea></label>'
             '<button type=submit>保存</button></form></div>') % (
        _csrf(sid), "selected" if snap.get("auto_claim") else "",
        "" if snap.get("auto_claim") else "selected", esc(cw_val),
        esc("\n".join(snap.get("reserved") or [])))

    body += ('<div class="card"><h2 style="margin-top:0">管理员密码</h2>'
             '<form method=post action="/admin/do" class="row">'
             '<input type=hidden name=csrf value="%s">'
             '<input type=hidden name=action value=admin_pw>'
             '<div><label class="f"><span>当前密码</span>'
             '<input type=password name=old required></label></div>'
             '<div><label class="f"><span>新密码（至少 8 位）</span>'
             '<input type=password name=pw required></label></div>'
             '<div style="flex:0 0 auto"><button type=submit>修改</button></div>'
             '</form></div>') % _csrf(sid)

    body += ('<div class="card"><h2 style="margin-top:0">后台来源限制</h2>'
             '<form method=post action="/admin/do">'
             '<input type=hidden name=csrf value="%s">'
             '<input type=hidden name=action value=admin_ip>'
             '<label class="f"><span>只允许这些 IP 访问 /admin（逗号分隔，留空 = 不限制）</span>'
             '<input type=text name=ip_allow value="%s" placeholder="1.2.3.4, 5.6.7.8"></label>'
             '<p class="help">注意：填了之后如果自己的 IP 变了会进不去，'
             '需要 SSH 改 admin.json 或删掉这一项。</p>'
             '<button type=submit>保存</button></form></div>') % (_csrf(sid), esc(ip_allow))
    return 200, {}, _page("设置", body, "settings", sid)


# ============================================================ 日志
def page_logs(be, sid, q):
    txt = ""
    try:
        txt = be.log_tail(300)
    except Exception as e:
        txt = "读取日志失败: %s" % e
    body = ('<h1>日志</h1><p class="sub">cloud4.log 最近 300 行（倒序不重要，自下往上看）</p>'
            '<div class="card" style="padding:0;border:none;background:none">'
            '<pre class="log">%s</pre></div>') % esc(txt)
    return 200, {}, _page("日志", body, "logs", sid)


# ============================================================ 主入口
def handle(be, method, path, query, headers, body, ip):
    """返回 (status, headers, body_bytes)。异常一律兜成 500 页面，不往外抛。"""
    try:
        return _handle(be, method, path, query, headers, body, ip)
    except Exception as e:
        import traceback
        auth.log("后台异常 %s %s: %s\n%s" % (method, path, e, traceback.format_exc()[:800]))
        return 500, {}, _page("出错", '<div class="card"><h1>500</h1>'
                                     '<p class="sub">%s</p></div>' % esc(e))


# ============================================================ JSON API 路由
def _handle_api(be, method, p, q, headers, body, ip):
    method = (method or "GET").upper()

    # ---- 登录（公开，按 IP 限速；成功后发会话 Cookie 并返回 csrf）
    if p == "/admin/api/login":
        if method != "POST":
            return _json({"ok": False, "err": "method not allowed"}, 405)
        if auth.throttled("admin:" + ip):
            return _json({"ok": False, "err": "尝试次数太多，请 10 分钟后再试"}, 429)
        f = _json_body(body)
        if check_admin_pw(f.get("pw") or ""):
            auth.clear_fails("admin:" + ip)
            sid = _new_session()
            auth.log("后台登录成功（API）ip=%s" % ip)
            return _json({"ok": True}, 200, {
                "Set-Cookie": "%s=%s; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=%d"
                              % (COOKIE, sid, SESSION_TTL)})
        auth.note_fail("admin:" + ip)
        auth.log("后台登录失败（API）ip=%s" % ip)
        return _json({"ok": False, "err": "密码不对"}, 401)

    # ---- 以下全部要求会话
    sid = _session(headers)
    if not sid:
        return _json({"ok": False, "err": "未登录"}, 401)
    csrf = _csrf(sid)

    if p == "/admin/api/logout":
        if method != "POST":
            return _json({"ok": False, "err": "method not allowed"}, 405)
        if (headers.get("x-csrf-token") or "") != csrf:
            return _json({"ok": False, "err": "CSRF 校验失败"}, 403)
        with _LOCK:
            _SESSIONS.pop(sid, None)
        return _json({"ok": True})

    if p == "/admin/api/whoami":
        return _json({"ok": True, "csrf": csrf})

    if p == "/admin/api/snapshot":
        if method != "GET":
            return _json({"ok": False, "err": "method not allowed"}, 405)
        out = _sanitize_snapshot(be.snapshot())
        out["ip_allow"] = load_cfg().get("ip_allow") or []
        out["ok"] = True          # ★ 客户端统一按 {ok,...} 判定，必须包一层
        return _json(out)

    if p == "/admin/api/logs":
        if method != "GET":
            return _json({"ok": False, "err": "method not allowed"}, 405)
        try:
            n = int(q.get("n") or 300)
        except Exception:
            n = 300
        n = max(50, min(n, 2000))
        txt = ""
        try:
            txt = be.log_tail(n)
        except Exception as e:
            return _json({"ok": False, "err": "读取日志失败: %s" % e}, 500)
        return _json({"ok": True, "text": txt, "lines": txt.splitlines()})

    if p == "/admin/api/do":
        if method != "POST":
            return _json({"ok": False, "err": "method not allowed"}, 405)
        if (headers.get("x-csrf-token") or "") != csrf:
            return _json({"ok": False, "err": "CSRF 校验失败，请刷新页面"}, 403)
        f = _json_body(body)
        msg, err = do_action(be, f.get("action") or "", f)
        if err:
            return _json({"ok": False, "err": err}, 400)
        return _json({"ok": True, "msg": msg})

    return _json({"ok": False, "err": "not found"}, 404)


def _handle(be, method, path, query, headers, body, ip):
    q = parse_qs(query)
    p = path.rstrip("/") or "/"
    method = (method or "GET").upper()

    if p == "/":
        return _redirect("/admin")

    if not p.startswith("/admin"):
        return 404, {}, b"not found"

    # ---- 后台来源限制
    cfg = load_cfg()
    allow = [str(x).strip() for x in (cfg.get("ip_allow") or []) if str(x).strip()]
    if allow and ip not in allow:
        auth.log("后台拒绝（IP 不在白名单）ip=%s" % ip)
        if p.startswith("/admin/api/"):
            return _json({"ok": False, "err": "该 IP 不在后台白名单里"}, 403)
        return 403, {}, _page("拒绝访问", '<div class="card"><h1>403</h1>'
                                          '<p class="sub">该 IP 不在后台白名单里。</p></div>')

    # ---- JSON API（SPA 用）：全部返回 JSON，不重定向
    if p.startswith("/admin/api/"):
        return _handle_api(be, method, p, q, headers, body, ip)

    # ---- 静态资源（SPA 三件套；不含任何数据，允许未登录加载，IP 白名单已前置校验）
    if p.startswith("/admin/assets/"):
        return _serve_asset(p[len("/admin/assets/"):])

    # ---- 登录 / 登出
    if p == "/admin/login":
        if method == "POST":
            f = parse_body(body)
            if auth.throttled("admin:" + ip):
                return page_login(q, "尝试次数太多，请 10 分钟后再试")
            if check_admin_pw(f.get("pw") or ""):
                auth.clear_fails("admin:" + ip)
                sid = _new_session()
                auth.log("后台登录成功 ip=%s" % ip)
                return _redirect("/admin", {
                    "Set-Cookie": "%s=%s; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=%d"
                                  % (COOKIE, sid, SESSION_TTL)})
            auth.note_fail("admin:" + ip)
            auth.log("后台登录失败 ip=%s" % ip)
            return page_login(q, "密码不对")
        return page_login(q)

    if p in ("/admin/logout", "/admin/logout-form"):
        sid = _session(headers)
        if sid:
            with _LOCK:
                _SESSIONS.pop(sid, None)
        return _redirect("/admin/login", {"Set-Cookie": "%s=; Path=/; Max-Age=0" % COOKIE})

    # ---- 其余全部要求已登录（/admin 例外：给 SPA 外壳，由 JS 显示登录页）
    sid = _session(headers)
    if not sid:
        if p in ("/admin", "/admin/") and method == "GET" and q.get("ui") != "classic":
            return _serve_asset("index.html")
        return _redirect("/admin/login")

    snap = be.snapshot()

    # ---- 写操作（旧表单流程保留；SPA 走 /admin/api/do）
    if p == "/admin/do":
        if method != "POST":
            return _redirect("/admin")
        f = parse_body(body)
        if f.get("csrf") != _csrf(sid):
            return _redirect("/admin?err=页面已过期，请重试")
        msg, err = do_action(be, f.get("action") or "", f)
        if err:
            return _redirect("/admin?err=" + _q(err))
        return _redirect("/admin?msg=" + _q(msg))

    # ---- SPA 外壳：/admin 默认给单页应用（JS 里再判断登录态）
    if p in ("/admin", "/admin/") and method == "GET" and q.get("ui") != "classic":
        return _serve_asset("index.html")

    if p == "/admin/classic":
        return _redirect("/admin?ui=classic")

    tab = q.get("tab") or "overview"
    if tab == "accounts":
        return page_accounts(snap, sid, q)
    if tab == "gateways":
        return page_gateways(snap, sid, q)
    if tab == "devices":
        return page_devices(snap, sid, q)
    if tab == "settings":
        return page_settings(snap, sid, q)
    if tab == "logs":
        return page_logs(be, sid, q)
    return page_overview(snap, sid, q)


def _q(s):
    from urllib.parse import quote_plus
    return quote_plus(str(s))
