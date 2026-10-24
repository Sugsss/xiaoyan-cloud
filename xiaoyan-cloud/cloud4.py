#!/usr/bin/env python3
"""
小燕(Terncy) 家庭云 v4 —— 真转译层
=====================================
    App(补丁版) --MQTT/WSS /ws/mqtt--> 假云端(本服务) --/ws/json--> 家庭中心(局域网)

v3 的问题：App 侧 protobuf 全是 TODO，只能回声，App 拿不到设备。
v4 补齐：
  · GetEntity(13)  -> 用网关设备缓存构造 GetEntityResult(14)（LiveEntity/PhysicDevice/Attribute）
  · 房间/场景：sync type=room / scene -> LiveEntity(BaseType=2/1) + 空 Room/Scene 子消息
  · OnOff(11)      -> 网关 execute {"attr":"on"}，回 OnOffResult(12)
  · SetSceneOnOff(21) -> 网关 execute（与设备同一报文），回 SetSceneOnOffResult(22)
  · WriteAttribute(63) -> AttrID 映射成网关属性名，回 WriteAttributeResult(64)
  · ReadAttribute(41)  -> 用缓存值回 ReadAttributeResult(42)
  · 网关事件 -> Event(8/9) 推给 App
  · GetCloudServer(88) -> 回本机地址，App 可持久化

协议细节见 terncy_proto.py / RE_DEEPEN2.md。

运行：
    PORT=443 CERT=le/fullchain.pem KEY=le/privkey.pem python3 cloud4.py
    （PLAIN=1 时明文，交给 nginx 终结 TLS）
"""
# 注意：服务器是 Python 3.6.8，不能用 `from __future__ import annotations`（3.7+）
# 本文件注解均为传统写法，兼容 3.6

import asyncio
import base64
import hashlib
import json
import logging
import os
import queue
import socket
import ssl
import struct
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import terncy_proto as pb  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))
HOST = os.environ.get("HOST", "127.0.0.1" if os.environ.get("PLAIN") == "1" else "0.0.0.0")
PORT = int(os.environ.get("PORT", "443"))
CERT = os.environ.get("CERT", os.path.join(BASE, "cert.pem"))
KEY = os.environ.get("KEY", os.path.join(BASE, "key.pem"))
LOGDIR = os.environ.get("LOGDIR", os.path.join(BASE, "logs"))
PLAIN = os.environ.get("PLAIN") == "1"
PUBLIC_API = os.environ.get("PUBLIC_API", "api.example.com")
PUBLIC_WS = os.environ.get("PUBLIC_WS", "ws.example.com")
GW_CONFIG_FILE = os.environ.get("GATEWAYS", os.path.join(BASE, "gateways.json"))
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# 账号/密码 与 Web 后台（同目录模块，systemd 下 sys.path[0] 未必是脚本目录，显式加一次）
sys.path.insert(0, BASE)
try:
    import auth                      # 账号 -> 密码哈希（PBKDF2）
    import admin_web                 # /register 注册页 + /admin 后台
    HAS_WEB = True
except Exception as _web_err:        # 缺文件也不要让主服务起不来
    HAS_WEB = False
    _WEB_ERR = "%s: %s" % (type(_web_err).__name__, _web_err)

try:
    GWS = json.load(open(GW_CONFIG_FILE)) if os.path.exists(GW_CONFIG_FILE) else []
except Exception:
    GWS = []

# 公网隧道上全是漏洞扫描器（wp-config.php / .env / docker-compose…）。
# 用**扫描器特征denylist**而不是 API 白名单：白名单太脆（App 的 /verificationcodes
# 之类会被误杀），而扫描器特征很稳定。命中者 404 且每条只记一次。
SCANNER_HINTS = (
    ".php", ".env", ".git", ".svn", ".hg", ".ds_store", ".sql", ".bak", ".old",
    ".save", ".dist", ".orig", ".log", ".ini", ".yml", ".yaml", ".config",
    "wp-", "wp_", "wordpress", "phpinfo", "docker-compose", "dockerfile",
    "jenkins", "postman", "composer", "package.json", "nuget", "appveyor",
    "travis", "circle", "buildkite", "terraform", "vagrant", "s3cmd",
    "web.config", "settings", "secret", "credential", "password", "backup",
    "admin", "server-status", "actuator", "swagger", "graphql", "console",
    "aws", "azure", "gcp", "firebase", "keycloak", "oauth-credentials",
)
SEEN_UNKNOWN = set()


def is_scanner(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in SCANNER_HINTS)

os.makedirs(LOGDIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout),
              logging.FileHandler(os.path.join(LOGDIR, "cloud4.log"), encoding="utf-8")],
)
log = logging.info


def short(b: bytes, n: int = 100) -> str:
    try:
        t = b.decode("utf-8")
        if t.isprintable():
            return f"text:{t[:n]}"
    except Exception:
        pass
    return f"hex:{b[:n].hex()}"


_HTTP_REASON = {200: "OK", 301: "Moved Permanently", 302: "Found", 303: "See Other",
                400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                404: "Not Found", 429: "Too Many Requests",
                500: "Internal Server Error"}


# ============================================================ 多租户（M3）
# 目标：几台网关 / 几个朋友共用一个假云端，彼此看不到、也控不到对方的家。
#
# 身份从哪来（2026-10-19 线上日志实锤，不是推测）：
#   · MQTT：App 建连后先 SUBSCRIBE message/<uid>，再 SUBSCRIBE event/<hc_uuid>
#           （日志里 670 条 `SUBSCRIBE ['message/13800000000'] sid=13800000000`）
#           → MQTT 会话自己就带 uid，RPC 鉴权直接用它，零猜测。
#   · HTTP：每条请求是独立 TCP（Connection: close），Session 不共享，
#           uid 只能靠「请求自带的 Bearer token」或「来源 IP 的短期记忆」还原。
#
# 归属表 tenants.json：{ "<uid>": ["<hc_uuid>", ...] }
#   · 文件不存在 / 为空  → 单租户兼容模式，沿用旧行为（GWS[0] / 硬编码兜底），
#                         保证没配表之前线上照旧能用。
#   · 文件存在且非空      → 严格模式：roster 只吐自己的 hc，message/<hc> 校验归属。
TENANTS_FILE = os.environ.get("TENANTS", os.path.join(BASE, "tenants.json"))
TENANT_LOCK = threading.Lock()
TOKENS = {}       # access token -> uid（登录时登记）
TOKENS_FILE = os.environ.get("TOKENS", os.path.join(BASE, "tokens.json"))
IP_UID = {}       # 来源 IP -> {uid: ts}：同一公网 IP 可能有多台手机/多个账号
                  # 旧格式是 ip -> (uid, ts)（只记最后一个），会互相覆盖，已改成多值
# ★ 2026-10-21（AUDIT A4）：30 分钟 → 10 分钟。CGNAT/大 NAT 下同一出口 IP 可能被陌生人
#   共用，窗口越短借用面越小；App 冷启动先 HTTP 后 MQTT（秒级），10 分钟足够覆盖。
IP_UID_TTL = 600

# ★ 2026-10-24：设备指纹 -> uid（解决「App 用 4G 连不上」）。
#   背景：ACL 只能靠公网 IP 认人，而手机 4G 出口 IP 与家里宽带出口不同
#   （实测 家里 <宽带出口IP> / 4G <移动出口IP>），IP 判据必然落空；
#   而 App 已有登录态不会再走 HTTP 登录，IP_UID 永远补不上 → 结构性死结。
#   依据：App 的 MQTT username 形如 `xy_sbk_<11位随机串><计数>`，**前 18 位是安装级
#   随机串**，跨天跨网络恒定（10-18~10-24、3 个出口 IP 实测一致），尾部 4 位是
#   每次连接的计数。取前 18 位当设备指纹，可在外网漫游时认人。
#   安全边界：指纹只在「IP 判据已认出 uid」时才建立绑定（强证据），
#   之后仅凭指纹放行；指纹是 11 位 base36 随机（≈3.7e17），不可枚举。
DEV_UID = {}          # 设备指纹 -> {uid: ts}
DEV_UID_FILE = os.environ.get("DEVUID", os.path.join(BASE, "devuid.json"))
# ★ 0 = 永久有效（2026-10-24 改）。原为 30 天：手机长期不回家（出差）就会过期，
#   在第 31 天于外网失效 —— 而绑的是**设备**，不会因为没回家就变成别人的设备。
#   作废改由后台/手工解绑（删 devuid.json 条目）。ts 仍每次在家时刷新，
#   保留「最后一次在家认证时间」供审计。
DEV_UID_TTL = 0
DEV_FP_LEN = 18              # `xy_sbk_` + 11 位随机串
_DEVUID_LAST_SAVE = [0]


def load_tokens():
    """token -> uid 落盘。为什么必须落盘：
    App 冷启动之外还会长期轮询 GET /users/~/roster，请求里只带
    `Authorization: Bearer <token>`，路径里没有 uid。服务一重启内存表就空，
    这个 token 立刻变成「无法还原身份」→ roster 返回空列表 → App 首页变空。
    （2026-10-20 部署后实测踩到，App 必须强制重启才能自己调 /users/<uid>/token 重绑。）"""
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        raw = json.load(open(TOKENS_FILE, encoding="utf-8"))
        if isinstance(raw, dict):
            return dict((str(k), str(v)) for k, v in raw.items())
    except Exception as e:
        log("[token] %s 解析失败: %s" % (TOKENS_FILE, e))
    return {}


def save_tokens():
    try:
        with TENANT_LOCK:
            snap = dict(TOKENS)
        # 只保留最近 800 条（按插入顺序，dict 在 3.6 保序），防文件无限长
        if len(snap) > 800:
            snap = dict(list(snap.items())[-800:])
        tmp = TOKENS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, TOKENS_FILE)
    except Exception as e:
        log("[token] 落盘失败 %s: %s" % (type(e).__name__, e))


def bind_token(token, uid):
    """登记 token 归属，变了才落盘（roster 每次都会走这里，不能每次都写文件）。"""
    if not token or not uid:
        return
    with TENANT_LOCK:
        old = TOKENS.get(token)
        TOKENS[token] = uid
    if old != uid:
        save_tokens()


try:
    TOKENS.update(load_tokens())
except Exception:
    pass

# ★ 注意：IP_UID 的落盘回填**不能**写在这里。
#   load_ipuid() 定义在文件更下方（remember_uid 之前），模块导入时执行到这一行
#   会抛 NameError，被 except 吞掉 —— 结果 ipuid.json 从来没被加载过，
#   服务重启后 MQTT ACL 认不出任何人（实测确认）。
#   回填逻辑已移到 def remember_uid(...) 之后执行，见下方标注。


GW_IP = {}        # hc_uuid -> 网关连上来的公网 IP（用于自动认领核对）
GW_IP_LOCK = threading.Lock()
# hc_uuid -> 网关「首次上线」时的公网 IP（防冒充）。
# 背景：网关身份只靠 CONNECT username 的 box- 前缀，任何人填 clientId/username
# 为受害者 hc 就能顶掉真网关、收走全部上行事件。这里做一次性 IP 锁定：
#   · 同一 hc 的旧连接还在线，却从别的 IP 连进来 → 视为冒充，拒绝；
#   · 旧连接已掉线（换网/重启/路由器重新拨号）→ 允许接管并更新绑定 IP。
GW_BIND_IP = {}
GW_BIND_LOCK = threading.Lock()
# hc_uuid -> 本进程第一次看到它上线的时间戳。
# 自动认领只在这个时间点之后的 CLAIM_WINDOW 秒内有效：
# 正常流程是「App 里切换服务器 → 立刻注册账号」，窗口足够；
# 而家里来客人在几小时后注册时，窗口早过了，不会被抢走网关。
GW_FIRST_SEEN = {}

# 离线也能显示名字：网关在线时以 GWS / 实际 roster 为准，这里只是兜底表
HC_NAMES = {}


def load_tenants():
    if not os.path.exists(TENANTS_FILE):
        log("[tenant] 无 %s —— 单租户兼容模式" % TENANTS_FILE)
        return {}
    try:
        d = json.load(open(TENANTS_FILE, encoding="utf-8"))
    except Exception as e:
        log("[tenant] %s 解析失败: %s —— 单租户兼容模式" % (TENANTS_FILE, e))
        return {}
    global AUTO_CLAIM, RESERVED, HC_NAMES, MEMBER_TYPE, CLAIM_WINDOW, MQTT_ACL, VG_BRIDGE, MEMBER_PERM
    AUTO_CLAIM = bool(d.get("_auto_claim", True))
    MQTT_ACL = bool(d.get("_mqtt_acl", True))
    VG_BRIDGE = bool(d.get("_vg_bridge", False))   # AUDIT A5：虚拟组主题桥接，默认关
    try:
        MEMBER_PERM = dict((str(k), int(v)) for k, v in (d.get("_member_perm") or {}).items())
    except Exception as e:
        MEMBER_PERM = {}
        log("[tenant] _member_perm 解析失败，全部按 14 处理: %s" % e)
    try:
        # 自动认领的时间窗口（分钟），三种取值：
        #   不设这个键（默认）→ None = 不限制时间，只要 IP 对上就能认领
        #   设 0              → 禁止自动认领（最安全）
        #   设正数            → 只在该网关首次上线后的 N 分钟内允许
        # 注意必须用 float 再乘，否则 0.05 会被 int() 截成 0。
        _cw = d.get("_claim_window_minutes", None)
        CLAIM_WINDOW = None if _cw is None else int(float(_cw) * 60)
    except Exception:
        CLAIM_WINDOW = None
    RESERVED = set(str(x) for x in (d.get("_reserved") or []))
    HC_NAMES = dict((str(k), str(v)) for k, v in (d.get("_names") or {}).items())
    try:
        # ★ 默认改成 2（2026-10-20 21:15 真机实锤）：Type=1 在 App 眼里是「未通过审核」，
        #   成员会被「我的家人」页整页过滤掉（页面全空、连"邀请"按钮都不显示）。
        #   Type=2 才是「已通过审核的正式成员」。本服务没有审批流，成员即正式成员。
        MEMBER_TYPE = int(d.get("_member_type", 2))
    except Exception:
        MEMBER_TYPE = 2
    out = {}
    for k, v in (d or {}).items():
        if str(k).startswith("_"):
            continue          # 允许 "_readme" / "_note" / "_auto_claim" 之类控制键
        if isinstance(v, str):
            v = [v]
        elif isinstance(v, dict):
            v = v.get("hcs") or []
        out[str(k)] = [str(x) for x in (v or [])]
    if out:
        _wdesc = "不限时间" if CLAIM_WINDOW is None else ("已禁止" if CLAIM_WINDOW <= 0 else "窗口 %ds" % CLAIM_WINDOW)
        log("[tenant] 严格模式 %d 个用户: %s | 自动认领=%s（%s）| 保留=%s" % (
            len(out), "; ".join("%s->%s" % (u, ",".join(hcs)) for u, hcs in out.items()),
            AUTO_CLAIM, _wdesc, ",".join(sorted(RESERVED)) or "无"))
    else:
        log("[tenant] %s 为空 —— 单租户兼容模式" % TENANTS_FILE)
    return out


AUTO_CLAIM = True
CLAIM_WINDOW = None         # None = 不限时间；0 = 禁止认领；正数 = 窗口秒数
RESERVED = set()
MEMBER_TYPE = 2              # 2 = 已通过审核的正式成员（1 会被 App 当"待审核"整页过滤，见 load_tenants）
# ★ 2026-10-21 11:50：按成员覆盖 Permission 位（tenants.json 的 "_member_perm"），默认 14。
#   位含义（RE_DEEPEN2 反汇编 + 2026-10-19 实测）：
#     2 = edit（编辑场景/自动化），4 = control（控设备），8 = view（只看）
#   控制门禁白名单 {4,6,12,14}，编辑门禁白名单 {2,6,10,14} —— 所以 **8 = 只读**（两个都不在）。
#   ⚠️ 只读是否真的被 App 遵守，**尚未真机验证**（手机当时在 Dozing）。默认仍给 14，行为不变；
#      想给访客只读时写 "_member_perm": {"guest@example.com": 8} 再真机确认。
MEMBER_PERM = {}
# ★ 默认值必须定义在 load_tenants() **之前**：load_tenants() 内部用 global 读取/覆盖它。
#   历史上这条默认值写在文件下方（原第 692 行），导入到那时 load_tenants() 早在
#   第 259 行跑完了 → tenants.json 里 "_mqtt_acl": false 会被硬编码 True 覆盖，
#   开关形同虚设。
MQTT_ACL = True             # 由 tenants.json 的 "_mqtt_acl" 控制，默认开
VG_BRIDGE = False           # 由 tenants.json 的 "_vg_bridge" 控制，默认关（AUDIT A5）
TENANTS = load_tenants()


def save_tenants():
    """把当前 TENANTS 落盘。保留文件里的 _readme / _note / _auto_claim / _reserved。"""
    with TENANT_LOCK:
        snapshot = dict((u, list(h)) for u, h in TENANTS.items())
    try:
        raw = {}
        if os.path.exists(TENANTS_FILE):
            try:
                raw = json.load(open(TENANTS_FILE, encoding="utf-8")) or {}
            except Exception:
                raw = {}
        # ★ 2026-10-20：以前只 merge、不删旧键 —— 从内存里删掉的账号会在下次重启时
        #   从文件里"复活"（撤销授权等于无效）。先清掉所有非下划线键，再整份写入。
        for _k in [k for k in raw.keys() if not str(k).startswith("_")]:
            raw.pop(_k, None)
        for u, hcs in snapshot.items():
            raw[u] = hcs
        tmp = TENANTS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o600)     # 归属表含账号与家庭中心对应关系，不给 others 读
        os.replace(tmp, TENANTS_FILE)
        log("[tenant] 归属表已落盘 %s（%d 个用户）" % (TENANTS_FILE, len(snapshot)))
        return True
    except Exception as e:
        log("[tenant] 落盘失败: %s: %s" % (type(e).__name__, e))
        return False


def claimed_hcs():
    with TENANT_LOCK:
        out = set()
        for hcs in TENANTS.values():
            out.update(hcs)
    return out


def try_auto_claim(uid, my_ip, ua=""):
    """自动认领：uid 未登记 + 有「已连上假云端但没人认领」的网关，
    且该网关连上来的公网 IP 与请求方一致（= 同一个 NAT / 同一个家）→ 绑给他。

    为什么用公网 IP 而不是 MAC：
      App 不会把手机看到的网关 MAC 发给云端，云端也无从读取手机局域网 MAC。
      但网关连我们服务器时的源 IP、和手机发 HTTP 请求的源 IP，
      在「手机与网关同一个 WiFi」时必然相同 —— 这就是可核对的「局域网在场证明」。
    """
    if not AUTO_CLAIM or not uid:
        return []
    peers = peers_snapshot()
    if not peers:
        return []
    taken = claimed_hcs()
    now = time.time()
    with GW_IP_LOCK:
        gw_ip = dict(GW_IP)
        first = dict(GW_FIRST_SEEN)

    def _in_window(hc):
        """时间条件（可选）。

        CLAIM_WINDOW is None → 不看时间，只要其它条件满足就允许认领（默认）
        CLAIM_WINDOW <= 0    → 禁止自动认领
        CLAIM_WINDOW > 0     → 只在该网关首次上线后的 N 秒内允许

        为什么不靠时间兜安全：App 不向云端透露网关 MAC / 手机局域网 IP，
        所以「同一个公网 IP」已经是能做到的最强在场证明；时间窗口只是额外收紧，
        代价是朋友切完服务器如果没立刻注册就得找管理员。默认不用它。
        """
        if CLAIM_WINDOW is None:
            return True
        if CLAIM_WINDOW <= 0:
            return False
        return (now - first.get(hc, 0)) <= CLAIM_WINDOW

    cands = [hc for hc in peers
             if hc not in taken and hc not in RESERVED
             and gw_ip.get(hc) == my_ip and _in_window(hc)]
    if not cands:
        # 记录一下，方便排查「为什么没自动绑上」
        near = [hc for hc in peers if hc not in taken and hc not in RESERVED]
        if near:
            log("[tenant] 自动认领未命中：uid=%s ip=%s，未认领网关 %s 的公网 IP 是 %s（上线时长 %s）" % (
                uid, my_ip or "?", ",".join(near),
                ",".join(gw_ip.get(h, "?") for h in near),
                ",".join("%ds" % int(now - first.get(h, 0)) for h in near)))
        return []
    if len(cands) > 1:
        log("[tenant] 自动认领放弃：同 IP 下有 %d 台未认领网关 %s，歧义" % (len(cands), cands))
        return []
    hc = cands[0]
    with TENANT_LOCK:
        TENANTS[uid] = [hc]
    # 认领事件写进日志，带上「机型/UA」和 IP —— 万一被不该认领的人抢走，
    # 凭这两条就能判断是谁，然后改 tenants.json 撤销。
    log("[tenant] ★ 自动认领：uid=%s <- %s（公网 IP %s，UA=%s）" % (
        uid, hc, my_ip, (ua or "?")[:90]))
    save_tenants()
    return [hc]


def tenants_of(uid):
    with TENANT_LOCK:
        return list(TENANTS.get(uid or "", []))


def hc_owner_of(hc_uuid):
    """家庭中心 -> 归属账号（tenants.json 反查）。找不到返回 ""。

    ★ 2026-10-20 复盘 v3.0 新增：成员表（/users/<hc>/roster）以前匿名请求时
      用 `_uid or "13800000000"` 兜底 —— 结果是任何人裸着打这个接口都能拿到一个
      硬编码手机号，而且**查哪台 hc 都返回同一份**（成员表根本没按 hc 过滤）。
      现在改成反查归属：主人看自己家得到主人，朋友看自己家得到朋友，
      匿名 / 不认识的 hc 一律拿不到身份。
    """
    if not hc_uuid:
        return ""
    with TENANT_LOCK:
        for uid, hcs in TENANTS.items():
            if hc_uuid in (hcs or []):
                return uid
    return ""


def hc_name_of(hc_uuid):
    """家庭中心显示名。优先级：tenants.json 的 _names > gateways.json > 默认。"""
    if hc_uuid in HC_NAMES:
        return HC_NAMES[hc_uuid]
    for g in GWS:
        if g.get("hc_uuid") == hc_uuid:
            return g.get("hc_name") or "小燕家庭中心"
    return "小燕家庭中心"


IPUID_FILE = os.environ.get("IPUID", os.path.join(BASE, "ipuid.json"))
_IPUID_LAST_SAVE = [0.0]


def load_ipuid():
    """IP -> uid 也要落盘：MQTT 的访问控制靠它认人，服务一重启就空的话，
    App 重连后所有订阅都会被判匿名（首页变离线），直到下一次 HTTP 请求把 IP 补回来。"""
    if not os.path.exists(IPUID_FILE):
        return {}
    try:
        raw = json.load(open(IPUID_FILE, encoding="utf-8"))
        now = time.time()
        out = {}
        for k, v in (raw or {}).items():
            if isinstance(v, dict):
                rec = dict((str(u), float(ts)) for u, ts in v.items() if now - float(ts) < IP_UID_TTL)
            elif isinstance(v, (list, tuple)) and len(v) == 2:
                rec = {str(v[0]): float(v[1])}      # 兼容旧的单值格式
            else:
                continue
            if rec:
                out[str(k)] = rec
        return out
    except Exception as e:
        log("[acl] 读 %s 失败: %s" % (IPUID_FILE, e))
        return {}


def save_ipuid(force=False):
    now = time.time()
    if not force and now - _IPUID_LAST_SAVE[0] < 60:
        return                      # 请求很密，最多一分钟写一次
    _IPUID_LAST_SAVE[0] = now
    try:
        with TENANT_LOCK:
            snap = {}
            for ip, rec in IP_UID.items():
                keep = dict((u, ts) for u, ts in (rec or {}).items() if now - ts < IP_UID_TTL)
                if keep:
                    snap[ip] = keep
        tmp = IPUID_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, IPUID_FILE)
    except Exception as e:
        log("[acl] 写 %s 失败: %s" % (IPUID_FILE, e))


def remember_uid(ip, uid):
    """记「这台 IP 上出现过这个账号」。同一 IP 允许有多个账号（一个家多台手机），
    否则后登录的会覆盖前一个 —— 实测就踩过：调试时用 friend 账号登录了一下，
    App 的 MQTT 订阅立刻被判成越权。"""
    if ip and uid:
        now = time.time()
        with TENANT_LOCK:
            rec = IP_UID.setdefault(ip, {})
            rec[uid] = now
            for u in [u for u, ts in rec.items() if now - ts > IP_UID_TTL]:
                rec.pop(u, None)
            # 一个 IP 最多记 8 个账号，防止被刷爆
            if len(rec) > 8:
                for u, _ in sorted(rec.items(), key=lambda kv: kv[1])[:-8]:
                    rec.pop(u, None)
        save_ipuid()


def dev_fingerprint(username):
    """App 的 MQTT username -> 设备指纹。取前 DEV_FP_LEN 位，去掉每次连接递增的尾部计数。

    非 App（网关 `box-xxx`、空、异常短）一律返回 ""，绝不参与判据 ——
    指纹是弱凭据，只对 App 这类「无凭据客户端」开，网关有自己的 hc 校验。"""
    u = username or ""
    if not u.startswith("xy_sbk_"):
        return ""
    if len(u) < DEV_FP_LEN:
        return ""
    return u[:DEV_FP_LEN]


def dev_uid_alive(ts, now=None):
    """指纹绑定是否仍然有效。集中在一处判断，避免 4 个调用点各写一遍 TTL 逻辑。

    DEV_UID_TTL == 0 表示永久有效（2026-10-24 起），此时只要求 ts 是个合法时间值。"""
    if not DEV_UID_TTL:
        try:
            return float(ts) > 0
        except Exception:
            return False
    return (now if now is not None else time.time()) - float(ts) < DEV_UID_TTL


def load_devuid():
    """指纹 -> uid 落盘。不落盘的话服务一重启，正在外面用 4G 的手机立刻变匿名。"""
    if not os.path.exists(DEV_UID_FILE):
        return {}
    try:
        raw = json.load(open(DEV_UID_FILE, encoding="utf-8"))
        now = time.time()
        out = {}
        for k, v in (raw or {}).items():
            if isinstance(v, dict):
                rec = dict((str(u), float(ts)) for u, ts in v.items()
                           if dev_uid_alive(ts, now))
            elif isinstance(v, (list, tuple)) and len(v) == 2:
                rec = {str(v[0]): float(v[1])}
            else:
                continue
            if rec:
                out[str(k)] = rec
        return out
    except Exception as e:
        log("[acl] 读 %s 失败: %s" % (DEV_UID_FILE, e))
        return {}


def save_devuid(force=False):
    now = time.time()
    if not force and now - _DEVUID_LAST_SAVE[0] < 60:
        return
    _DEVUID_LAST_SAVE[0] = now
    try:
        with TENANT_LOCK:
            snap = {}
            for fp, rec in DEV_UID.items():
                keep = dict((u, ts) for u, ts in (rec or {}).items()
                            if dev_uid_alive(ts, now))
                if keep:
                    snap[fp] = keep
        tmp = DEV_UID_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, DEV_UID_FILE)
    except Exception as e:
        log("[acl] 写 %s 失败: %s" % (DEV_UID_FILE, e))


def remember_dev(username, uids):
    """把「这个设备指纹」绑定到「这些账号」。★ 只在 IP 判据已经认出人时才调用，
    绝不允许用指纹自己给自己续绑定（否则一次误绑会永久生效）。"""
    fp = dev_fingerprint(username)
    if not fp or not uids:
        return
    now = time.time()
    with TENANT_LOCK:
        rec = DEV_UID.setdefault(fp, {})
        for u in uids:
            rec[u] = now
        for u in [u for u, ts in rec.items() if not dev_uid_alive(ts, now)]:
            rec.pop(u, None)
        if len(rec) > 8:                      # 一台手机最多绑 8 个账号
            for u, _ in sorted(rec.items(), key=lambda kv: kv[1])[:-8]:
                rec.pop(u, None)
    save_devuid()


# ★ IP -> uid 的落盘回填（原先在第 191 行，那时 load_ipuid 还没定义 → 一直静默失败）。
#   放在这里的原因：此刻 load_ipuid 已定义、IP_UID / IP_UID_TTL 常量也已就绪。
#   作用：服务重启后 MQTT ACL 仍能认出「这台公网 IP 刚才登录过谁」，
#   App 重连才不会被判成匿名（否则首页显示家庭中心离线）。
try:
    IP_UID.update(load_ipuid())
    if IP_UID:
        log("[acl] 已从 %s 回填 %d 条 IP 登录记录" % (IPUID_FILE, len(IP_UID)))
except Exception as _ipuid_err:
    log("[acl] 回填 %s 失败: %s: %s" % (IPUID_FILE, type(_ipuid_err).__name__, _ipuid_err))

# ★ 设备指纹绑定的落盘回填（2026-10-24）：服务一重启，正在外面用 4G 的手机
#   仍能凭指纹认人，不会被打回匿名（IP 判据在外网本来就落空）。
try:
    DEV_UID.update(load_devuid())
    if DEV_UID:
        log("[acl] 已从 %s 回填 %d 条设备指纹绑定" % (DEV_UID_FILE, len(DEV_UID)))
except Exception as _devuid_err:
    log("[acl] 回填 %s 失败: %s: %s" % (DEV_UID_FILE, type(_devuid_err).__name__, _devuid_err))


# ============================================================ Web 后台数据桥
# admin_web 只管渲染，所有读写都走这里，保证「后台看到的」就是「服务在用的」。
class AdminBackend:
    started = time.time()

    # ---- 读
    def snapshot(self):
        with TENANT_LOCK:
            tenants = dict((u, list(h)) for u, h in TENANTS.items())
        online = set(peers_snapshot().keys())
        with GW_IP_LOCK:
            gw_ip = dict(GW_IP)
            first = dict(GW_FIRST_SEEN)
        known = set()
        for g in GWS:
            if g.get("hc_uuid"):
                known.add(g["hc_uuid"])
        known |= online | set(gw_ip) | set(HC_NAMES)
        for hcs in tenants.values():
            known |= set(hcs)
        gateways = []
        for hc in sorted(known):
            owner = ""
            for u, hcs in tenants.items():
                if hc in hcs:
                    owner = u
                    break
            gateways.append({
                "uuid": hc,
                "name": hc_name_of(hc),
                "online": hc in online,
                "ip": gw_ip.get(hc, ""),
                "owner": owner,
                "first_seen": int(first.get(hc, 0)),
            })
        accounts = {}
        try:
            accounts = dict(auth.load())
        except Exception:
            pass
        sessions = 0
        try:
            sessions = len(BROKER.sessions)
        except Exception:
            pass
        # ---- 设备指纹绑定（2026-10-24 新增）
        #   指纹 TTL 改成永久之后，「后台能看到并解绑」就是唯一的安全出口，
        #   否则一部丢了/卖掉的手机会永久保有访问权。这里顺便标出当前是否在线、
        #   从哪个公网 IP 连着，方便判断「这是我现在用的手机」还是「该踢的」。
        dev_uids = []
        try:
            with BROKER.lock:
                _sess = list(BROKER.sessions)
        except Exception:
            _sess = []
        live = {}
        for _s in _sess:
            _fp = dev_fingerprint(getattr(_s, "mqtt_user", "") or "")
            if _fp:
                live.setdefault(_fp, []).append(
                    (getattr(_s, "pub_ip", "") or "", getattr(_s, "tag", "")))
        with TENANT_LOCK:
            _dev = dict((k, dict(v or {})) for k, v in DEV_UID.items())
        for _fp in sorted(_dev):
            for _u in sorted(_dev[_fp]):
                _live = live.get(_fp) or []
                dev_uids.append({
                    "fp": _fp,
                    "uid": _u,
                    "ts": _dev[_fp][_u],
                    "online": bool(_live),
                    "ip": _live[0][0] if _live else "",
                })
        return {
            "accounts": accounts,
            "tenants": tenants,
            "gateways": gateways,
            "reserved": sorted(RESERVED),
            "auto_claim": AUTO_CLAIM,
            "claim_window": CLAIM_WINDOW,
            "dev_uids": dev_uids,
            "stats": {"uptime": time.time() - self.started,
                      "sessions": sessions,
                      "tokens": len(TOKENS)},
        }

    def log_tail(self, n=300):
        path = os.path.join(LOGDIR, "cloud4.log")
        try:
            with open(path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                back = min(size, 96 * 1024)
                f.seek(size - back)
                data = f.read().decode("utf-8", "replace")
            return "\n".join(data.splitlines()[-n:])
        except Exception as e:
            return "读取 %s 失败: %s" % (path, e)

    # ---- 写（归属表）
    def ensure_tenant(self, uid):
        if not uid:
            return
        with TENANT_LOCK:
            TENANTS.setdefault(uid, [])
        save_tenants()

    def drop_tenant(self, uid):
        with TENANT_LOCK:
            TENANTS.pop(uid, None)
        # 用 persist_meta 而不是 save_tenants：后者只覆盖、不删除，
        # 删掉的账号会以 "<uid>: []" 的形式残留在文件里（踩过）。
        self.persist_meta()

    def bind(self, uid, hc):
        if not (uid and hc):
            return
        with TENANT_LOCK:
            cur = list(TENANTS.get(uid, []))
            if hc not in cur:
                cur.append(hc)
            TENANTS[uid] = cur
        save_tenants()
        log("[admin] 手工绑定 %s <- %s" % (uid, hc))

    def unbind(self, uid, hc):
        with TENANT_LOCK:
            cur = [h for h in TENANTS.get(uid, []) if h != hc]
            TENANTS[uid] = cur
        save_tenants()
        log("[admin] 手工解绑 %s -/-> %s" % (uid, hc))

    # ---- 写（设备指纹）
    def dev_unbind(self, fp, uid=None):
        """解绑一个设备指纹；uid 为空 = 这个指纹下的所有账号。

        ★ 必须同时踢掉该指纹当前的在线会话：只删绑定而长连接还活着的话，
        App 已经订阅的 event/<hc> 照样收事件、照样能下发控制，解绑就是假的。
        返回 (解除条数, 踢掉的会话数)。"""
        fp = (fp or "").strip()
        if not fp:
            return 0, 0
        with TENANT_LOCK:
            rec = DEV_UID.get(fp)
            if not rec:
                return 0, 0
            if uid:
                n = 1 if uid in rec else 0
                rec.pop(uid, None)
            else:
                n = len(rec)
                rec = {}
            if rec:
                DEV_UID[fp] = rec
            else:
                DEV_UID.pop(fp, None)
        save_devuid(force=True)
        kicked = 0
        try:
            with BROKER.lock:
                victims = [s for s in BROKER.sessions
                           if dev_fingerprint(getattr(s, "mqtt_user", "") or "") == fp]
        except Exception:
            victims = []
        for s in victims:
            try:
                s.kick("后台解绑指纹 %s" % fp[:12])
                kicked += 1
            except Exception as e:
                log("[admin] 踢会话失败: %s: %s" % (type(e).__name__, e))
        log("[admin] 解绑设备指纹 %s uid=%s：解除 %d 条、强制断开 %d 个连接"
            % (fp[:12], uid or "(全部)", n, kicked))
        return n, kicked

    # ---- 写（控制键）
    def set_reserved(self, hc, on):
        if not hc:
            return
        if on:
            RESERVED.add(hc)
        else:
            RESERVED.discard(hc)
        self.persist_meta()
        log("[admin] 保留列表 %s %s" % ("加入" if on else "移除", hc))

    def rename(self, hc, name):
        if not hc or not name:
            return
        HC_NAMES[hc] = name
        self.persist_meta()
        log("[admin] 改名 %s -> %s" % (hc, name))

    def save_settings(self, auto_claim, window, reserved):
        global AUTO_CLAIM, CLAIM_WINDOW, RESERVED
        AUTO_CLAIM = bool(auto_claim)
        CLAIM_WINDOW = window
        RESERVED = set(reserved or [])
        self.persist_meta()
        log("[admin] 设置更新：auto_claim=%s window=%s reserved=%s"
            % (AUTO_CLAIM, CLAIM_WINDOW, ",".join(sorted(RESERVED)) or "无"))

    def persist_meta(self):
        """把控制键 + 归属表整份写回 tenants.json（保留其它自定义键）。"""
        with TENANT_LOCK:
            tenants = dict((u, list(h)) for u, h in TENANTS.items())
        try:
            raw = {}
            if os.path.exists(TENANTS_FILE):
                try:
                    raw = json.load(open(TENANTS_FILE, encoding="utf-8")) or {}
                except Exception:
                    raw = {}
            for k in list(raw.keys()):
                if not str(k).startswith("_"):
                    raw.pop(k, None)
            raw["_auto_claim"] = AUTO_CLAIM
            if CLAIM_WINDOW is None:
                raw.pop("_claim_window_minutes", None)
            else:
                raw["_claim_window_minutes"] = round(float(CLAIM_WINDOW) / 60.0, 4)
            raw["_reserved"] = sorted(RESERVED)
            raw["_names"] = dict(HC_NAMES)
            raw.setdefault("_readme", "uid(登录邮箱或手机号) -> 该账号能看到的家庭中心 uuid 列表。"
                                      "本文件由 /admin 后台维护，也可手工改后重启服务。")
            raw.update(tenants)
            tmp = TENANTS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(raw, f, ensure_ascii=False, indent=2)
                f.write("\n")
            os.chmod(tmp, 0o600)     # 同 save_tenants：后台保存后仍保持 600
            os.replace(tmp, TENANTS_FILE)
            return True
        except Exception as e:
            log("[admin] 写 %s 失败: %s: %s" % (TENANTS_FILE, type(e).__name__, e))
            return False


ADMIN_BE = AdminBackend()


def client_ip(sess, headers):
    """真实客户端 IP。服务在 nginx 后面，sess.addr 永远是 127.0.0.1，
    直接用它做身份键会把所有客户端混成一个人（踩过：探针把 App 身份污染了）。"""
    xri = (headers.get("x-real-ip") or "").strip()
    if xri:
        return xri
    xff = (headers.get("x-forwarded-for") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return sess.addr[0] if sess.addr else ""


def resolve_uid(sess, headers, path):
    """HTTP 请求 -> uid。按证据强度排序，取第一个命中的：
         1) Authorization: Bearer <token> —— 最强凭证（必须是登记过的 token）
         2) 路径里的 uid —— 弱证据，仅在没有 Bearer 时使用
         3) 严格模式返回空；单租户模式兜底 LAST_UID

    ★ 2026-10-21 10:40（AUDIT A2 结构重构）：原来是「路径 uid 第一、token 第二」，
      等于「URL 里写谁就是谁」—— 持任意有效 token 请求 /users/<他人>/roster
      会拿到他人的成员条目（A2 漏洞面）。现在对调：**token 说了算**；只在完全
      没有 Bearer 时才看路径 uid（兼容旧路径；敏感入口另有二次校验）。
      影响面取证（2026-10-21 线上日志）：App 请求 auth=有 958 次 / auth=无 21 次
      （且无 auth 的全是自测与扫描器）—— 正常路径全部带 token，重构不改变其身份。
    """
    auth = (headers.get("authorization") or "").strip()
    _tk = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    seg = path.split("?")[0].strip("/").split("/")
    _path_uid = ""
    if len(seg) >= 2 and seg[0] == "users" and seg[1] not in (
            "~", "", "me", "token", "name", "notification", "roster", "avatar",
            "verificationcodes") and not seg[1].startswith("box-"):
        # ★ 必须排除 box-*：/users/<hc_uuid>/roster 与 /users/<hc>/name 的
        #   第二段是家庭中心 UUID，不是用户身份。历史上 LAST_UID 就被这样污染过
        #   （曾把 uid 记成 "name"）。
        _path_uid = seg[1]
    # ---- 1) Bearer token 优先（登记过才认；不认识的 token = 未认证，P0 语义不变）
    if _tk:
        with TENANT_LOCK:
            uid = TOKENS.get(_tk)
        if uid:
            remember_uid(client_ip(sess, headers), uid)
            return uid
        # ★ 2026-10-21 07:33：带了 token 但**不认识** —— 明确当作未认证，
        #   绝不再退回「按来源 IP 猜身份」，也**不**再退回路径 uid（A2）：
        #   否则任意假 Bearer + 受害者路径 = 受害者身份。
        return ""
    # ---- 2) 没有 Bearer 时才看路径 uid（弱证据，调用方敏感入口会二次校验）
    if _path_uid:
        # ★★★ 2026-10-21 07:30 P0 修复：这里原来会 `bind_token(_tk, _path_uid)`，
        #   即「路径里写谁，就把客户端带来的 token 绑成谁」—— 这是**零凭据账号接管**：
        #     任意人只要 `GET /users/<受害者>/roster` 带一个自己编的 Bearer，
        #     他的 token 立刻变成受害者的；之后 roster / remember_uid / MQTT ACL 全部认他。
        #   实测（2026-10-21 07:29）：随手编的 `evil1792538968abcdefghijklmnop`
        #   一请求就被写进 tokens.json → owner@example.com。
        #   现在路径只用来"猜身份"，**绝不再写 token**；且只在无 Bearer 时生效（A2）。
        #   App 的 token 由 `POST /users/authenticate`（密码校验通过）登记并落盘 tokens.json，
        #   服务重启也不会丢，所以这条路本来就不需要"自学习绑定"。
        return _path_uid
    # ★ 2026-10-21 07:35：删掉「按来源 IP 猜身份」的兜底（原来是 IP_UID 里取最近登录者）。
    #   依据：全量日志里 App 的 roster 请求 **100% 带 Bearer**（`auth=有`），
    #   `auth=无` 的只有 curl 自测。而这条兜底意味着「同一公网 IP 下任何人裸打
    #   /users/~/roster 就能拿到主人的 3 台家庭中心」—— 家里来客人、同 WiFi 任何设备都算。
    #   HTTP 侧本来就有真 token，不需要这条兜底；MQTT 侧仍然用它（那是另一套模型）。
    # 严格模式下宁可返回空（由调用方走单租户兜底），也不能靠一个全局变量
    # 猜出一个「别人的 uid」——那会让 A 看到 B 的家，是最坏的结果。
    if TENANTS:
        return ""
    return LAST_UID or ""


def acl_can_control(sess, hc_uuid):
    """【已废弃，2026-10-20 v3.0 复盘】保留签名，实现改为 fail-closed。

    原来的实现是「身份不明 → 放行」（`if not uid: return True`），
    正是 v2.0 修掉的那个洞的原始形态。全文件已无调用点，但留着 fail-open 的实现
    等于给后来人埋雷：谁把它接回 RPC 路由，安全就静默回退。
    现在改成 fail-closed —— 身份不明一律拒绝。新代码请用 mqtt_can_pub / mqtt_can_sub。
    """
    if not TENANTS:
        return True
    uid = getattr(sess, "uid", None)
    if not uid:
        log("[tenant] acl_can_control(废弃) 身份不明 -> 拒绝 hc=%s" % hc_uuid)
        return False
    if hc_uuid in tenants_of(uid):
        return True
    log("[tenant] 拒绝越权 RPC：uid=%s 试图操作 %s" % (uid, hc_uuid))
    return False


# ============================================================ MQTT 访问控制
# 背景（2026-10-20 复盘实测，P0）：MQTT 侧原本**没有任何鉴权**。
#   ① CONNECT 不校验账号，随便填 username 就 CONNACK 0；
#   ② SUBSCRIBE 不限主题 —— 订阅 `event/+` 就能收到**别人家**的全部事件；
#   ③ PUBLISH 只在「uid 已知且不属于该家」时拒绝，uid 为空时【放行】，
#      所以不订阅 message/* 的匿名会话可以直接向 message/<hc> 下发 RPC，
#      实测拿到了网关 59KB 的 GetEntity 回包。
#
# 为什么不能像 HTTP 那样拿 token 认证：App 的 MQTT CONNECT 里只有随机 username
# （`xy_sbk_*`），**没有密码、没有 token**，服务端无法据此认出用户。
# 所以只能用「同一个公网 IP」做在场证明 —— 这本来就是自动认领用的模型。
#
# 判定顺序（都不信任客户端自报的 uid）：
#   1) 该公网 IP 最近通过 HTTP 登录过谁（IP_UID，30 分钟，落盘）
#   2) 该公网 IP 上有一台在线网关 → 网关归属的账号
#   3) 都不成立 → 拒绝
# MQTT_ACL 的默认值已在文件上方（load_tenants() 调用之前）定义，此处不再重复赋值 ——
# 重复赋值会把 tenants.json 里的 "_mqtt_acl": false 覆盖成 True（开关失效，已修）。


def vg_uuid(hc):
    """box-aa-bb-cc-dd-ee-ff -> box-vg-aa-bb-cc-dd-ee-ff
    （App 的虚拟组别名：session.dart 对每个 HC 无条件 replaceRange(4,12,"vg")）

    ★ 偏移量实测修正：hc[:4] + "vg" + hc[6:]。
      以前写的是 hc[12:]，算出来是 box-vg-90-15-ab（丢掉两段），
      与网关实际使用的虚拟组 uuid 不一致 → 网关订不到虚拟组主题。"""
    if hc and hc.startswith("box-") and len(hc) >= 12:
        return hc[:4] + "vg" + hc[6:]
    return ""


def same_hc_family(a, b):
    if not a or not b:
        return False
    if a == b:
        return True
    return (vg_uuid(a) and vg_uuid(a) == b) or (vg_uuid(b) and vg_uuid(b) == a)


def hc_of_vg(vg):
    """box-vg-aa-bb-cc-dd-ee-ff -> box-aa-bb-cc-dd-ee-ff（vg 主题反查真实 hc）。

    ★ 2026-10-21（AUDIT A5）：不要用字符串硬拼（`box-vg-` → `box-1c-`）——
      那假设 MAC 前缀永远是 1c。这里改成拿已知 hc 集合反查 vg_uuid()，换网关也不会错。
    """
    if not vg or not vg.startswith("box-vg-"):
        return ""
    for hc in known_hc_set():
        if vg_uuid(hc) == vg:
            return hc
    return ""


def mqtt_acl_uids_by_ip(sess):
    """只靠**公网 IP** 认人：IP_UID 登录记录 + 同 IP 在线网关。

    返回列表而不是单值：一个公网 IP 后面可能是一个家里的多台手机 / 多个账号，
    取单一「最后登录者」会让另一台手机立刻被判越权（实测踩过）。"""
    ip = getattr(sess, "pub_ip", "") or ""
    if not ip:
        return []
    out = []
    now = time.time()
    with TENANT_LOCK:
        rec = dict(IP_UID.get(ip) or {})
    out.extend([u for u, ts in rec.items() if now - ts < IP_UID_TTL])
    # 退路：这个公网 IP 上有在线网关 → 用它的归属账号
    with GW_IP_LOCK:
        candidates = [hc for hc, gip in GW_IP.items() if gip and gip == ip]
    if candidates:
        with TENANT_LOCK:
            for hc in candidates:
                for uid, hcs in TENANTS.items():
                    if hc in hcs and uid not in out:
                        out.append(uid)
    return out


def mqtt_acl_uids(sess):
    """MQTT 会话 -> 它**可能**代表哪些账号。只认强证据，绝不用客户端自报的 topic。

    两条判据，先 IP 后指纹（2026-10-24）：
      ① 公网 IP —— 家里 WiFi 场景：HTTP 登录记录 / 同 IP 有在线网关
      ② 设备指纹 —— 4G 漫游场景：手机出口 IP 与家里不同，① 必然落空
         （实测 家里 <宽带出口IP> vs 4G <移动出口IP>），靠 App 安装级
         随机串 `xy_sbk_*` 认人。绑定只在 ① 成立时才写入，见 remember_dev。
    """
    out = mqtt_acl_uids_by_ip(sess)
    if out:
        return out
    fp = dev_fingerprint(getattr(sess, "mqtt_user", "") or "")
    if not fp:
        return out
    now = time.time()
    with TENANT_LOCK:
        rec = dict(DEV_UID.get(fp) or {})
    for u, ts in rec.items():
        if dev_uid_alive(ts, now) and u not in out:
            out.append(u)
    if out:
        log("[acl] 指纹认人 fp=%s... uids=%s ip=%s"
            % (fp[:12], ",".join(out), getattr(sess, "pub_ip", "") or "?"))
    return out


def mqtt_can_sub(sess, topic):
    if not MQTT_ACL:
        return True
    hc = getattr(sess, "hc_uuid", None)
    if hc:
        # 网关：只订自己的 message/<hc>、虚拟组别名，以及自己的 event/
        return topic in ("message/" + hc, "message/" + vg_uuid(hc), "event/" + hc)
    uids = mqtt_acl_uids(sess)
    if not uids:
        log("[acl] 拒绝匿名 SUBSCRIBE %r（来源 IP 没有登录记录，也没有同 IP 的网关）" % topic)
        return False
    if topic.startswith("message/") and topic[8:] in uids:
        return True
    if topic.startswith("event/"):
        t = topic[6:]
        for uid in uids:
            if any(same_hc_family(t, h) for h in tenants_of(uid)):
                return True
    log("[acl] 拒绝越权 SUBSCRIBE uids=%s topic=%r" % (",".join(uids), topic))
    return False


def known_hc_set():
    """服务端**认识**的 hc_uuid 集合。

    用途：网关 CONNECT 自报的 username 必须落在集合内，否则就是拿 box-xxx 乱猜。
    四个来源（任一命中即可，允许网关「还没配 tenants.json 就上线」的兼容路径）：
      · gateways.json（GWS）
      · tenants.json 的归属值（TENANTS）
      · 当前在线的网关（peers_snapshot）
      · 本进程见过公网 IP 的网关（GW_IP，含已掉线的）
    """
    out = set()
    for g in GWS:
        _h = (g or {}).get("hc_uuid")
        if _h:
            out.add(str(_h))
    with TENANT_LOCK:
        for hcs in TENANTS.values():
            for x in (hcs or []):
                out.add(str(x))
    out.update(peers_snapshot().keys())
    with GW_IP_LOCK:
        out.update(GW_IP.keys())
    return out


def mqtt_can_pub(sess, topic):
    if not MQTT_ACL:
        return True
    hc = getattr(sess, "hc_uuid", None)
    if hc:
        # 网关上行只许发这几个主题（收窄，见 2026-10-20 复盘 P1）：
        #   event/<hc>、event/<vg>       —— 设备属性/在线状态，推给 App 的订阅
        #   message/<hc>、message/<vg>   —— RPC 应答、主动上报
        #   message/<uid>                —— 网关要把 RPC 应答发到 App 的 uid 主题
        # 这里的 uid 必须是「拥有该 hc 的账号」；以前允许 message/*（任意），
        # 等于网关会话可以向任意 uid 的收件箱投递伪造报文。
        _vg = vg_uuid(hc)
        allowed = set(["event/" + hc, "message/" + hc])
        if _vg:
            allowed.add("event/" + _vg)
            allowed.add("message/" + _vg)
        if topic in allowed:
            return True
        if topic.startswith("message/"):
            _t = topic[8:]
            # (a) 该 hc 的归属账号 —— 严格模式的正常路径
            with TENANT_LOCK:
                for uid, hcs in TENANTS.items():
                    if _t == uid and hc in (hcs or []):
                        return True
            # (b) 同一个公网 IP 上的账号 —— 兼容「还没配 tenants.json」的单租户部署：
            #     此时 TENANTS 为空，归属无从查起，但网关与手机在同一 NAT 后面，
            #     用 mqtt_acl_uids 得到的账号集就是这台网关「自己家」的手机账号。
            if _t in mqtt_acl_uids(sess):
                return True
        log("[acl] 拒绝网关 PUBLISH hc=%s topic=%r" % (hc, topic))
        return False
    uids = mqtt_acl_uids(sess)
    if not uids:
        log("[acl] 拒绝匿名 PUBLISH %r" % topic)
        return False
    if topic.startswith("message/"):
        t = topic[8:]
        for uid in uids:
            if any(same_hc_family(t, h) for h in tenants_of(uid)):
                return True
        log("[acl] 拒绝越权 PUBLISH uids=%s topic=%r" % (",".join(uids), topic))
        return False
    log("[acl] 拒绝可疑 PUBLISH uids=%s topic=%r" % (",".join(uids), topic))
    return False


# ============================================================ MQTT 基础

def mqtt_varint(n: int) -> bytes:
    out = b""
    while True:
        b = n % 128
        n //= 128
        out += bytes([b | 0x80 if n else b])
        if not n:
            return out


def mqtt_read_varint(data, i):
    mult, val = 1, 0
    while True:
        b = data[i]
        i += 1
        val += (b & 0x7F) * mult
        if not (b & 0x80):
            return val, i
        mult *= 128


def mqtt_read_string(data, i):
    ln = struct.unpack(">H", data[i:i + 2])[0]
    return data[i + 2:i + 2 + ln].decode("utf-8", "replace"), i + 2 + ln


MQTT_NAMES = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
              6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
              10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP",
              14: "DISCONNECT"}


def topic_match(pattern: str, topic: str) -> bool:
    if pattern == topic:
        return True
    p, t = pattern.split("/"), topic.split("/")
    if len(p) != len(t):
        return False
    for a, b in zip(p, t):
        if a == "#":
            return True
        if a not in ("+", b):
            return False
    return True


class Broker:
    def __init__(self):
        self.subs = {}          # topic -> set(Session)
        self.sessions = set()
        self.lock = threading.Lock()

    def subscribe(self, sess, topic):
        with self.lock:
            self.subs.setdefault(topic, set()).add(sess)

    def unsubscribe(self, sess, topic):
        with self.lock:
            self.subs.get(topic, set()).discard(sess)

    def drop(self, sess):
        with self.lock:
            self.sessions.discard(sess)
            for m in self.subs.values():
                m.discard(sess)

    def publish(self, topic, payload, exclude=None, qos=0):
        # ★ 2026-10-21（AUDIT A5）：虚拟组主题桥接，由 tenants.json 的 "_vg_bridge" 控制（默认关）。
        #   背景：网关3 会同时向 event/box-vg-aa-bb-cc-dd-ee-ff 发事件，而 App 只订阅
        #   event/box-aa-bb-cc-dd-ee-ff → 线上统计 15531 条 vg 事件 0 个订阅者。
        #   实测（17841 个 vg sha vs 6645 个 hc sha）**交集为 0**，说明不是重复投递，是真丢了。
        #   桥接方式：把 vg 事件按 hc 主题**改名投递**给 event/<hc> 的订阅者，
        #   让 App 看到的主题始终是它认识的那个。
        targets = []                      # [(session, topic_to_send)]
        with self.lock:
            for pat, members in self.subs.items():
                if topic_match(pat, topic):
                    targets.extend([(m, topic) for m in members])
            if VG_BRIDGE and topic.startswith("event/box-vg-"):
                _hc = hc_of_vg(topic[6:])
                if _hc:
                    _alias = "event/" + _hc
                    for pat, members in self.subs.items():
                        if topic_match(pat, _alias):
                            targets.extend([(m, _alias) for m in members])
        n = 0
        seen = set()
        for s, t in targets:
            if s is exclude or not s.alive or (id(s), t) in seen:
                continue
            seen.add((id(s), t))
            try:
                # 一律用 QoS0 下发：本 broker 没有实现 QoS1 的报文标识符分配
                # 与 PUBACK 重传，按原 qos 转发会在报文里漏掉 packet id，
                # 对端会把 payload 前两字节误读成 id → 整包作废
                # （App 的 mqtt_client 就是这么把网关的 Event 全丢了的）。
                s.send_publish(t, payload, 0)
                n += 1
            except Exception as e:
                log(f"[broker] 推送失败 {s.tag}: {e}")
        return n

    def apps(self):
        with self.lock:
            return [s for s in self.sessions if s.kind == "app"]


BROKER = Broker()

# ---------------------------------------------------------------- 在线宣告（presence）
# 网关连上 broker 后，App 必须收到一条 Event.presence 才会把该家庭中心标成「在线」：
#   mqtt/client.dart 0x8cd1e0 事件分发：topic.split("/")[1] -> getHomeCenterCache()
#     -> 取不到就 return（整条消息丢弃）
#     -> Event.hasPresence() -> HomeCenterManager::processPresence (0x8d778c)
#        -> updateHomeCenterStatus (0x8d7b30)
#           hc.field_13 = online(Bool)   ← 首页横幅「家庭中心离线」的判定位
#           hc.field_f  = Smi(3)         ← getSessionHomeCenters 订阅 peer 的条件
# 之前缺这条消息，App 永远停在离线态、连 GetEntity 都不发。
PEERS = {}            # hc_uuid -> Session（当前连着的网关）
PEER_LOCK = threading.Lock()


def peers_snapshot():
    with PEER_LOCK:
        return dict(PEERS)


def announce_presence(hc_uuid, online, name=""):
    """向 event/<hc uuid> 广播 PresenceEvent（发不到订阅者也无害）。"""
    if not hc_uuid:
        return
    try:
        body = pb.build_event(pb.EVT_PRESENCE,
                              pb.build_presence_event(bool(online), hc_uuid, name),
                              sender=hc_uuid)
    except Exception as e:
        log(f"[presence] 编码失败 {hc_uuid}: {e}")
        return
    n = BROKER.publish("event/" + hc_uuid, body)
    log(f"[presence] {hc_uuid} online={bool(online)} -> {n} 个订阅者")



# ============================================================ 设备缓存

class DeviceCache:
    """网关 JSON 实体 -> 归一化模型，供 protobuf 编码复用"""

    # 网关里 room.name 可能为空（该区域是预分配槽位 / 名字只存在旧云端 DB）。
    # 空名房间若挂了设备就兜底命名，否则整个丢弃，免得 App 里一排空白房间。
    ROOM_FALLBACK = {"area-0000": "未分配"}

    def __init__(self):
        self.lock = threading.Lock()
        self.rooms = {}      # uuid -> name（已过滤/兜底）
        self.devices = {}    # device_uuid -> {model,name,room,online,services[]}
        self.services = {}   # svc_uuid -> {dev_uuid, name, room, profile, attrs{}}
        self.scenes = {}     # scene_uuid -> {name, room, on, online}
        self.gw_uuid = ""    # 组主 UUID（Sender）
        self.room_override = self._load_room_override()

    @staticmethod
    def _load_room_override():
        p = os.path.join(BASE, "rooms.json")
        if not os.path.exists(p):
            return {}
        try:
            d = json.load(open(p, encoding="utf-8"))
            log(f"[cache] 房间名覆盖 {len(d)} 条 <- rooms.json")
            return {str(k): str(v) for k, v in d.items()}
        except Exception as e:
            log(f"[cache] rooms.json 解析失败: {e}")
            return {}

    def load(self, entities, gw_uuid=""):
        devices, services = {}, {}
        for e in entities or []:
            if e.get("type") not in (None, "device"):
                continue
            duid = e.get("id", "")
            devices[duid] = {
                "uuid": duid, "model": e.get("model", ""), "name": e.get("name", ""),
                "room": e.get("room", ""), "online": bool(e.get("online")),
                "services": [],
            }
            for s in e.get("services", []) or []:
                suid = s.get("id") or f"{duid}"
                attrs = {a.get("attr"): a.get("value") for a in s.get("attributes", []) or []}
                services[suid] = {
                    "uuid": suid, "dev_uuid": duid, "name": s.get("name") or e.get("name", ""),
                    "room": s.get("room") or e.get("room", ""),
                    "profile": s.get("profile"), "attrs": attrs,
                    "online": devices[duid]["online"],
                }
                devices[duid]["services"].append(suid)
        with self.lock:
            if devices:
                self.devices, self.services = devices, services
            if gw_uuid:
                self.gw_uuid = gw_uuid
        log(f"[cache] {len(devices)} 设备 / {len(services)} 服务")

    def load_rooms(self, entities):
        """网关 sync type=room -> {uuid: 显示名}。空名且无设备的槽位丢弃。"""
        raw = {}
        for e in entities or []:
            if not isinstance(e, dict) or e.get("type") != "room":
                continue
            ruid = e.get("id") or ""
            if ruid:
                raw[ruid] = (e.get("name") or "").strip()

        with self.lock:
            used = {d.get("room") for d in self.devices.values() if d.get("room")}
            rooms = {}
            for ruid, name in raw.items():
                name = self.room_override.get(ruid) or name or self.ROOM_FALLBACK.get(ruid, "")
                if not name:
                    if ruid not in used:
                        continue                      # 空槽位，无设备，不暴露
                    name = f"房间{ruid[-4:]}"
                rooms[ruid] = name
            self.rooms = rooms
        log(f"[cache] {len(rooms)} 房间（网关给 {len(raw)}，已滤空槽）: "
            + ", ".join(f"{k}={v}" for k, v in list(rooms.items())[:6])
            + (" …" if len(rooms) > 6 else ""))

    def load_scenes(self, entities):
        scenes = {}
        for e in entities or []:
            if not isinstance(e, dict) or e.get("type") != "scene":
                continue
            suid = e.get("id") or ""
            name = (e.get("name") or "").strip()
            if not suid or not name:
                continue                              # 空名场景槽位，不暴露
            scenes[suid] = {"name": name, "room": e.get("room") or "",
                            "on": bool(e.get("on")), "online": bool(e.get("online", True))}
        with self.lock:
            self.scenes = scenes
        log(f"[cache] {len(scenes)} 场景: " + ", ".join(f"{v['name']}" for v in scenes.values()))

    def update_attrs(self, svc_uuid, attrs: dict):
        with self.lock:
            s = self.services.get(svc_uuid)
            if s:
                s["attrs"].update(attrs)

    def get(self, uuid_):
        with self.lock:
            if uuid_ in self.services:
                return self.services[uuid_]
            d = self.devices.get(uuid_)
            if d:
                return d
        return None

    # ---------------- 转 protobuf ----------------

    def _attrs_to_pb(self, attrs: dict):
        out = []
        for name, val in attrs.items():
            aid = pb.ATTR_BY_NAME.get(name)
            if aid is None:
                continue
            if isinstance(val, bool):
                out.append(pb.build_attribute(aid, int(val)))
            elif isinstance(val, int):
                out.append(pb.build_attribute(aid, val))
            elif isinstance(val, str):
                out.append(pb.build_attribute(aid, None, val))
        return out

    def entities_pb(self, types=None, ent_uuid: str = ""):
        """按 GetEntityRequest.types 过滤后返回 LiveEntity 字节列表"""
        want = set(types or [])
        all_types = not want
        out = []
        with self.lock:
            if ent_uuid:
                s = self.services.get(ent_uuid)
                if s:
                    return [self._svc_entity(s)]
                if ent_uuid in self.scenes:
                    sc = self.scenes[ent_uuid]
                    return [pb.build_scene_entity(ent_uuid, sc["name"], sc["room"], sc["on"])]
                if ent_uuid in self.rooms:
                    return [pb.build_room_entity(ent_uuid, self.rooms[ent_uuid])]
                return []
            # 顺序：房间 -> 设备 -> 场景（与 App 侧分组期望一致）
            if all_types or 2 in want:
                for ruid, name in self.rooms.items():
                    out.append(pb.build_room_entity(ruid, name))
            if all_types or 0 in want:
                for s in self.services.values():
                    out.append(self._svc_entity(s))
            if all_types or 1 in want:
                for suid, sc in self.scenes.items():
                    out.append(pb.build_scene_entity(suid, sc["name"], sc["room"], sc["on"]))
        return out

    def _svc_entity(self, s):
        attrs = self._attrs_to_pb(s["attrs"])
        return pb.build_live_entity(
            s["uuid"], s["name"], [0], s.get("room", ""), attrs,
            model=self.devices.get(s["dev_uuid"], {}).get("model", "") or "TERNCY-DEVICE",
            online=s.get("online", True),
        )


CACHE = DeviceCache()

# 最近一次登录的手机号（uid）。
# ★ M3 起它只是【最后兜底】，正常路径走 resolve_uid()：Bearer token -> 路径 uid
#   （2026-10-21 A2 重构后 token 优先；详见 resolve_uid 文档字符串）。
#   （2026-10-21 起 IP 兜底已删除，见 resolve_uid 里的注释）
#   历史背景：App 的每个 HTTP 请求都是独立 TCP 连接（Connection: close），Session 不共享，
#   当初只能用一个全局变量顶着，多租户下必然串号。
LAST_UID = ""


# ============================================================ 网关连接（/ws/json）

class GatewayHub:
    def __init__(self):
        self.gateways = {}
        self.cmd_q = queue.Queue()
        self.evt_q = queue.Queue()
        self._thread = None

    def load_config(self):
        if not os.path.exists(GW_CONFIG_FILE):
            log(f"[hub] 无网关配置 {GW_CONFIG_FILE}（仅做 App 侧协议应答）")
            return []
        try:
            cfg = json.load(open(GW_CONFIG_FILE))
            log(f"[hub] 加载 {len(cfg)} 个网关")
            return cfg
        except Exception as e:
            log(f"[hub] 网关配置解析失败: {e}")
            return []

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        # Python 3.6 兼容：无 asyncio.run()（3.7+），手动管理事件循环
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._main())
        finally:
            loop.close()

    async def _main(self):
        tasks = []
        for g in self.load_config():
            conn = GatewayConn(g["ip"], g.get("token", ""), g.get("username", "ha_user"),
                               g.get("name", "HA User"), g.get("client_id", "homeass_nbhQ43"))
            self.gateways[g["ip"]] = conn
            tasks.append(asyncio.ensure_future(conn.run_forever()))
        tasks.append(asyncio.ensure_future(self._event_pump()))
        tasks.append(asyncio.ensure_future(self._cmd_pump()))
        await asyncio.gather(*tasks, return_exceptions=True)

    def submit(self, intent, prefer=None):
        """投递命令，返回 concurrent.futures.Future（网关响应）。无网关时返回 None。"""
        ip = prefer or (next(iter(self.gateways)) if self.gateways else None)
        if not ip:
            log("[hub] 无网关，命令丢弃")
            return None
        import concurrent.futures as cf
        fut = cf.Future()
        self.cmd_q.put((ip, intent, fut))
        return fut

    async def _cmd_pump(self):
        loop = asyncio.get_event_loop()
        while True:
            ip, d, fut = await loop.run_in_executor(None, self.cmd_q.get)
            conn = self.gateways.get(ip)
            if not conn or not conn.ws:
                log(f"[hub] 网关 {ip} 未连接，丢弃: {short(json.dumps(d).encode())}")
                if fut and not fut.done():
                    fut.set_exception(ConnectionError("gateway offline"))
                continue
            try:
                r = await conn.request(d)
                log(f"[hub] {d.get('intent')} -> {ip} ok: {short(json.dumps(r).encode())[:160]}")
                if fut and not fut.done():
                    fut.set_result(r)
                if d.get("intent") == "execute":
                    await asyncio.sleep(0.4)
                    await conn.sync_devices()   # 用网关真实状态校准缓存
            except Exception as e:
                log(f"[hub] 命令失败 {ip}: {e}")
                if fut and not fut.done():
                    fut.set_exception(e)

    async def _event_pump(self):
        loop = asyncio.get_event_loop()
        while True:
            ev = await loop.run_in_executor(None, self.evt_q.get)
            self._dispatch(ev)

    def _dispatch(self, ev):
        """网关事件 -> App 的 event/<sid>"""
        ents = ev.get("entities") or []
        log(f"[hub] 事件 type={ev.get('type')} entities={len(ents)}")
        for e in ents:
            if e.get("id") and e.get("attributes") is not None:
                attrs = {a.get("attr"): a.get("value") for a in e["attributes"]}
                CACHE.update_attrs(e["id"], attrs)
                payload = pb.build_device_attr_report(
                    e["id"], CACHE._attrs_to_pb(attrs))
                field = pb.EVT_DEVICE_ATTR_REPORT
                if "on" in attrs:
                    payload = pb.build_on_off_status_changed(e["id"], bool(attrs["on"]))
                    field = pb.EVT_ONOFF_STATUS_CHANGED
            else:
                continue
            # ★ 多租户：事件必须按 hc 主题路由，绝不广播给所有 App 会话。
            #   App 订阅的是 event/<HomeCenter uuid>（session.dart 0x8dfd4c 实锤：
            #   Type==3 时 subscribe("event/"+Username)）。
            #   旧实现 `for s in BROKER.apps()` 把事件推给【每一个】App 会话，
            #   多租户下等于把 A 家的设备状态泄漏给 B（潜在路径：/ws/json）。
            _hc = ev.get("hc") or CACHE.gw_uuid
            if not _hc:
                log("[hub] 事件无 hc 归属，丢弃")
                continue
            try:
                body = pb.build_event(field, payload, sender=_hc)
            except Exception as ex:
                log(f"[hub] 事件编码失败 {_hc}: {ex}")
                continue
            _n = BROKER.publish("event/" + _hc, body)
            log(f"[hub] 事件 -> event/{_hc} {_n} 个订阅者")


class GatewayConn:
    def __init__(self, ip, token, username, name, client_id):
        self.ip, self.token = ip, token
        self.username, self.name, self.client_id = username, name, client_id
        self.ws = None
        self._pending = {}

    @property
    def url(self):
        return (f"wss://{self.ip}:443/ws/json?clientId={self.client_id}"
                f"&username={self.username}&token={self.token}")

    async def run_forever(self):
        import websockets
        ctx = ssl._create_unverified_context()
        while True:
            try:
                log(f"[gw:{self.ip}] 连接 /ws/json ...")
                self.ws = await websockets.connect(self.url, ssl=ctx,
                                                   ping_timeout=None, ping_interval=None)
                log(f"[gw:{self.ip}] 已连接")
                # 必须先起接收循环，否则 sync 请求永远等不到应答（v3 的坑）
                recv = asyncio.ensure_future(self._recv_loop())
                await self.sync_all()
                await recv
            except Exception as e:
                log(f"[gw:{self.ip}] 断开 {type(e).__name__}: {e}, 10s 重连")
                self.ws = None
                for f in self._pending.values():
                    if not f.done():
                        f.set_exception(ConnectionError("closed"))
                self._pending.clear()
                await asyncio.sleep(3)

    async def _recv_loop(self):
        async for raw in self.ws:
            await self._on_message(raw)

    async def _on_message(self, raw):
        try:
            d = json.loads(raw)
        except Exception:
            return
        if d.get("intent") == "ping":
            await self.ws.send('{"intent":"pong"}')
            return
        if d.get("rspId") in self._pending:
            self._pending.pop(d["rspId"]).set_result(d)
            return
        if d.get("intent") == "event":
            HUB.evt_q.put(d)

    async def request(self, data, timeout=15):
        rid = data.get("reqId") or uuid.uuid4().hex[:8]
        data["reqId"] = rid
        fut = asyncio.get_event_loop().create_future()
        self._pending[rid] = fut
        await self.ws.send(json.dumps(data))
        return await asyncio.wait_for(fut, timeout=timeout)

    async def sync_devices(self):
        d = await self.request({"intent": "sync", "type": "device"})
        ents = d.get("entities", [])
        gw = ""
        for e in ents:
            if e.get("type") == "homecenter" or e.get("id", "").endswith("-00"):
                gw = e.get("id", "")
                break
        CACHE.load(ents, gw_uuid=gw)
        return ents

    async def sync_all(self):
        """设备 + 房间 + 场景。房间必须在设备之后（要用设备反推哪些空名房间该保留）。"""
        ents = await self.sync_devices()
        for t, fn in (("room", CACHE.load_rooms), ("scene", CACHE.load_scenes)):
            try:
                d = await self.request({"intent": "sync", "type": t})
                fn(d.get("entities", []))
            except Exception as e:
                log(f"[gw:{self.ip}] sync {t} 失败: {e}")
        return ents


HUB = GatewayHub()


# ============================================================ MQTT 会话

class Session:
    def __init__(self, sock, addr, kind="app"):
        self.s = sock
        self.addr = addr
        self.kind = kind
        self.tag = f"{kind}:{addr[0]}:{addr[1]}"
        self.buf = b""
        self.client_id = None
        self.session_id = None
        self.uid = None             # App 会话：由 SUBSCRIBE message/<uid> 还原
        self.hc_uuid = None         # 网关会话：CONNECT username 即家庭中心 uuid
        self.msg_topic = None
        self.evt_topic = None
        self.alive = True
        self.pkt_count = 0          # 诊断：收到的 MQTT 包计数
        self.subs = []              # 诊断：已订阅主题
        self.lock = threading.Lock()
        # 注意：不在此处加入 BROKER.sessions。
        # 之前无条件 add 让每个 HTTP 连接（含公网扫描器）都被 broker 强引用，
        # 引用计数永不归零 → socket 永不回收 → fd 耗尽（Errno 24）。
        # 只有真正升级为 WebSocket 的会话才在 101 之后注册。

    # ---- WebSocket ----
    def _fill(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d:
                return False
            self.buf += d
        return True

    def ws_recv(self, timeout=300):
        self.s.settimeout(timeout)
        if not self._fill(2):
            return None
        b1, b2 = self.buf[0], self.buf[1]
        op, ln, hdr = b1 & 0x0F, b2 & 0x7F, 2
        if ln == 126:
            if not self._fill(4):
                return None
            ln = struct.unpack(">H", self.buf[2:4])[0]
            hdr = 4
        elif ln == 127:
            if not self._fill(10):
                return None
            ln = struct.unpack(">Q", self.buf[2:10])[0]
            hdr = 10
        mask = b""
        if b2 & 0x80:
            if not self._fill(hdr + 4):
                return None
            mask = self.buf[hdr:hdr + 4]
            hdr += 4
        if not self._fill(hdr + ln):
            return None
        data = self.buf[hdr:hdr + ln]
        self.buf = self.buf[hdr + ln:]
        if mask:
            data = bytes(x ^ mask[i & 3] for i, x in enumerate(data))
        return op, data

    def ws_send(self, payload, opcode=2):
        n = len(payload)
        if n < 126:
            hdr = bytes([0x80 | opcode, n])
        elif n < 65536:
            hdr = bytes([0x80 | opcode, 126]) + struct.pack(">H", n)
        else:
            hdr = bytes([0x80 | opcode, 127]) + struct.pack(">Q", n)
        with self.lock:
            self.s.sendall(hdr + payload)

    def send_raw(self, pkt):
        self.ws_send(pkt, 2)

    def send_publish(self, topic, payload, qos=0):
        body = struct.pack(">H", len(topic)) + topic.encode() + payload
        self.send_raw(bytes([0x30 | (qos << 1)]) + mqtt_varint(len(body)) + body)

    # ---- MQTT ----
    def handle(self, pkt):
        ptype, flags = pkt[0] >> 4, pkt[0] & 0x0F
        self.pkt_count += 1
        _, i = mqtt_read_varint(pkt, 1)
        body = pkt[i:]
        name = MQTT_NAMES.get(ptype, f"type{ptype}")

        if ptype == 1:  # CONNECT
            cid, j = mqtt_read_string(body, 0)
            level = body[j]; j += 1
            cflags = body[j]; j += 1
            ka = struct.unpack(">H", body[j:j + 2])[0]; j += 2
            username = None
            if cflags & 0x80:
                username, j = mqtt_read_string(body, j)
            # ★ 取证：App 到底有没有带 password 字段（0x40）。没有的话，MQTT 这条通道
            #   就**根本没有密码可校验**，只能靠 IP/指纹认人 —— 这是安全模型的根。
            password = None
            if cflags & 0x40:
                password, j = mqtt_read_string(body, j)
            self.client_id = cid
            # 设备指纹判据要用（App 是 `xy_sbk_<安装随机串><计数>`，网关是 `box-xxx`）
            self.mqtt_user = username or ""
            log(f"[{self.tag}] CONNECT v{level} clientId={cid!r} user={username!r} ka={ka} "
                f"cflags=0x{cflags:02x} pw={password!r}")
            # ★★ 身份闸门（P0）：没有任何身份依据的连接在这里就断掉 ★★
            # 为什么必须放在 CONNECT：MQTT 的权限口子全在「连接之后」，而客户端
            # 自报的 clientId / username 我们无法验证。历史上有两个直接绕过：
            #   ① CONNECT 自动订阅 clientId 对应的 message/event → 填 clientId=<受害 hc>
            #      就能收到别人家的事件，一条 SUBSCRIBE 都不用发（已删除）；
            #   ② 匿名会话可以向 message/<hc> 下发 RPC（现由 mqtt_can_pub 拦）。
            # 所以「认不出是谁」= 当场拒绝，不给后续任何试探机会。
            # CONNACK return_code：0x00=accepted，0x05=not authorized。
            _pub_ip = getattr(self, "pub_ip", "") or ""
            if username and username.startswith("box-"):
                # —— 网关：username 必须是我们认识的 hc_uuid ——
                if username not in known_hc_set():
                    log("[acl] 拒绝 CONNECT 未知网关 hc=%r ip=%s（不在 GWS/tenants/在线/GW_IP 里）"
                        % (username, _pub_ip or "?"))
                    self.send_raw(b"\x20\x02\x00\x05")
                    self.alive = False
                    return
                # —— P1：首次 IP 锁定，防「抢注网关」——
                # 只有旧连接还活着（同一 hc 仍在线）时才拒绝异地接管；
                # 旧连接已掉线则允许换网/重连，并把绑定 IP 更新成新的。
                with GW_BIND_LOCK:
                    _bound_ip = GW_BIND_IP.get(username)
                if _bound_ip and _pub_ip and _bound_ip != _pub_ip \
                        and username in peers_snapshot():
                    log("[acl] 拒绝冒充网关 hc=%s 已绑定 ip=%s 本次 ip=%s"
                        % (username, _bound_ip, _pub_ip))
                    self.send_raw(b"\x20\x02\x00\x05")
                    self.alive = False
                    return
            else:
                # —— App：来源 IP 或设备指纹必须能还原出至少一个账号 ——
                _ip_uids = mqtt_acl_uids_by_ip(self)
                _uids = mqtt_acl_uids(self)
                if not _uids:
                    log("[acl] 拒绝 CONNECT 无身份 App clientId=%r ip=%s"
                        "（IP 没有登录记录/同 IP 网关，设备指纹也没绑过）"
                        % (cid, _pub_ip or "?"))
                    self.send_raw(b"\x20\x02\x00\x05")
                    self.alive = False
                    return
                # ★ 建立/续期设备指纹绑定：只在 IP 判据已认出人时写，
                #   这样手机在外面（IP 完全不同）也能凭指纹认人。
                if _ip_uids:
                    remember_dev(username, _ip_uids)
                self.uid = _uids[0]     # 只用于日志/展示，ACL 判定仍走 mqtt_acl_uids
            self.send_raw(b"\x20\x02\x00\x00")
            # ★ 已删除「自动订阅 message/<cid>、event/<cid>」两行（P0-1）：
            #   cid 是客户端自选的，服务端直接替它订阅等于绕过 ACL。
            #   线上日志确认 App 和网关都会自己发 SUBSCRIBE，删掉不影响功能。
            self.msg_topic = f"message/{cid}"
            self.evt_topic = f"event/{cid}"
            self.session_id = cid
            # 网关的 CONNECT username 就是家庭中心 uuid（App 侧是随机 xy_sbk_*）。
            # 记住它，稍后即可广播 presence 让 App 把该 HC 标成在线。
            if username and username.startswith("box-"):
                self.hc_uuid = username
                with PEER_LOCK:
                    PEERS[username] = self
                with GW_IP_LOCK:
                    GW_IP[username] = getattr(self, "pub_ip", "")
                    # 只在「本进程第一次看到这台网关」时打点；断线重连不重置窗口。
                    GW_FIRST_SEEN.setdefault(username, time.time())
                with GW_BIND_LOCK:
                    GW_BIND_IP[username] = getattr(self, "pub_ip", "")
                log(f"[{self.tag}] 网关上线 hc={username} ip={getattr(self, 'pub_ip', '?')}")
                announce_presence(username, True)

        elif ptype == 3:  # PUBLISH
            topic, j = mqtt_read_string(body, 0)
            qos = (flags >> 1) & 3
            pid = None
            if qos:
                pid = struct.unpack(">H", body[j:j + 2])[0]
                j += 2
            payload = body[j:]
            if pid is not None:
                self.send_raw(b"\x40\x02" + struct.pack(">H", pid))
            if topic.startswith("event/") or topic.startswith("message/"):
                # 只打长度 + 摘要，不打整包 hex（P2-11）：
                # 以前打 FULL=<hex>，把全屋设备表和读数都写进 cloud4.log（涨到 34MB）。
                # 排查时用 len + sha1 前 8 位就足够对齐同一帧。
                log(f"[{self.tag}] PUBLISH {topic!r} len={len(payload)} "
                    f"sha={hashlib.sha1(payload).hexdigest()[:8]}")
            else:
                log(f"[{self.tag}] PUBLISH {topic!r} len={len(payload)} {short(payload, 60)}")
            # 分流：
            #   · 网关会话（self.hc_uuid 非空）上行 = 上报/应答，只转发，绝不本地应答
            #   · App 会话发到 message/<hc> 且该网关在线 = 原生透传，保真、零逆向
            #   · 其余（没有网关真身）才走本地伪造兜底
            _drop = False
            if not mqtt_can_pub(self, topic):
                _drop = True
            elif self.hc_uuid:
                pass                      # 网关上行：只转发，绝不本地应答
            else:
                # ★ 多租户闸门放在分支之前：保证「网关在线（透传）」和
                #   「网关离线（本地伪造兜底）」两条路都受同一套归属校验。
                if topic.startswith("message/") and topic[8:] in peers_snapshot():
                    log(f"[{self.tag}] 透传 RPC -> 网关 {topic[8:]}")
                else:
                    handle_app_publish(self, topic, payload)
            if _drop:
                # handle() 是逐包调用，return 只跳过这一个包，会话不受影响
                return
            _fwd = BROKER.publish(topic, payload, exclude=self, qos=qos)
            if topic.startswith("event/") or topic.startswith("message/"):
                log(f"[{self.tag}] ROUTE {topic!r} -> {_fwd} 个订阅者")

        elif ptype == 8:  # SUBSCRIBE
            pid = struct.unpack(">H", body[:2])[0]
            topics, j = [], 2
            denied = []
            while j < len(body):
                t, j = mqtt_read_string(body, j)
                j += 1
                topics.append(t)
                if not mqtt_can_sub(self, t):
                    denied.append(t)
                    continue                      # 不注册，也不记进 self.subs
                BROKER.subscribe(self, t)
                if t not in self.subs:
                    self.subs.append(t)
                if t.startswith("message/"):
                    # 注意：这里的 self.uid 只用于展示/兼容，**不再作为 ACL 依据**
                    # （客户端自报，匿名请求也能填别人的 uid；真判定走 mqtt_acl_uid）
                    self.session_id = t[8:]
                    self.msg_topic = t
                    _sid = t[8:]
                    if _sid and not _sid.startswith("box-") and not _sid.startswith("probe"):
                        self.uid = _sid
                elif t.startswith("event/"):
                    self.evt_topic = t
            log(f"[{self.tag}] SUBSCRIBE {topics} sid={self.session_id}"
                + (f" 已拒 {denied}" if denied else ""))
            granted = bytes([0x80 if t in denied else 0x00 for t in topics])
            self.send_raw(b"\x90" + mqtt_varint(2 + len(granted)) + struct.pack(">H", pid) + granted)
            # App 订阅 event/<hc uuid> 就等于「开始关心这个家庭中心」，
            # 此刻立即补一条在线状态，App 才知道它是活的。
            # （只在网关确实连着该 hc 时发，避免谎报在线。）
            _peers = peers_snapshot()
            for t in topics:
                if t.startswith("event/"):
                    _hc = t[6:]
                    if _hc in _peers:
                        announce_presence(_hc, True)


        elif ptype == 10:  # UNSUBSCRIBE
            pid = struct.unpack(">H", body[:2])[0]
            j = 2
            while j < len(body):
                t, j = mqtt_read_string(body, j)
                BROKER.unsubscribe(self, t)
            self.send_raw(b"\xb0\x02" + struct.pack(">H", pid))

        elif ptype == 12:  # PINGREQ
            self.send_raw(b"\xd0\x00")

        elif ptype == 14:
            log(f"[{self.tag}] DISCONNECT")
            self.alive = False

        else:
            log(f"[{self.tag}] {name} flags={flags} {short(body, 40)}")

    def kick(self, reason=""):
        """★ 真正断开这条 MQTT 会话（后台解绑设备指纹时用）。

        只置 alive=False 是不够的：run() 正阻塞在 socket recv，长连接还会继续
        收发，App 已订阅的 event/<hc> 照样收事件、照样能下发控制 —— 那样解绑
        就是假的。必须关掉 socket 让 recv 抛错退出，BROKER.drop 才会真正执行。"""
        self.alive = False
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.s.close()
        except Exception:
            pass
        BROKER.drop(self)
        log("[admin] 踢掉会话 %s（%s）" % (self.tag, reason or "无原因"))

    def run(self):
        try:
            while self.alive:
                fr = self.ws_recv(320)
                if fr is None:
                    break
                op, data = fr
                if op == 8:
                    break
                if op == 9:
                    self.ws_send(data, 10)
                    continue
                if op in (1, 2):
                    buf = data
                    while len(buf) >= 2:
                        try:
                            rem, i = mqtt_read_varint(buf, 1)
                        except IndexError:
                            break
                        if len(buf) < i + rem:
                            break
                        self.handle(buf[:i + rem])
                        buf = buf[i + rem:]
        except Exception as e:
            log(f"[{self.tag}] 结束 {type(e).__name__}: {e}")
        finally:
            self.alive = False
            BROKER.drop(self)
            if self.hc_uuid:
                with PEER_LOCK:
                    if PEERS.get(self.hc_uuid) is self:
                        PEERS.pop(self.hc_uuid, None)
                        _gone = True
                    else:
                        _gone = False
                if _gone:
                    log(f"[{self.tag}] 网关掉线 hc={self.hc_uuid}")
                    announce_presence(self.hc_uuid, False)
            try:
                self.s.close()
            except Exception:
                pass


# ============================================================ App 请求处理
# ★★★ AUDIT C1（2026-10-21 评估）：本段（handle_app_publish / exec_gateway / DeviceCache）
#   是【仅离线兜底】路径 —— 线上 App 全部走 MQTT 透传（最近 5000 行日志 0 次 RPC），
#   这里的本地伪造 RPC 分支线上从不执行。保留是为了局域网直连/排障，不要据此推断线上行为；
#   exec_gateway 已按 hc 精确选网关（C1），DeviceCache 勿删（Sender 还在用）。

def exec_gateway(uid: str, attr: str, value, hc: str = "") -> int:
    """下发 execute 并等网关回执；返回 0=成功，非 0=设备拒绝/离线（直接透传网关 code）

    ★ 2026-10-21（AUDIT C1）：hc 非空时按 hc->ip 精确选网关（GW_IP 映射）。
      原来 prefer=None 会让 HUB.submit 在在线网关里**任意挑一台**——多租户下
      A 家的控制指令可能被发到 B 家网关（既控错设备，也越权）。无法映射时
      记日志并退回原选路（保持离线兜底路径可用）。
    """
    prefer = ""
    if hc:
        with GW_IP_LOCK:
            prefer = GW_IP.get(hc, "")
        if not prefer:
            log(f"[exec] hc={hc!r} 无在线网关映射，退回自动选路")
    fut = HUB.submit({"intent": "execute", "entities": [
        {"id": uid, "attributes": [{"attr": attr, "value": value, "method": 0}]}]},
        prefer=prefer or None)
    if fut is None:
        return 1
    try:
        r = fut.result(timeout=5)
    except Exception as e:
        log(f"[exec] {uid}.{attr}={value} 失败: {e}")
        return 2
    code = 0
    for e in (r or {}).get("entities", []):
        for a in e.get("attributes", []):
            if a.get("attr") == attr and a.get("code") is not None:
                code = int(a["code"])
    log(f"[exec] {uid}.{attr}={value} -> code={code}")
    return code


def reply(sess: Session, oneof: int, payload: bytes, req: dict, sender: str = ""):
    msg = pb.build_message(oneof, payload, correlation_id=req.get("MessageID", ""),
                           sender=sender or CACHE.gw_uuid, time_raw=req.get("Time_raw"))
    topic = sess.msg_topic or f"message/{sess.session_id or sess.client_id}"
    sess.send_publish(topic, msg)
    return msg


def handle_app_publish(sess: Session, topic: str, payload: bytes):
    if not topic.startswith("message/"):
        return
    try:
        req = pb.parse_message(payload)
    except Exception as e:
        log(f"[{sess.tag}] protobuf 解析失败: {e} raw={payload[:80].hex()}")
        return
    oneof = req["oneof"]
    log(f"[{sess.tag}] RPC #{oneof} from={req['Sender']!r} id={req['MessageID'][:8]}")
    p = req["payload"]
    # 请求方家庭中心（topic: message/<hc>）。AUDIT C1：exec_gateway 按它精确选网关
    _req_hc = topic[8:] if topic.startswith("message/") else ""

    if oneof == pb.MSG_GET_ENTITY:
        q = pb.parse_get_entity_request(p)
        log(f"[{sess.tag}]   GetEntity types={q['types']} idx={q['index']} cnt={q['count']} uuid={q['ent_uuid']!r}")
        # ★ 多租户：本地缓存只属于一个 hc（CACHE.gw_uuid 记录它是谁的）。
        #   请求方问的不是缓存主人的家时，绝不能把别人的设备表吐出去。
        #   ★ AUDIT C2/B8（2026-10-21 评估）：该守卫 fail-closed（宁可误伤不泄露）。
        #   线上此路径已死（最近 5000 行日志 0 次 RPC），保持现状不改行为；
        #   CACHE.gw_uuid 只在为空时被 roster 回填，见 2630 行附近注释。
        if TENANTS and CACHE.gw_uuid and _req_hc and CACHE.gw_uuid != _req_hc:
            log(f"[{sess.tag}]   GetEntity 跨租户请求 {_req_hc} != {CACHE.gw_uuid} -> 返回空")
            ents = []
        else:
            ents = CACHE.entities_pb(q["types"], q["ent_uuid"])
        # 分页：App 固定 count=20、index 递增（见 RE_DEEPEN2 §5）
        total = len(ents)
        if total == 0:
            # ★ AUDIT B8（2026-10-21 评估后仅加可见性，不改行为）：缓存为空时回空表
            #   会把 App 首页刷空。线上此路径已死（5000 行日志 0 次 RPC）；彻底修法
            #   （回上一次缓存 / 不回包）需要持久化缓存，超出范围，先留痕告警。
            log(f"[{sess.tag}]   GetEntity 缓存为空 -> 回空表（B8 已知取舍，仅离线兜底路径）")
        start = max(0, q["index"] or 0)
        cnt = q["count"] or 20
        page = ents[start:start + cnt]
        remaining = max(0, total - start - len(page))
        log(f"[{sess.tag}]   返回 {len(page)}/{total} 条，剩余 {remaining}")
        reply(sess, pb.MSG_GET_ENTITY_RESULT,
              pb.build_get_entity_result(page, remaining), req)

    elif oneof == pb.MSG_ONOFF:
        q = pb.parse_on_off_request(p)
        log(f"[{sess.tag}]   OnOff {q['uuid']} on={q['on']}")
        status = exec_gateway(q["uuid"], "on", 1 if q["on"] else 0, hc=_req_hc)
        reply(sess, pb.MSG_ONOFF_RESULT, pb.build_on_off_result(status), req)

    elif oneof == pb.MSG_SET_SCENE_ONOFF:
        q = pb.parse_set_scene_onoff_request(p)
        cmd = (q["command"] or [1])[0]
        on = cmd != 0                                  # OnOffCommand: 0=Off 1=On 2=Toggle
        log(f"[{sess.tag}]   SetSceneOnOff {q['uuid']} cmd={cmd}")
        status = exec_gateway(q["uuid"], "on", 1 if on else 0, hc=_req_hc)
        reply(sess, pb.MSG_SET_SCENE_ONOFF_RESULT,
              pb.build_set_scene_onoff_result(q["uuid"], on and status == 0), req)

    elif oneof == pb.MSG_WRITE_ATTRIBUTE:
        d = pb.parse(p)
        uid = pb.as_str(pb.one(d, 1, b""))
        ids = pb.ints(d, 2)
        aid = ids[0] if ids else None
        name = pb.ATTR_ID.get(aid) or pb.ATTR_GUESS.get(aid)
        ival = pb.one(d, 3, None)
        sval = pb.as_str(pb.one(d, 4, b""))
        log(f"[{sess.tag}]   WriteAttribute {uid} AttrID={aid}({name}) int={ival} str={sval!r}")
        code = 0
        if name:
            code = exec_gateway(uid, name, ival if ival is not None else sval, hc=_req_hc)
        reply(sess, pb.MSG_WRITE_ATTRIBUTE_RESULT, pb.build_write_attribute_result(code), req)

    elif oneof == pb.MSG_READ_ATTRIBUTE:
        d = pb.parse(p)
        uid = pb.as_str(pb.one(d, 1, b""))
        ids = pb.ints(d, 2)
        aid = ids[0] if ids else None
        name = pb.ATTR_ID.get(aid) or pb.ATTR_GUESS.get(aid)
        ent = CACHE.get(uid) or {}
        val = (ent.get("attrs") or {}).get(name)
        log(f"[{sess.tag}]   ReadAttribute {uid} AttrID={aid}({name}) -> {val!r}")
        # ReadAttributeResponse{1 Code, 2 Value, 3 ValueStr}：一次一个属性
        if isinstance(val, int):
            payload = pb.build_read_attribute_result(0, int_value=val)
        elif isinstance(val, str):
            payload = pb.build_read_attribute_result(0, str_value=val)
        else:
            payload = pb.build_read_attribute_result(1)      # 未知属性 -> 非 0 code
        reply(sess, pb.MSG_READ_ATTRIBUTE_RESULT, payload, req)

    elif oneof == pb.MSG_GET_TIME:
        # GetTimeResponse{1 Time, 2 TimeZone}；App 侧格式串为 "yyyy-MM-dd"
        lt = time.localtime()
        off = -(time.altzone if lt.tm_isdst else time.timezone)
        tz = f"{'+' if off >= 0 else '-'}{abs(off)//3600:02d}:{abs(off)%3600//60:02d}"
        reply(sess, pb.MSG_GET_TIME_RESULT,
              pb.enc_str(1, time.strftime("%Y-%m-%d %H:%M:%S", lt)) + pb.enc_str(2, tz), req)

    elif oneof == pb.MSG_GET_CLOUD_SERVER:
        reply(sess, pb.MSG_GET_CLOUD_SERVER_RESULT,
              pb.build_cloud_server_result(PUBLIC_API, PUBLIC_WS), req)

    elif oneof == pb.MSG_SET_CLOUD_SERVER:
        d = pb.parse(p)
        log(f"[{sess.tag}]   SetCloudServer api={pb.as_str(pb.one(d,3,b''))} ws={pb.as_str(pb.one(d,4,b''))}")
        reply(sess, pb.MSG_SET_CLOUD_SERVER_RESULT, pb.enc_uint(1, 0), req)

    else:
        # 未知 RPC：回一个空 payload 的同号 Result（编号+1），避免 App 挂起。
        # 但绝不能对「认不出来的报文」也这么做：
        #   1) 网关的应答里有些 oneof 我们没建模，oneof 可能是 None，
        #      None + 1 直接抛 TypeError；
        #   2) 一抛异常，Session.run 的 finally 就把这条连接关了 ——
        #      曾经因此把网关的 MQTT 会话打死（网关应答还没路由给 App 就断线）。
        if oneof is None:
            log(f"[{sess.tag}]   无法识别的报文（oneof=None），仅转发不回复")
            return
        log(f"[{sess.tag}]   未实现 RPC #{oneof}，回空 Result #{oneof + 1}")
        reply(sess, oneof + 1, b"", req)


# ============================================================ HTTP

def read_http_head(c):
    data = b""
    while b"\r\n\r\n" not in data:
        d = c.recv(4096)
        if not d:
            return None, b""
        data += d
        if len(data) > 65536:
            break
    head, _, rest = data.partition(b"\r\n\r\n")
    return head.decode("iso-8859-1").split("\r\n"), rest


def roster_probe(tag, uid):
    """roster 返回 8 秒后回看 App 的 MQTT 会话，用于区分三种失败形态：
       会话在 + 有包  → App 还活着，卡在解析之后（如 mDNS/checkToken）
       会话在 + 零包  → App 内部闭包静默死亡（Dart 异常）
       会话消失       → App 主动断开重试

    ★ 2026-10-20 v3.0：这是调试期临时加的探针，**默认关闭**。
      它每次 roster 都 dump 一遍全部 MQTT 会话（单行可达 1KB），
      实测一天能刷掉近 10MB 日志，还会把真正有用的行挤掉。
      需要排障时：`PROBE=1 systemctl restart xiaoyan-cloud`。
    """
    if not os.environ.get("PROBE"):
        return
    def _run():
        try:
            rows = []
            for s in list(BROKER.sessions):
                rows.append("cid=%r sid=%r pkts=%d alive=%s subs=%s" % (
                    s.client_id, s.session_id, s.pkt_count, s.alive, s.subs))
            log("[%s] PROBE+8s uid=%s %s" % (tag, uid, rows or "无 MQTT 会话"))
        except Exception as e:
            log("[%s] PROBE 异常 %s: %s" % (tag, type(e).__name__, e))
    try:
        threading.Timer(8.0, _run).start()
    except Exception:
        pass


def handle_http(sess: Session, lines, rest):
    global LAST_UID
    method, path = (lines[0].split(" ") + ["", ""])[:2]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    # ★ 2026-10-21（AUDIT B7）：服务在 nginx 后面，sess.addr 永远是 127.0.0.1，
    #   日志里的 tag 也就永远是 127.0.0.1——排障时无法区分客户端。这里按请求刷新
    #   tag 为真实公网 IP（X-Real-IP / X-Forwarded-For，与身份判定同一来源）。
    sess.tag = "%s:%s" % (sess.kind, client_ip(sess, headers))
    clen = int(headers.get("content-length", "0") or 0)
    # ★ 2026-10-21（AUDIT B3）：请求体上限。nginx 限 50m，但 python 侧每连接一个线程，
    #   大 body 会同时占内存与线程。App 最大的请求是注册/association（几百字节），
    #   2MB 对正常路径宽达三个数量级，超限直接 413，一个字节都不读。
    if clen > 2 * 1024 * 1024:
        log(f"[{sess.tag}] 拒绝超大请求体 clen={clen} path={path}")
        rb = b'{"code":413,"message":"payload too large"}'
        sess.s.sendall((f"HTTP/1.1 413 Payload Too Large\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(rb)}\r\nConnection: close\r\n\r\n").encode() + rb)
        return
    body = rest
    while len(body) < clen:
        d = sess.s.recv(4096)
        if not d:
            break
        body += d

    # 扫描器探测：404 且每条路径只记一次，避免把日志刷爆
    bare = path.split("?")[0]
    qs = path.split("?", 1)[1] if "?" in path else ""

    # ★★ Web 入口必须放在 is_scanner 之前 ★★
    #   SCANNER_HINTS 里有 "admin" / "password"，如果先跑扫描器判定，
    #   我们自己的 /admin 和 /users/<uid>/password 会被当成扫描器直接 404。
    if HAS_WEB and (bare == "/" or bare == "/admin" or bare.startswith("/admin/")):
        try:
            st, hdrs, rbody = admin_web.handle(ADMIN_BE, method, bare, qs, headers,
                                               body, client_ip(sess, headers))
        except Exception as e:
            log(f"[{sess.tag}] web 后台异常 {type(e).__name__}: {e}")
            st, hdrs, rbody = 500, {}, b"internal error"
        if st in (301, 302, 303):
            log(f"[{sess.tag}] -> {st} {bare} -> {hdrs.get('Location', '')}")
        elif st >= 400:
            log(f"[{sess.tag}] -> {st} {bare}")
        # Content-Type 默认 text/html；admin_web 自己带了（JSON API / 静态资源）就以它的为准。
        # 2026-10-21 前端改造前，这里硬编码 text/html 会把 app.css/app.js 打成双 Content-Type 头，
        # 浏览器直接拒载。旧页面从不自带该头，行为不变。
        _hdr_names = set(str(k).lower() for k in (hdrs or {}))
        _ct = "" if "content-type" in _hdr_names else "Content-Type: text/html; charset=utf-8\r\n"
        head = (f"HTTP/1.1 {st} {_HTTP_REASON.get(st, 'OK')}\r\n"
                f"{_ct}"
                f"Content-Length: {len(rbody)}\r\n"
                f"Cache-Control: no-store\r\nConnection: close\r\n")
        for k, v in (hdrs or {}).items():
            head += f"{k}: {v}\r\n"
        head += "\r\n"          # 空行分隔 header 与 body —— 少了它 nginx 会把 HTML 当 header 读
        sess.s.sendall(head.encode() + rbody)
        return

    # App 改密码：PATCH /users/<uid>/password（真机实测，App 用的是 PATCH 不是 POST）
    # 同样含 "password"，也得抢在扫描器判定之前。
    if (bare.startswith("/users/") and bare.rstrip("/").endswith("/password")
            and method.upper() in ("POST", "PATCH", "PUT")):
        try:
            req = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            req = {}
        _puid = bare.strip("/").split("/")[1]
        if _puid in ("~", "me", ""):
            _puid = resolve_uid(sess, headers, path)
        _old = (req.get("old_password") or req.get("oldPassword")
                or req.get("current_password") or req.get("credential") or "")
        _new = (req.get("new_password") or req.get("newPassword")
                or req.get("password") or "")
        log(f"[{sess.tag}] 改密码 uid={_puid!r} fields={sorted(req.keys())}")
        _ok, _msg = False, "参数不足"
        _acct = auth.get(_puid) if HAS_WEB else None
        _pwip = client_ip(sess, headers)
        if HAS_WEB and auth.throttled("pw:" + _pwip):
            # ★ 2026-10-21（AUDIT B1）：改密接口原来完全不限速 ——
            #   登录有 8 次/10 分钟，改密没有，等于给了另一条爆破通道。
            _msg = "操作太频繁，请 10 分钟后再试"
            log(f"[{sess.tag}] 改密限速命中 ip={_pwip}")
        elif not _puid or not _new:
            _msg = "参数不足"
        elif not _acct:
            # ★ 不存在的账号绝不能 set_password（P1-7）：
            #   auth.set_password 对未知 uid 会直接创建账号 —— 等于任何人
            #   PATCH /users/<任意邮箱>/password 就能「抢注」别人还没注册的邮箱，
            #   之后真主人再注册/登录就被顶掉。这里只允许改**已存在**账号的密码。
            _msg = "该邮箱未注册"
            log(f"[{sess.tag}] 拒绝改密码：账号不存在 uid={_puid!r}")
        elif not _acct.get("pw"):
            # ★ 2026-10-21（AUDIT B2）：原来是 `elif _acct.get("pw") and not check_pw(...)`，
            #   pw 为空时整个条件为假 → 直接走 set_password，**不校验旧密码**（fail-open）。
            #   迁移遗留账号 / 手工编辑过的 accounts.json 都可能出现空 pw，等于后门。
            _msg = "该账号未设置密码，请联系管理员重置"
            log(f"[{sess.tag}] 拒绝改密码：账号 pw 为空 uid={_puid!r}（需管理员重置）")
        elif not auth.check_pw(_old, _acct["pw"]):
            _msg = "原密码不正确"
        else:
            _ok, _msg = auth.set_password(_puid, _new)
        if not _ok and HAS_WEB:
            auth.note_fail("pw:" + _pwip)      # 失败也计数（成功不计数，避免自己把自己锁住）
        _res = {"status_code": 20000, "code": 0, "message": "ok", "status": "ok",
                "data": {}} if _ok else {"status_code": 40100, "code": 401,
                                         "message": _msg, "status": "error"}
        _rb = json.dumps(_res).encode()
        sess.s.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(_rb)}\r\nConnection: close\r\n\r\n").encode() + _rb)
        if _ok:
            # ★ 2026-10-21 11:35（AUDIT A3 遗留）：改密后吊销该账号的**其他** token。
            #   以前改密码完全不碰 TOKENS —— 被盗 token 永久有效，只能手工编辑 tokens.json。
            #   这里保留**本次请求所用的**那个 token（否则 App 改完密立刻掉线，体验很怪），
            #   其余全部吊销。返回体里带上吊销数量，方便后台/日志核对。
            _cur_tk = (headers.get("authorization") or "").strip()
            _cur_tk = _cur_tk[7:].strip() if _cur_tk[:7].lower() == "bearer " else ""
            _revoked = 0
            with TENANT_LOCK:
                for _k in [k for k, v in TOKENS.items() if v == _puid and k != _cur_tk]:
                    TOKENS.pop(_k, None)
                    _revoked += 1
            if _revoked:
                save_tokens()
            # ★★ 2026-10-24：改密必须同时清掉**设备指纹绑定**，否则等于没改。
            #   MQTT 那条通道既不认 token 也不认密码，只认指纹；丢了/卖了手机的人改了密码，
            #   旧手机照样能订阅 `event/<hc>` 和下发 `message/<hc>`（指纹还是永久有效）。
            #   只吊销 token 是挡不住的 —— 这就是「改了密码对方还能控我家灯」的口子。
            _dev_cleared = 0
            with TENANT_LOCK:
                for _fp in list(DEV_UID.keys()):
                    _rec = DEV_UID.get(_fp) or {}
                    if _puid in _rec:
                        _rec.pop(_puid, None)
                        _dev_cleared += 1
                        if not _rec:
                            DEV_UID.pop(_fp, None)
            if _dev_cleared:
                save_devuid(force=True)
            # 让**当前这台**设备立刻自愈：改密请求本身带有效 token（强凭据），
            # 把当前 IP 记为可信 → App 重连时命中 IP 判据 → 自动重新绑定指纹，用户无感；
            # 而丢的那台手机在别的 IP，指纹已清且没有 IP 依据 → 永久挡在外面。
            remember_uid(_pwip, _puid)
            log(f"[{sess.tag}] -> 改密码成功 uid={_puid} 吊销其他 token {_revoked} 条、"
                f"清除设备指纹绑定 {_dev_cleared} 条（其他设备须重新在家认证）")
        return

    if is_scanner(bare):
        if bare not in SEEN_UNKNOWN:
            SEEN_UNKNOWN.add(bare)
            log(f"[{sess.tag}] 扫描器路径 {method} {bare} -> 404（后续同类不再记录，"
                f"已记 {len(SEEN_UNKNOWN)} 条）")
        rb = b'{"code":404,"message":"not found"}'
        sess.s.sendall((f"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(rb)}\r\nConnection: close\r\n\r\n").encode() + rb)
        return

    log(f"[{sess.tag}] HTTP {method} {path}")
    if body:
        log(f"[{sess.tag}]   body={short(body, 300)}")

    # ★ 每个请求进站先统一解析一次身份。
    #   放在这里（而不是只在 roster 分支里调）的原因：
    #   App 冷启动走的是 POST /users/<uid>/token，那条分支自己不解析身份，
    #   导致 Bearer token 永远绑不上 —— 只有这条路径能顺手完成「路径 uid + token」绑定。
    _req_uid = resolve_uid(sess, headers, path)

    if headers.get("upgrade", "").lower() == "websocket":
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        proto = headers.get("sec-websocket-protocol", "")
        extra = f"\r\nSec-WebSocket-Protocol: {proto.split(',')[0].strip()}" if proto else ""
        sess.s.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}{extra}\r\n\r\n").encode())
        log(f"[{sess.tag}] -> WS 101 ({proto!r})")
        sess.buf = b""
        # 记下这条长连接的公网 IP：网关连上来时用它做「同一个家」的核对依据
        sess.pub_ip = client_ip(sess, headers)
        sess.tag = "%s:%s" % (sess.kind, sess.pub_ip)   # AUDIT B7：WS 日志同样带真实 IP
        BROKER.sessions.add(sess)   # 只有真正长连接的会话才进 broker
        sess.run()
        return

    if path.startswith("/verificationcodes"):
        # App 侧流程（login_userinfo_page）：
        #   POST /verificationcodes  body={push_type,push_target,purpose,...}
        #   响应必须含 verification_code_id(String?)，否则 App 认为发送失败并重试
        # 没有短信网关，这里只发一个 id；登录时 authenticate 接受任意验证码。
        try:
            req = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            req = {}
        vcid = "vc-" + uuid.uuid4().hex[:20]
        target = req.get("push_target") or req.get("number") or req.get("username") or ""
        payload = {
            # App 的 HTTP 层统一读 status_code(int?) 作为成功判据，成功值是 20000。
            # 反汇编里写作 `mov x17, #0x9c40; cmp w0, w17`，0x9c40=40000 是 Dart Smi
            # 的**带标记**形式（raw = 实际值<<1），实际比较的是 20000。
            # 缺字段或值不符都会导致「获取验证码」被判失败并自动重试。
            "status_code": 20000,
            "code": 0, "message": "ok", "status": "ok",
            "verification_code_id": vcid,
            "verificationCodeId": vcid,
            "expire_in_second": 300,
            "expireInSecond": 300,
            "push_target": target,
            "data": {
                "verification_code_id": vcid,
                "verificationCodeId": vcid,
                "expire_in_second": 300,
                "expireInSecond": 300,
                "push_target": target,
            },
        }
        resp_body = json.dumps(payload).encode()
        log(f"[{sess.tag}] -> verificationcodes 200 id={vcid} target={target} "
            f"req={ {k: req[k] for k in req} }")
    elif bare == "/users" and method.upper() == "POST":
        # ★ App 内「注册」按钮：HttpProxy::register (0xc2dd4c) → POST /users
        #   反汇编实锤（http_proxy.dart 0xc2dd4c 附近）请求体：
        #     {"id_type":"email|mobile", "id":"<账号>", "credential":"<用户自设密码>",
        #      "verification_code_id":"vc-..."}
        #   App 拿 status_code==20000 当成功（其余走 error 分支弹提示）。
        #   注意：我们不发短信/邮件，verification_code_id 无法验证真伪，
        #   所以只做「格式 + 是否重复 + IP 限速」，密码强度交给 auth 校验。
        try:
            req = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            req = {}
        _ip = client_ip(sess, headers)
        _uid = auth.normalize(req.get("id") or req.get("username")
                              or req.get("email") or req.get("mobile") or "") if HAS_WEB else ""
        _pw = req.get("credential") or req.get("password") or ""
        _ok, _msg = False, "服务未启用账号模块"
        if not HAS_WEB:
            _msg = "服务未启用账号模块"
        elif auth.throttled("reg:" + _ip):
            _msg = "操作太频繁，请 10 分钟后再试"
        elif not _uid:
            _msg = "缺少账号"
        elif auth.has_password(_uid):
            _msg = "该账号已注册，请直接登录"
        else:
            _ok, _msg = auth.create(_uid, _pw, nickname=_uid)
            auth.note_fail("reg:" + _ip)          # 成功也计数，挡批量刷号
            if _ok:
                ADMIN_BE.ensure_tenant(_uid)
        if _ok:
            _user = {"id": _uid, "name": _uid, "nickname": _uid,
                     "mobile": "", "phone": "",
                     "email": _uid, "email_confirmed": True,
                     "id_type": "email", "role": "user", "user_role": "user",
                     "open_ids": [], "avatar": "", "avatar_url": ""}
            payload = {"status_code": 20000, "code": 0, "message": "ok", "status": "ok"}
            payload.update(_user)
            payload["data"] = dict(_user, created=int(time.time()))
            resp_body = json.dumps(payload).encode()
            log(f"[{sess.tag}] -> 注册 200 uid={_uid!r} ip={_ip} "
                f"ua={(headers.get('user-agent') or '')[:60]}")
        else:
            resp_body = json.dumps({"status_code": 40100, "code": 401,
                                    "message": _msg, "status": "error",
                                    "error": _msg, "data": {}}).encode()
            log(f"[{sess.tag}] -> 注册 40100 uid={_uid!r} ip={_ip} reason={_msg}")
    elif path.startswith("/users/authenticate"):
        sid = str(uuid.uuid4())
        token = "tk-" + sid.replace("-", "")[:24]
        refresh = "rt-" + sid.replace("-", "")[:24]
        uid = "u-" + sid[:8]
        try:
            req = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            req = {}
        # App 实际发的登录体是 snake_case：
        #   {"id_type":"mobile","id":"1997...","credential":"123456",
        #    "client_id":"xy_android_...","verification_code_id":"vc-..."}
        # 登录成功后 App 调 LoginManager::storeUsernameAndToken(username, access_token)，
        # 所以响应必须同时给 **username** 和 **access_token**（下划线），
        # 只给 accessToken 驼峰是不认的。
        who = (req.get("id") or req.get("username") or req.get("mobile")
               or req.get("phone") or req.get("email") or "")
        credential = req.get("credential") or req.get("password") or ""
        vcid = req.get("verification_code_id") or req.get("verificationCodeId") or ""
        _ip = client_ip(sess, headers)
        _ua = (headers.get("user-agent") or "")[:60]
        if HAS_WEB:
            who = auth.normalize(who)

        # ★★ 密码校验（2026-10-20 修 P0：以前这里谁都不校验，知道账号名就能冒充）★★
        #   · 已注册账号必须给对密码；密码用 PBKDF2 哈希存 accounts.json
        #   · **只允许邮箱账号**（2026-10-20 定稿）：App 对手机号只给验证码入口，
        #     而本服务器没有短信通道 → 手机号账号注册完就登不进来，所以直接拒绝
        #   · 验证码登录一律拒绝：没有短信/邮件通道，无法证明那个码是真的
        #   · 未注册账号直接拒绝，引导在 App 里注册
        _deny = ""
        if not HAS_WEB:
            log("[auth] ⚠ auth 模块未加载，登录校验被跳过（危险，请检查文件）")
        elif not who:
            _deny = "缺少账号"
        elif "@" not in who:
            _deny = "本服务器只支持邮箱登录，请用邮箱账号"
        elif auth.throttled("login:" + _ip):
            _deny = "尝试次数过多，请 10 分钟后再试"
        else:
            _acct = auth.get(who)
            if not _acct or not _acct.get("pw"):
                _deny = "该邮箱未注册，请先在 App 登录页点「注册」"
            elif not _acct.get("enabled", True):
                _deny = "账号已停用"
            elif vcid:
                _deny = "本服务器只支持邮箱+密码登录，不发验证码"
            elif not auth.check_pw(credential, _acct.get("pw")):
                _deny = "密码不正确"

        if _deny:
            if HAS_WEB and who and _deny not in ("尝试次数过多，请 10 分钟后再试",):
                auth.note_fail("login:" + _ip)
            payload = {"status_code": 40100, "code": 401,
                       "message": _deny, "status": "error",
                       "error": _deny, "data": {}}
            resp_body = json.dumps(payload).encode()
            log(f"[{sess.tag}] -> authenticate 40100 user={who!r} ip={_ip} "
                f"reason={_deny} ua={_ua}")
        else:
            payload = {
                "status_code": 20000,
                "code": 0, "message": "ok", "status": "ok",
                # —— 下划线命名（App 真正读取的）——
                "access_token": token,
                "refresh_token": refresh,
                "user_id": uid,
                "session_id": sid,
                "expires_in": 86400 * 365,
                "username": who,
                "phone": "",
                "nickname": who,
                "email": who,
                "id_type": "email",
                # —— 驼峰命名（保留兼容）——
                "token": token,
                "accessToken": token, "refreshToken": refresh,
                "userId": uid, "sessionId": sid, "expiresIn": 86400 * 365,
                "data": {
                    "access_token": token, "refresh_token": refresh,
                    "user_id": uid, "session_id": sid, "expires_in": 86400 * 365,
                    "username": who, "phone": "", "email": who,
                    "nickname": who, "id_type": "email",
                    "token": token, "accessToken": token,
                    "userId": uid, "sessionId": sid,
                },
            }
            resp_body = json.dumps(payload).encode()
            # 登记 token -> uid，并记住来源 IP：后续 roster 靠这两条还原「我是谁」
            if who:
                bind_token(token, who)
                remember_uid(client_ip(sess, headers), who)
                if HAS_WEB:
                    auth.touch_login(who)
                    auth.clear_fails("login:" + _ip)
            log(f"[{sess.tag}] -> authenticate 200 user={who!r} session={sid[:8]} "
                f"ip={_ip} req_fields={sorted(req.keys())}")
    elif path.startswith("/v1/speed"):
        resp_body = json.dumps({"status_code": 20000, "code": 0, "speed": 999,
                                "data": {"speed": 999}}).encode()
    elif path.endswith("/token") and method.upper() == "POST":
        # LoginManager::start() 的自动登录链路（blutter 实锤）：
        #   HttpProxy::validateAccessToken(username, token)   -> POST /users/<uid>/token
        #     .then(0xe06530)   // 解析 status_code==20000 -> startSession + getAccountInformation
        #     .timeout(Duration(microseconds: 6000000),        // 6 秒
        #              onTimeout: 0xe064bc)                  // -> RxBus.post(LoginEvent(5))
        #     .catchError(0xe06390)                          // -> LOGIN ERROR + LoginEvent(4)
        #
        # first_page::_start 的 LoginEvent 分派（0xc599f4 起，比较值都是 Smi raw）：
        #   raw 0x0 (值0) -> 打印 "first page login complete"，不跳转
        #   raw 0xa (值5) -> _switchToHomePage()   ← 唯一无条件 pushAndRemoveUntil("/Home")
        #   raw 0x2 (值1) -> 取消订阅 + _switchToHomePage()
        #   raw 0x4/0x6 (值2/3) -> 已有 HC 时直接 return（什么都不做）
        #
        # 也就是说 LoginEvent(5) 只在 validate **超时**时才发。服务器返回太快时
        # Future.timeout 不会触发 onTimeout，App 就永远停在「正在获取数据」。
        # 这里故意延迟 7 秒（>6 秒 timeout）让兜底先跑到：先进 /Home，
        # 1 秒后响应到达仍会走 .then -> startSession -> roster，数据随后补齐。
        # 注：Future.timeout 不会取消原 Future，所以 .then 依然会执行。
        # 2026-10-19 修正：不再故意延迟 7 秒。
        # 实测冷启动时 App 在 4.2s 就自己中断了这个连接：
        #   LOGIN ERROR: Software caused connection abort
        #   first page loginevent: 4  0   → catchError 分支 → push /AddHomeCenter
        # 延迟 hack 的前提（Groups 是 Map）已经不成立，现在 roster 能正常解析，
        # 正常快速的 200 才能让 .then → startSession → roster 这条正向链路跑通。
        # ★ 2026-10-21（AUDIT A3）：这里原来**无条件**返回 20000 —— 不校验 token、不看账号是否存在。
        #   后果：① 伪造 Bearer 也能过（`POST /users/nobody@x/token` 带假 token → 20000）；
        #        ② tokens.json 丢失时表现为"已登录但首页空白"，很难判断。
        #   现在：带了 Bearer 就必须是登记过的，否则 40100（App 会走重新登录）。
        #   完全不带 Bearer 的请求保持 20000（历史兼容，避免打断任何未知调用路径），但会记日志。
        _tk_hdr = (headers.get("authorization") or "").strip()
        _tk_val = _tk_hdr[7:].strip() if _tk_hdr[:7].lower() == "bearer " else ""
        _tk_known = None
        if _tk_val:
            with TENANT_LOCK:
                _tk_known = TOKENS.get(_tk_val)
        if _tk_val and not _tk_known:
            resp_body = json.dumps({"status_code": 40100, "code": 401,
                                    "message": "登录状态已失效，请重新登录",
                                    "status": "error", "data": {}}).encode()
            log(f"[{sess.tag}] -> token 40100（Bearer 未登记 token={_tk_val[:8]}...）")
        else:
            resp_body = json.dumps({"status_code": 20000, "code": 0, "message": "ok",
                                    "status": "ok", "data": {}}).encode()
            log(f"[{sess.tag}] -> token 200 auth={'有' if _tk_val else '无'}"
                f"{(' uid=' + _tk_known) if _tk_known else ''}")
    elif path.endswith("/roster"):
        # session.dart 对 roster 的解析格式（blutter 反汇编实锤）：
        #   resp["roster"] 必须是一个非空列表，每个元素是 Map，含以下键：
        #     Groups, RedirectTo, RedirectGroupName, Nickname,
        #     Username, Type, Permission
        #   ★★ Groups 必须是"字符串列表"，不是字典 ★★（2026-10-19 logcat 运行期实锤）
        #     真机堆栈：
        #       Receiver: _LinkedHashMap len:1
        #       Tried calling: contains("__gateway__")
        #       #2 _FirstState._gotoHomePageOnFailure (first_page.dart:139)
        #       #3 _FirstState._start.<anonymous closure> (first_page.dart:437)
        #     App 调用的是 Groups.contains("__gateway__")（0x8df534 / 0xc59244 是动态派发，
        #     静态反汇编无法区分 [] 与 contains，此前的 Map 结论是误判）。
        #     Dart 的 Map 没有 contains 方法 → NoSuchMethodError → 异步闭包静默死亡
        #     → 不创建 HomeCenter → 不订阅 event/ → 卡在登录页（长期现象的真因）。
        #     Dart 里 String 和 List 都有 contains()，所以 Type=1 时可传字符串，Type=3 传列表。
        #   Groups.contains("__gateway__")==true 才处理该 item（0x8df594 tbnz w0,#4 → false 跳过）
        #   Username 作为 HomeCenterManager map 的 key 和 HomeCenter.field_7
        #   Nickname 作为 HomeCenter.field_b（显示名）
        #   Type 决定分支：1=协会/拆分"|"，2/3=直接创建 HomeCenter
        #   Type==3 时 field_f=6（raw），numberOfAddedHomeCenter() 会计入
        #   Permission 写入 HomeCenter.field_43
        #   RedirectTo 留空可绕过 vg 虚拟组变换（getVirtualUuid: replaceRange(4,12,"vg")）
        # 注意：Username(HC uuid) 必须 >= 12 字符——App 侧对每个已有 HomeCenter 无条件调用
        # uuid.replaceRange(4, 12, "vg")（session.dart 0x8deecc），短 uuid 会抛 RangeError
        # 导致 roster 响应处理器静默死亡（第二次 roster 刷新时必现）。
        # 无网关配置时用真实网关 UUID 兜底（21 字符，与真机格式一致）。
        # ★ 多租户（M3）：这个账号能看见哪几个家，完全由 tenants.json 决定。
        #   未配表 -> 沿用旧的单租户行为（GWS[0] / 真实网关 UUID 兜底），线上不受影响。
        _uid = _req_uid
        _legacy = [GWS[0]["hc_uuid"] if GWS else "box-aa-bb-cc-dd-ee-ff"]
        # 单租户兜底只在「只登记了一个账号」时启用。
        # 一旦加了朋友（TENANTS 里 ≥2 个账号），未识别的身份就拿不到任何家 ——
        # 否则陌生人只要跳过 /users/<uid>/token 就能看到主人的家。
        _legacy_ok = len(TENANTS) <= 1
        if TENANTS and _uid:
            _mine = tenants_of(_uid)
            if not _mine:
                # 自动认领：未登记的账号，如果和某台「已连上假云端但没人认领」的网关
                # 来自同一个公网 IP（= 同一个家），就把那台网关绑给他。
                _mine = try_auto_claim(_uid, client_ip(sess, headers),
                                       headers.get("user-agent", ""))
            if not _mine:
                log(f"[{sess.tag}] roster: uid={_uid!r} 未在 tenants.json 登记，返回空列表")
        elif _legacy_ok:
            # 未配表，或 uid 完全没还原出来 -> 退回旧的单租户行为。
            # 后者是刻意的安全阀：身份解析失败时宁可退回老行为，
            # 也不要把自用账号锁在「一个家都看不到」的黑屏里。
            _mine = _legacy
            if TENANTS:
                log(f"[{sess.tag}] roster: uid 未解析（auth="
                    f"{'有' if headers.get('authorization') else '无'}）-> 单租户兜底")
        else:
            _mine = []
            log(f"[{sess.tag}] roster: 多租户已启用但 uid 未解析 -> 返回空列表")
        hc_uuid = _mine[0] if _mine else ""
        hc_name = hc_name_of(hc_uuid) if hc_uuid else ""
        hc = {"hc_uuid": hc_uuid, "hc_name": hc_name}

        # ★ 两个 roster 接口语义不同（2026-10-19 tcpdump + 反汇编实锤）
        #   GET /users/~/roster         -> 我的家庭中心列表，item 的 Groups 含 "__gateway__"
        #   GET /users/<hc_uuid>/roster -> 该家庭中心的**成员**列表，
        #       AssociateAccountManager::getAssociateAccoutOfHomeCenter（0x8b804c）
        #       遍历 roster，找 Groups.contains("__user__") 的项，再读
        #       Type / Username / Nickname / Permission 组装 Account。
        #   之前两者返回同一份「只有 __gateway__」的数据 → 找不到 __user__
        #   → 成员表为空 → 后续初始化停住（App 只发了 HTTP+CONNECT，不发任何 RPC）。
        _seg = path.split("?")[0].strip("/").split("/")
        _who = _seg[1] if len(_seg) >= 2 else "~"
        if _who not in ("~", "", "me"):
            # 身份：resolve_uid 三条来源（Bearer -> 路径 uid -> 来源 IP 记忆）。
            # ★ v3.0 复盘 F1（2026-10-20 17:50）：这里原来是 `_uid or "13800000000"`。
            #   后果有两个：① 匿名请求能拿到一个硬编码手机号；
            #   ② 查**任何** hc（连不存在的 hc）都返回同一份，成员表根本没按 hc 过滤。
            #   现在分三种情况：
            #     · 能还原出账号            -> 用这个账号（正常路径）
            #     · 带了凭证但还原不出账号  -> 用该 hc 在 tenants.json 的归属账号（App 冷启动兜底）
            #     · 完全匿名（连 header 都没有）-> 空成员表，不猜、不泄漏
            _auth_hdr = (headers.get("authorization") or "").strip()
            uname = _uid
            if not uname and _auth_hdr and _who.startswith("box-"):
                # ★ 2026-10-20 21:37（v2.22）：凭证还原不出账号时的退路，只认
                #   「这个公网 IP 最近登录过该 hc 的某个归属账号」（IP_UID，30 分钟）。
                #   不能只凭"有 Authorization 头"就回归属账号 —— 伪造一个 Bearer 头也能骗到，
                #   那等于把 F1 修掉的泄漏又从后门放回来。
                _ip = client_ip(sess, headers)
                with TENANT_LOCK:
                    _ipuids = [u for u, ts in (IP_UID.get(_ip) or {}).items()
                               if time.time() - ts < IP_UID_TTL]
                if _ipuids:
                    _hco = hc_owner_of(_who)
                    if _hco and _hco in _ipuids:
                        uname = _hco
            if not uname:
                _eb = {"status_code": 20000, "code": 0, "message": "ok", "status": "ok",
                       "state": 10, "roster": [], "members": []}
                _erb = json.dumps(_eb).encode()
                log(f"[{sess.tag}] -> hc-roster(成员) 200 hc={_who!r} 匿名且无归属 -> 空列表")
                sess.s.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                f"Content-Length: {len(_erb)}\r\nConnection: close\r\n\r\n").encode() + _erb)
                return
            # ★ 2026-10-20 21:10（v2.20）：成员表返回该 hc 的**全部**归属账号，不再只有自己。
            #   背景：tenants.json 里一个 hc 本来就可以被多个账号拥有
            #   （box-aa-bb-cc-dd-ee-ff = owner@example.com + guest@example.com），
            #   但这里以前恒只回一条「当前账号」，于是 App 的「我的家人」页永远是空的
            #   —— 页面展示的是「除我以外的成员」，一条都不剩。
            #   顺序：自己排第一（App 可能取第一条当"我的权限"），其余按 tenants.json 顺序。
            # ★★ 2026-10-20 21:36 修漏（v2.22，自己引入的）：
            #   第一版是「无条件把自己 insert 到第 0 位」，结果**任何登录账号**都能
            #   查别人家的成员表，还会把自己塞进那份列表里（实测 family@test.com
            #   能看到 11-29 / 15-ab 的 owner+friend，并且自己排在最前面）。
            #   现在：必须是该 hc 的成员才能看，否则返回空表。
            _member_uids = []
            if _who.startswith("box-"):
                with TENANT_LOCK:
                    for _mu, _mhcs in TENANTS.items():
                        if _who in (_mhcs or []) and _mu not in _member_uids:
                            _member_uids.append(_mu)
                if not uname or uname not in _member_uids:
                    _eb = {"status_code": 20000, "code": 0, "message": "ok", "status": "ok",
                           "state": 10, "roster": [], "members": []}
                    _erb = json.dumps(_eb).encode()
                    log(f"[{sess.tag}] -> hc-roster(成员) 200 hc={_who!r} uid={uname!r} 非该 hc 成员 -> 空列表")
                    sess.s.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                    f"Content-Length: {len(_erb)}\r\nConnection: close\r\n\r\n").encode() + _erb)
                    return
                _member_uids.remove(uname)          # 自己排第一
                _member_uids.insert(0, uname)
            else:
                # ★ 2026-10-21（AUDIT A2）：路径不是 hc（如 /users/<uid>/roster）时，
                #   原来直接 `_member_uids = [uname]` —— 而 uname 来自**路径 uid**，
                #   于是 `curl /users/owner@example.com/roster` 不带任何凭据也能拿到一条成员条目。
                #   现在：必须带**登记过的** Bearer 才回显，否则空表。
                _tk2 = (headers.get("authorization") or "").strip()
                _tk2 = _tk2[7:].strip() if _tk2[:7].lower() == "bearer " else ""
                _tok_uid = None
                if _tk2:
                    with TENANT_LOCK:
                        _tok_uid = TOKENS.get(_tk2)
                if not _tok_uid:
                    _eb = {"status_code": 20000, "code": 0, "message": "ok", "status": "ok",
                           "state": 10, "roster": [], "members": []}
                    _erb = json.dumps(_eb).encode()
                    log(f"[{sess.tag}] -> hc-roster(成员) 200 who={_who!r} 无有效 token -> 空列表")
                    sess.s.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                    f"Content-Length: {len(_erb)}\r\nConnection: close\r\n\r\n").encode() + _erb)
                    return
                _member_uids = [uname]
            _member_uids = _member_uids[:8]        # 上限 8，防止异常数据把响应撑大

            def _mk_member(_u):
                return {
                    "Groups": ["__user__"],
                    "RedirectTo": "",
                    "RedirectGroupName": "",
                    "Nickname": _u,
                    "Username": _u,
                    # ★ 成员状态位。App 用这个值判断「这个账号是不是已通过审核的成员」：
                    #   反汇编 association_request_manager 里有 `cmp w0, #2` 的分支。
                    #   用 tenants.json 的 _member_type 可热切换做 A/B，默认 2（已通过审核）。
                    "Type": MEMBER_TYPE,
                    # ★ 成员条目的 Permission 也必须是「含控制位」的值（2026-10-19 实测）
                    #   位掩码：4=control，6=view|control，12=control|edit，14=view|control|edit
                    #   之前这里是 0（无权限）。App 启动时会先后请求
                    #     GET /users/~/roster            —— 家庭中心列表（owner 视角）
                    #     GET /users/<hc_uuid>/roster    —— 该 HC 的成员列表（我的成员视角）
                    #   两者都会写入当前用户的权限状态；只要有一条是 0，
                    #   HomeCenter::hasControlPermission 就会判无权限，
                    #   点磁贴/点开关全部【静默丢弃，不发任何 RPC】。
                    # ★ 2026-10-21 11:50：改为按成员覆盖（tenants.json `_member_perm`），默认 14。
                    "Permission": MEMBER_PERM.get(_u, 14),
                }

            members = [_mk_member(_u) for _u in _member_uids] or [_mk_member(uname)]
            body = {
                "status_code": 20000, "code": 0, "message": "ok", "status": "ok",
                "state": 10,
                "roster": members,
                "members": members,
            }
            rb = json.dumps(body).encode()
            log(f"[{sess.tag}] -> hc-roster(成员) 200 hc={_who!r} 自己={uname!r} 成员={len(members)} {_member_uids}")
            sess.s.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            f"Content-Length: {len(rb)}\r\nConnection: close\r\n\r\n").encode() + rb)
            return

        def _roster_item(_hc):
            """单个家庭中心的 roster 条目。参数化后同一份逻辑可服务多个 hc。"""
            return {
                "Groups": ["__gateway__"],
                "RedirectTo": "",
                "RedirectGroupName": "",
                "Nickname": hc_name_of(_hc),
                "Username": _hc,
                "Type": 3,
                # ★★ 控制权限的唯一来源（2026-10-19 反汇编 + 真机实锤）★★
                # session.dart roster 解析闭包：
                #   0x8df718  r30 = "Permission"     ← map["Permission"]
                #   0x8dfa18  mov x17, #0xe          ← 构造默认 field_43 = 14
                #   0x8dfab4  StoreField r1->field_43 = r0   ← 用 roster 值【覆盖】默认
                # 也就是说 Permission 缺省时是 14，一旦返回 0 就变成 0。
                # HomeCenter::hasControlPermission(0xae1890)：
                #   defaultSession().field_13 == "LOCAL" → true
                #   否则要求 hc.field_43 ∈ [4, 6, 12, 14]（0x8df1938..0x8df1950 白名单）
                # 这四个数都是位掩码且都含 bit 4（=控制位）：
                #   4 = control，6 = view|control，12 = control|edit，14 = view|control|edit
                # 之前一直返回 0 → 判定无控制权限 → 点磁贴/点电源键【静默丢弃】，
                # 不发任何 RPC（这正是「App 显示真实设备但控不动」的真因）。
                # ★ 2026-10-21 11:50：改为按成员覆盖（tenants.json `_member_perm`），默认 14。
                #   想给访客只读就写 {"guest@example.com": 8} —— 8 不在控制白名单 {4,6,12,14}，
                #   也不在编辑白名单 {2,6,10,14}，两个门禁都过不去 = 只能看。
                "Permission": MEMBER_PERM.get(_uid, 14),
                # App 日志 `lan token for <uuid> not exist or OA: <openAccess>, skip it`
                # （session 侧打印，OA = openAccess）。HomeCenter.fromMap 里
                # openAccess -> field_1f（0x907754），默认 true；带上它让 App
                # 走「免令牌」的本地直连分支，不必等云端下发 lanToken。
                # openAccess -> field_1f（0x907754）
                "openAccess": True,
                # processPresence 收尾会重拉一次 GET /users/~/roster
                # （HttpProxy::getRosterOfCurrentUser 0x8d7aec），
                # 该闭包 0x8d8984 逐项读 Groups + online(bool) 再调
                # updateHomeCenterStatus。这里必须给真实在线位，
                # 否则会被刷成离线。
                "online": _hc in peers_snapshot(),
                "state": 10,
            }

        roster = {
            "status_code": 20000, "code": 0, "message": "ok", "status": "ok",
            # 冗余兜底（FINAL_PLAN §22）：first_page.dart 状态机按顶层 state 路由
            #   10/9/8 → /Home；7 → /AddHomeCenter；5 → loginUncomplete 弹窗
            # 真实路径是 session.dart 成功尾部把 LoginManager().field_7 设成 10，
            # 这里同时给出 state 覆盖另一条读取路径（data_shared "update home center status"），
            # App 若不读此字段则完全无害。
            "state": 10,
            "roster": [_roster_item(x) for x in _mine],
            "members": [],
            # 冗余：部分页面用 home_centers 列表取 HC 信息
            "home_centers": [
                {"id": x, "uuid": x, "name": hc_name_of(x), "state": 10, "state_code": 10}
                for x in _mine
            ],
            "home_center": {"id": hc_uuid, "uuid": hc_uuid, "name": hc_name, "state": 10},
        }
        resp_body = json.dumps(roster).encode()
        # 无网关时 CACHE.gw_uuid 为空，用 roster 里的 HC uuid 回填，
        # 保证 RPC 应答的 Sender 字段是真实家庭中心 UUID
        if not CACHE.gw_uuid:
            CACHE.gw_uuid = hc.get("hc_uuid", "")
        log(f"[{sess.tag}] -> roster 200 hc={hc.get('hc_uuid')!r} "
            f"ua={headers.get('user-agent', '')!r} "
            f"enc={headers.get('accept-encoding', '')!r} "
            f"auth={'有' if headers.get('authorization') else '无'}")
        try:
            roster_probe(sess.tag, path.split("/")[2] if path.count("/") >= 2 else "")
        except Exception:
            pass
        # —— 延迟返回（关键）——
        # 真实官方云端经公网往返通常 >1s。App 在 startSession 后**立刻**发 roster，
        # 而 Session 内部的 mqtt client 引用是连接建立后才挂上的。
        # session.dart 0x8dfe14 / 0x8dfe88 读 r1->field_2f（client）后直接
        # `cmp NULL; b.eq 0x8e00c8/0x8e00d0`，而 0x8e00c4..0x8e00d4 全是
        # NullCastErrorShared（空断言）——只要为 null 就抛异常，
        # 整个 roster 闭包静默死亡。
        # 后果：addHomeCenter 已在崩溃点之前执行（HC 建出来了），但收尾的
        # LoginEvent(3)（0x8e005c）永远发不出去 →
        # 登录页 _FirstState 处理器里 numberOfAddedHomeCenter() 仍为 0 →
        # 不跳 /Home，表现为「卡在验证码页 / 正在获取数据」。
        # 2026-10-19 修正：去掉 2 秒人为延迟。
        # 实测 roster 请求到达时 MQTT client 早已挂上（CONNECT→SUBSCRIBE message/
        # →0.4s 后才发 GET roster），不存在 field_2f 为 null 的竞态。
        # 反而这个延迟把整条登录链路拖到 ≈4s，超过首屏动画时长 →
        # _FirstState::_onAnimationEnd 在那个时刻读到 stage=0 只做 setState，
        # 一次性回调不再重试 → 永久停在启动页转圈（黑底 spinner）。
    elif bare.startswith("/users/") and bare.endswith("/notification"):
        # GET /users/<uid>/notification
        # account_manager / notification 页面读取推送配置；给一份结构完整的空配置，
        # 避免缺字段导致后续初始化流程静默中断。
        notif = {
            "status_code": 20000, "code": 0, "message": "ok", "status": "ok",
            "enabled": True, "push_enabled": True,
            "data": {"enabled": True, "push_enabled": True, "channels": [],
                     "events": [], "config": {}},
        }
        resp_body = json.dumps(notif).encode()
    elif bare.startswith("/users/"):
        # GET /users/<uid>
        # account_manager.dart ::refreshAccountInformation (0x86147c) 逐字段读取：
        #   status_code / name / mobile / email / email_confirmed / role / user_role / open_ids
        # 这些都在【顶层】读取。之前这里返回 data:{}（无任何用户字段），
        # 导致账号信息全为 null —— 手动登录路径在 getAccountInformation 之后
        # 不再发起 /ws/mqtt，流程静默中断。
        uid = bare.split("/")[-1] or ""
        if not uid or uid == "~":
            # ★ v3.0 复盘 F1：原来这里硬编码 "13800000000" —— 匿名打 GET /users/~
            #   就能拿到一个假账号（带手机号）。改成用凭证还原；还原不出来就明确拒绝。
            uid = resolve_uid(sess, headers, path)
            if not uid:
                resp_body = json.dumps({"status_code": 40100, "code": 401,
                                        "message": "unauthorized",
                                        "status": "error"}).encode()
                log(f"[{sess.tag}] -> users 40100（/users/~ 无凭证，拒绝）")
                sess.s.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                f"Content-Length: {len(resp_body)}\r\n"
                                f"Connection: close\r\n\r\n").encode() + resp_body)
                return
        # ★ 身份类型必须与登录方式一致。
        #   以前对所有账号都硬编码 id_type="mobile"、mobile=<uid>、email=""，
        #   用邮箱登录时 App 拿到的身份类型是错的 → 加入申请里出现 "user_id_type": null
        #   → 申请无法与成员匹配 → 列表里堆出一堆删不掉的「请求函」。
        if "@" in uid:
            _id_type, _mobile, _email, _email_ok = "email", "", uid, True
        else:
            _id_type, _mobile, _email, _email_ok = "mobile", uid, "", False
        user_obj = {
            "id": uid, "name": uid, "nickname": uid,
            "mobile": _mobile, "phone": _mobile,
            "email": _email, "email_confirmed": _email_ok,
            "role": "user", "user_role": "user",
            "id_type": _id_type, "open_ids": [],
            "avatar": "", "avatar_url": "",
        }
        uresp = {"status_code": 20000, "code": 0, "message": "ok", "status": "ok"}
        uresp.update(user_obj)
        uresp["data"] = user_obj
        resp_body = json.dumps(uresp).encode()
        log(f"[{sess.tag}] -> users 200 uid={uid!r}")
        sess.uid = uid
        # 只有「两段路径 GET /users/<uid>」才是真正的用户身份。
        # /users/<mac>/name、/users/<uid>/token、/users/<uid>/notification 等
        # 会把最后一段误当成 uid（曾把 LAST_UID 污染成 "name"）。
        # ★ 这里**不再** remember_uid（P0-3）：
        #   GET /users/<uid> 没有任何鉴权，以前任何人 `GET /users/owner@xxx`
        #   就能把自己的公网 IP 记成 owner，随后 MQTT 拿到全权（ACL 认人只看 IP）。
        #   身份只能从两条**凭证路径**写入 IP_UID：
        #     ① POST /users/authenticate 成功（密码校验通过）；
        #     ② resolve_uid() 里 Bearer token 命中 TOKENS 的分支。
        _useg = bare.strip("/").split("/")
        if len(_useg) == 2:
            _cand = _useg[1]
            if _cand and _cand not in ("~", "token", "name", "notification",
                                       "roster", "avatar", "verificationcodes") \
                    and not _cand.startswith("box-"):
                LAST_UID = _cand
    elif bare.startswith("/devices/") and "/association" in bare:
        # POST /devices/<hc>/association —— App 点「同意加入」时触发
        # 请求体示例（推测）：{"user_id":"...","user_id_type":"email/mobile",...}
        # 我们的处理：把当前用户和该 hc 写入 tenants.json（如果还没绑定的话）
        _hc = bare.split("/")[2] if bare.count("/") >= 2 else ""
        _uid = _req_uid
        try:
            req = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            req = {}
        # ★★ 2026-10-21（AUDIT A1）：删掉「请求体自报 uid」的兜底。
        #   原来无凭据请求只要 body 里带 user_id，就能把**任意未被认领的网关**绑到自己名下。
        #   实测（本地实例）：POST /devices/box-2222-2222-2222-2222/association
        #     {"user_id":"attacker@evil.com"} → 20000，tenants.json 直接多出
        #     "attacker@evil.com": ["box-2222-..."]。
        #   hc uuid 是 MAC 派生（box-aa-bb-cc-dd-ee-ff），可枚举 → 等于"抢注 + 把真主人挡在门外"
        #   （真主人再来 association 会被 _owner 拦下："该家庭中心已被其他账号绑定"）。
        #   现在：必须能从 Bearer 还原出账号，否则 40100。
        _body_uid = req.get("user_id") or req.get("username") or req.get("id") or ""
        log(f"[{sess.tag}] association {_hc!r} uid={_uid!r} "
            f"auth={'有' if headers.get('authorization') else '无'} "
            f"body_uid={_body_uid!r} method={method} body={req}")
        if not _uid:
            _rb = json.dumps({"status_code": 40100, "code": 401,
                              "message": "未登录", "status": "error",
                              "data": {}}).encode()
            sess.s.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            f"Content-Length: {len(_rb)}\r\nConnection: close\r\n\r\n").encode() + _rb)
            log(f"[{sess.tag}] 拒绝 association：无凭据 hc={_hc!r} body_uid={_body_uid!r}")
            return
        if _uid and _hc and not _hc.startswith("box-"):
            # 如果 hc 是 MAC 格式（1c-82-...）补成 box- 前缀
            _hc = "box-" + _hc
        # ★ 归属校验（P2-10）：以前只要带个 uid 就能把 hc 加进该账号名下，
        #   结果是「一房两主」—— 任何知道 hc uuid 的人都能把自己加成主人。
        #   规则：hc 已被**别的**账号拥有 → 拒绝；无主 → 允许（首个认领）；
        #        已属于当前账号 → 幂等成功（App 重试不会报错）。
        _assoc_err = ""
        _assoc_added = ""
        _owner = ""
        _share_target = ""
        _action = str(req.get("action") or "").strip().lower()
        _target = str(req.get("user") or req.get("user_id") or "").strip()
        if _action == "share" and _uid and _hc and _target:
            # ★ 2026-10-20 21:26（v2.21）：App 的「邀请新用户」打的就是这个接口：
            #   body = {"action":"share","user":"<被邀请人>","by":"<邀请人>",
            #           "device_name":"...","user_id_type":"email"}
            #   以前**完全没处理 share** —— App 打 "associate home center succeed: share"，
            #   但 tenants.json 一个字都没变，被邀请的人永远看不到这台家庭中心。
            #   现在的规则：只有该 hc 的成员能邀请；只接受邮箱（本服务 EMAIL_ONLY）；幂等。
            if "@" not in _target:
                _assoc_err = "本服务器只支持邮箱邀请"
            elif _hc not in tenants_of(_uid):
                _assoc_err = "只有该家庭中心的成员可以邀请他人"
            elif _target == _uid:
                _share_target = _target            # 邀请自己：幂等成功，不做任何事
            else:
                _already = False
                with TENANT_LOCK:
                    _tgt = list(TENANTS.get(_target, []))
                    if _hc in _tgt:
                        _already = True
                    else:
                        _tgt.append(_hc)
                        TENANTS[_target] = _tgt
                if _already:
                    _share_target = _target
                    log(f"[tenant] share 幂等：{_target} 已经有 {_hc}")
                else:
                    save_tenants()
                    _share_target = _target
                    log(f"[tenant] ★ share 邀请：{_uid} 把 {_hc} 分享给 {_target}")
        elif _action in ("cancel_share", "unshare") and _uid and _hc and _target:
            # ★ 2026-10-21 07:36（v2.23）：家人页点「取消分享」→ 确认 → 打的就是这个接口：
            #   body = {"action":"cancel_share","user":"<被移除人>","by":"<操作人>",...}
            #   以前同样被静默忽略（App 显示成功，tenants.json 不变，人还在）。
            #   规则：只有该 hc 的成员能操作；不能移除自己；幂等（本来就没有也算成功）。
            if _hc not in tenants_of(_uid):
                _assoc_err = "只有该家庭中心的成员可以取消分享"
            elif _target == _uid:
                _assoc_err = "不能取消自己的分享"
            else:
                _removed = False
                with TENANT_LOCK:
                    _tgt = list(TENANTS.get(_target, []))
                    if _hc in _tgt:
                        _tgt.remove(_hc)
                        _removed = True
                        if _tgt:
                            TENANTS[_target] = _tgt
                        else:
                            TENANTS.pop(_target, None)   # 一个家都没有了就别留空壳
                if _removed:
                    save_tenants()
                    log(f"[tenant] ★ cancel_share：{_uid} 把 {_target} 从 {_hc} 移除")
                else:
                    _share_target = _target
                    log(f"[tenant] cancel_share 幂等：{_target} 本来就不在 {_hc}")
        elif _uid and _hc:
            # 注意：save_tenants() 内部自己会取 TENANT_LOCK（普通 Lock，不可重入），
            # 所以它必须放在 with 块之外调用，否则死锁。
            with TENANT_LOCK:
                for _u, _hcs in TENANTS.items():
                    if _u != _uid and _hc in (_hcs or []):
                        _owner = _u
                        break
                _mine = list(TENANTS.get(_uid, []))
                if _hc in _mine:
                    pass                      # 幂等：已经绑过
                elif _owner:
                    _assoc_err = "该家庭中心已被其他账号绑定"
                else:
                    _mine.append(_hc)
                    TENANTS[_uid] = _mine
                    _assoc_added = _hc
            if _assoc_err:
                log("[tenant] 拒绝 association：hc=%s 已属于 uid=%s，%s 试图占用"
                    % (_hc, _owner, _uid))
            elif _assoc_added:
                save_tenants()
                log(f"[tenant] ★ association 绑定：uid={_uid} <- {_hc}")
        if _assoc_err:
            assoc_resp = {
                "status_code": 40100, "code": 401, "message": _assoc_err,
                "status": "error", "error": _assoc_err, "data": {},
            }
            resp_body = json.dumps(assoc_resp).encode()
        else:
            # 返回 App 期望的成功结构（与 roster 成员条目同构，减少解析差异）
            assoc_resp = {
                "status_code": 20000, "code": 0, "message": "ok", "status": "ok",
                "data": {
                    "home_center_uuid": _hc,
                    "user_id": _share_target or _uid,
                    "permission": 14,
                    "type": MEMBER_TYPE,
                    "associated": True,
                },
            }
            resp_body = json.dumps(assoc_resp).encode()
    elif bare.startswith("/v1/speed"):
        # App 启动时的服务器测速探测
        resp_body = json.dumps({"status_code": 20000, "code": 0, "message": "ok",
                                "status": "ok", "speed": 100, "latency": 50,
                                "data": {"speed": 100, "latency": 50}}).encode()
    else:
        resp_body = json.dumps({"status_code": 20000, "code": 0, "message": "ok",
                                "status": "ok", "data": {}}).encode()

    sess.s.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(resp_body)}\r\nConnection: close\r\n\r\n").encode() + resp_body)


# ============================================================ 主循环

def serve(sess):
    try:
        lines, rest = read_http_head(sess.s)
        if lines is None:
            return
        handle_http(sess, lines, rest)
    except Exception as e:
        log(f"[{sess.tag}] 服务结束 {type(e).__name__}: {e}")
    finally:
        # 关键：无论成功、失败还是扫描器探测，都必须关闭 socket 并退出会话表。
        # 缺少这一步会造成 fd 泄漏，被公网扫描器刷爆后 accept 抛 Errno 24 整个进程失去响应。
        sess.alive = False
        try:
            BROKER.drop(sess)
        except Exception:
            pass
        try:
            sess.s.close()
        except Exception:
            pass


def accept_loop():
    ctx = None
    if not PLAIN:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(128)
    log(f"===== 小燕家庭云 v4 {HOST}:{PORT} {'(明文)' if PLAIN else '(TLS)'} =====")
    log(f"API={PUBLIC_API} WS={PUBLIC_WS} 网关={len(HUB.gateways)}")
    while True:
        try:
            c, addr = srv.accept()
        except OSError as e:
            # fd 短暂耗尽或 EINTR 时不能让主循环死掉，否则服务表现为「假死」
            log(f"accept 失败 {type(e).__name__}: {e}，0.3s 后继续")
            time.sleep(0.3)
            continue
        # 慢连接（扫描器/半开连接）会白占 fd，给个硬超时
        try:
            c.settimeout(60)
        except Exception:
            pass
        if ctx is not None:
            try:
                c = ctx.wrap_socket(c, server_side=True)
            except Exception as e:
                log(f"[{addr[0]}:{addr[1]}] TLS 失败: {e}")
                try:
                    c.close()
                except Exception:
                    pass
                continue
        # 线程数保护：被扫描器刷时不无限起线程
        if threading.active_count() > 256:
            try:
                c.close()
            except Exception:
                pass
            continue
        threading.Thread(target=serve, args=(Session(c, addr),), daemon=True).start()


def main():
    HUB.start()
    time.sleep(1.5)
    if HAS_WEB:
        try:
            generated = admin_web.ensure_admin()
            if generated:
                log("[admin] ★ 首次启动，已生成后台密码（写在 %s，权限 600）"
                    % admin_web.INITIAL_PW_FILE)
            log("[admin] 账号 %d 个 | 后台 https://%s/admin | 注册 https://%s/register"
                % (auth.count(), PUBLIC_API, PUBLIC_API))
        except Exception as e:
            log("[admin] 初始化失败 %s: %s" % (type(e).__name__, e))
    else:
        log("[admin] ⚠ 未加载 auth/admin_web（%s）—— 登录不校验密码，后台不可用" % _WEB_ERR)
    accept_loop()


if __name__ == "__main__":
    main()
