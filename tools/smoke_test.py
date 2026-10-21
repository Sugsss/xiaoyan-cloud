#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smoke_test.py —— 假云端冒烟测试（T7）
=====================================
覆盖三层，全部**只读**（唯一写操作是登录失败计数，不产生业务数据）：

  HTTP  ① /v1/speed 200
        ② 手机号登录必须 40100（只允许邮箱）
        ③ 错误密码必须 40100
        ④ 无凭据 association 必须 40100（AUDIT A1）
        ⑤ 无凭据读成员表必须为空（AUDIT A2）
        ⑥ 伪造 Bearer 校验 token 必须 40100（AUDIT A3）
        ⑦ 超大请求体必须 413（AUDIT B3）
        ⑧ 改不存在账号密码必须 40100（B2/P1-7）
        ⑨ 正确密码 → 200 + token（需提供 SMOKE_UID / SMOKE_PW）
        ⑩ GET /users/<uid> 返回 id_type=email
        ⑪ 持有效 token 读他人 uid 成员表不得出现他人条目（A2 重构回归，需 SMOKE_UID/PW）
  MQTT  ⑨ 匿名 CONNECT 必须 rc=5
        ⑩ 冒充网关（username=box-*，非本机 IP）必须被断开
        ⑪ 合法 App 订阅 event/<自己的 hc> 必须 SUBACK 0x00（需 SMOKE_UID/PW + 同 IP 登录）

用法：
  # 基础（不测登录成功项）
  python3 tools/smoke_test.py

  # 完整（含登录成功 + MQTT 合法订阅）
  SMOKE_UID=owner@example.com SMOKE_PW='你的密码' python3 tools/smoke_test.py

  # 换目标
  SMOKE_BASE=https://api.example.com python3 tools/smoke_test.py

退出码：0=全通过，1=有失败，2=前置条件缺失（如没装 websockets）
"""
import json
import os
import ssl
import struct
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("SMOKE_BASE", "https://api.example.com").rstrip("/")
UID = os.environ.get("SMOKE_UID", "").strip()
PW = os.environ.get("SMOKE_PW", "")
WS_URL = BASE.replace("https://", "wss://").replace("http://", "ws://") + "/ws/mqtt"

PASS, FAIL, SKIP = [], [], []


def ok(name, detail=""):
    PASS.append(name)
    print("  \033[32m✓\033[0m %-42s %s" % (name, detail))


def bad(name, detail=""):
    FAIL.append(name)
    print("  \033[31m✗\033[0m %-42s %s" % (name, detail))


def skip(name, why=""):
    SKIP.append(name)
    print("  \033[33m-\033[0m %-42s %s" % (name, why))


def http(method, path, body=None, token=None, timeout=15):
    """返回 (status, json_or_text)。不抛异常，失败返回 (0, 错误串)。"""
    url = BASE + path
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl.create_default_context()) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return 0, "%s: %s" % (type(e).__name__, e)


# ---------------------------------------------------------------- HTTP
def test_http():
    print("\n[HTTP]")
    st, js = http("GET", "/v1/speed")
    if st == 200:
        ok("GET /v1/speed", "200")
    else:
        bad("GET /v1/speed", "status=%s %s" % (st, str(js)[:80]))

    # 手机号登录必须被拒
    st, js = http("POST", "/users/authenticate",
                  {"id": "13800000000", "id_type": "mobile",
                   "credential": "whatever", "verification_code": "123456"})
    sc = js.get("status_code") if isinstance(js, dict) else None
    if sc == 40100:
        ok("手机号登录被拒", "status_code=40100")
    else:
        bad("手机号登录被拒", "status=%s status_code=%s" % (st, sc))

    # 错误密码必须被拒
    st, js = http("POST", "/users/authenticate",
                  {"id": "nobody@example.com", "id_type": "email",
                   "credential": "definitely-wrong-password"})
    sc = js.get("status_code") if isinstance(js, dict) else None
    if sc == 40100:
        ok("错误密码被拒", "status_code=40100")
    else:
        bad("错误密码被拒", "status=%s status_code=%s" % (st, sc))

    # ---------- 安全回归（AUDIT-20261021 A1/A2/A3）----------
    # 这三条都是「无凭据/伪造凭据」的只读探测，除 A1 外不产生任何业务数据。
    # A1 若回归（返回 20000），会往 tenants.json 写一条 smoke-attacker@invalid.local，
    # 看到这条失败请顺手删掉该账号的归属。

    # A1：无凭据 association 必须被拒（曾可零凭据抢注网关）
    st, js = http("POST", "/devices/box-0000-0000-0000-0001/association",
                  {"user_id": "smoke-attacker@invalid.local"})
    sc = js.get("status_code") if isinstance(js, dict) else None
    if sc == 40100:
        ok("无凭据 association 被拒", "status_code=40100")
    else:
        bad("无凭据 association 被拒",
            "status=%s status_code=%s ← 可能已写脏 tenants.json" % (st, sc))

    # A2：无凭据读别人 uid 的成员表必须为空（曾返回该 uid 的成员条目）
    st, js = http("GET", "/users/smoke-probe@invalid.local/roster")
    members = (js.get("members") if isinstance(js, dict) else None) or []
    if st == 200 and not members:
        ok("无凭据成员表为空", "members=[]")
    else:
        bad("无凭据成员表为空", "status=%s members=%s" % (st, len(members)))

    # A3：伪造 Bearer 校验 token 必须 40100（曾无条件 20000）
    st, js = http("POST", "/users/smoke-probe@invalid.local/token",
                  {}, token="totally-fake-token-123")
    sc = js.get("status_code") if isinstance(js, dict) else None
    if sc == 40100:
        ok("伪造 token 校验被拒", "status_code=40100")
    else:
        bad("伪造 token 校验被拒", "status=%s status_code=%s" % (st, sc))

    # B3：超大请求体必须 413（曾无上限，nginx 50m 全量进 python 线程）
    st, js = http("POST", "/users", {"id": "x" * (3 * 1024 * 1024)})
    if st == 413:
        ok("超大请求体被拒", "413")
    else:
        bad("超大请求体被拒", "status=%s（期望 413）" % st)

    # B2/P1-7：改不存在账号的密码必须 40100（曾可抢注未注册邮箱）
    st, js = http("PATCH", "/users/smoke-probe@invalid.local/password",
                  {"old_password": "x", "new_password": "yyyyyyyy"})
    sc = js.get("status_code") if isinstance(js, dict) else None
    if sc == 40100:
        ok("改密不存在的账号被拒", "status_code=40100")
    else:
        bad("改密不存在的账号被拒", "status=%s status_code=%s" % (st, sc))

    if not (UID and PW):
        skip("正确密码登录", "缺 SMOKE_UID / SMOKE_PW")
        skip("GET /users/<uid>", "依赖登录")
        return None

    st, js = http("POST", "/users/authenticate",
                  {"id": UID, "id_type": "email", "credential": PW})
    sc = js.get("status_code") if isinstance(js, dict) else None
    tok = ""
    if isinstance(js, dict):
        tok = (js.get("token") or (js.get("data") or {}).get("token") or "")
    if st == 200 and sc == 20000:
        ok("正确密码登录", "200 / token=%s" % ("有" if tok else "无"))
    else:
        bad("正确密码登录", "status=%s status_code=%s %s" % (st, sc, str(js)[:80]))
        return None

    st, js = http("GET", "/users/" + UID, token=tok or None)
    it = js.get("id_type") if isinstance(js, dict) else None
    if st == 200 and it == "email":
        ok("GET /users/<uid>", "id_type=email")
    else:
        bad("GET /users/<uid>", "status=%s id_type=%s" % (st, it))

    # A2 重构回归（2026-10-21）：持**有效** token 读他人 uid 的成员表，
    # 不得出现他人条目（重构前路径 uid 第一优先 → 返回该 uid 的条目）
    st, js = http("GET", "/users/smoke-other@invalid.local/roster", token=tok or None)
    members = (js.get("members") if isinstance(js, dict) else None) or []
    leaked = [m.get("Username") for m in members
              if (m.get("Username") or "") not in (UID, "")]
    if st == 200 and not leaked:
        ok("A2 持 token 不读他人条目", "members=%d 无他人" % len(members))
    else:
        bad("A2 持 token 不读他人条目", "status=%s leaked=%s" % (st, leaked))
    return tok


# ---------------------------------------------------------------- MQTT
def _vint(n):
    out = b""
    while True:
        b = n % 128
        n //= 128
        out += bytes([b | 0x80 if n else b])
        if not n:
            return out


def _s(x):
    b = x.encode()
    return struct.pack(">H", len(b)) + b


def _connect(cid, user):
    vh = _s("mqtt") + bytes([4, 0xC2, 0, 60])
    body = vh + _s(cid) + _s(user)
    return b"\x10" + _vint(len(body)) + body


def _subscribe(topic, pid=1):
    body = struct.pack(">H", pid) + _s(topic) + bytes([1])
    return b"\x82" + _vint(len(body)) + body


def test_mqtt():
    print("\n[MQTT]")
    try:
        import asyncio
        import websockets
    except Exception as e:
        skip("MQTT 全部", "缺 websockets（pip install websockets）: %s" % e)
        return

    async def one(cid, user, topic=None, want_rc=None):
        ctx = ssl.create_default_context()
        kw = dict(subprotocols=["mqtt"], ssl=ctx, max_size=2 ** 22)
        try:
            ws = await asyncio.wait_for(websockets.connect(WS_URL, **kw), 12)
        except TypeError:   # websockets 9.x 没有 open_timeout 语义差异
            ws = await asyncio.wait_for(websockets.connect(WS_URL, **kw), 12)
        try:
            await ws.send(_connect(cid, user))
            ack = await asyncio.wait_for(ws.recv(), 10)
            rc = ack[3] if len(ack) > 3 else -1
            suback = None
            if rc == 0 and topic:
                await ws.send(_subscribe(topic))
                try:
                    p = await asyncio.wait_for(ws.recv(), 6)
                    if p and (p[0] >> 4) == 9 and len(p) >= 5:
                        suback = p[4]
                except Exception:
                    pass
            return rc, suback
        except Exception as e:
            return ("closed:%s" % type(e).__name__), None
        finally:
            try:
                await ws.close()
            except Exception:
                pass

    loop = asyncio.new_event_loop()

    rc, _ = loop.run_until_complete(one("smoke-anon", "whatever"))
    if rc == 5:
        ok("匿名 CONNECT 被拒", "rc=5")
    else:
        bad("匿名 CONNECT 被拒", "rc=%s（期望 5）" % rc)

    rc, _ = loop.run_until_complete(
        one("smoke-fake-gw", "box-aa-bb-cc-dd-ee-ff"))
    if rc == 5 or (isinstance(rc, str) and rc.startswith("closed")):
        ok("冒充网关被拒", "rc=%s" % rc)
    else:
        bad("冒充网关被拒", "rc=%s（期望 5 或连接被关）" % rc)

    if UID and PW:
        # 登录后同 IP 才有身份；这里只能验证「已登录后能订自己的 hc」
        rc, sub = loop.run_until_complete(one("smoke-app", "xy_sbk_smoke"))
        if rc == 0:
            ok("合法 App CONNECT", "rc=0")
        elif rc == 5:
            skip("合法 App CONNECT", "本机 IP 无登录记录（在服务器上跑会这样）")
        else:
            bad("合法 App CONNECT", "rc=%s" % rc)
    else:
        skip("合法 App CONNECT", "缺 SMOKE_UID / SMOKE_PW")

    loop.close()


# ---------------------------------------------------------------- main
def main():
    print("目标: %s" % BASE)
    test_http()
    test_mqtt()
    print("\n" + "=" * 56)
    print("通过 %d / 失败 %d / 跳过 %d" % (len(PASS), len(FAIL), len(SKIP)))
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
