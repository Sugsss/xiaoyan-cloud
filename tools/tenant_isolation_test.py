#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tenant_isolation_test.py —— 多租户隔离回归（持续验证用）
============================================================================
为什么单独做一个：`smoke_test.py` 只测了「持 token 不读他人条目」一条，
但隔离真正会坏的地方是三处：
  ① 跨账号 roster —— A 不该在 /users/~/roster 里看到 B 的家庭中心
  ② 一房两主     —— B 不该能把 A 已认领的 hc 再认领一次
  ③ 跨 hc 成员表 —— B 不该读到 A 那个 hc 的成员名单

设计原则：**不碰线上数据**。把线上 tenants/accounts/tokens/ipuid 复制到临时目录，
在另一个端口（默认 19446）起一个实例，全部断言打在它身上，跑完连目录一起删。

用法：
  python3 tools/tenant_isolation_test.py                 # 默认读 /opt/xiaoyan-cloud
  SRC=/opt/xiaoyan-cloud PORT=19446 python3 ...
  SRC=./xiaoyan-cloud python3 ...                        # 本地跑（需有 terncy_proto.py 在上一级）

退出码：0=全通过，1=有失败，2=环境准备失败
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

SRC = os.path.abspath(os.environ.get("SRC", "/opt/xiaoyan-cloud"))
PORT = int(os.environ.get("PORT", "19446"))
BASE = "http://127.0.0.1:%d" % PORT
PY = os.environ.get("PY", "python3")
TS = str(int(time.time()))[-6:]
UA = "isotest/1.0"

PASS, FAIL = [], []


def ok(name, detail=""):
    PASS.append(name)
    print("  \033[32m✓\033[0m %-34s %s" % (name, detail))


def bad(name, detail=""):
    FAIL.append(name)
    print("  \033[31m✗\033[0m %-34s %s" % (name, detail))


def http(method, path, body=None, token=None, timeout=15):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
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


def sc(js):
    return js.get("status_code") if isinstance(js, dict) else None


def wait_port(proc, timeout=30):
    for _ in range(timeout):
        time.sleep(1)
        if proc.poll() is not None:
            return False
        try:
            s = socket.create_connection(("127.0.0.1", PORT), 1)
            s.close()
        except Exception:
            continue
        st, _ = http("GET", "/v1/speed", timeout=3)
        if st == 200:
            return True
    return False


def main():
    print("=== 多租户隔离回归 ===")
    print("源码目录: %s" % SRC)
    print("临时端口: %d" % PORT)

    need = ["cloud4.py", "auth.py", "admin_web.py"]
    for f in need:
        if not os.path.exists(os.path.join(SRC, f)):
            print("✗ 缺少 %s（SRC 不对？）" % f)
            return 2
    proto = os.path.join(SRC, "terncy_proto.py")
    if not os.path.exists(proto):
        proto = os.path.join(os.path.dirname(SRC), "terncy_proto.py")
    if not os.path.exists(proto):
        print("✗ 找不到 terncy_proto.py")
        return 2

    tmp = tempfile.mkdtemp(prefix="iso-test.")
    proc = None
    try:
        for f in need + ["admin_assets"]:
            src = os.path.join(SRC, f)
            if os.path.exists(src):
                dst = os.path.join(tmp, f)
                if os.path.isdir(src):
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
        shutil.copy2(proto, os.path.join(tmp, "terncy_proto.py"))
        # 复制线上真实数据（含真实租户），测完即弃
        for f in ["tenants.json", "accounts.json", "tokens.json", "ipuid.json"]:
            src = os.path.join(SRC, f)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(tmp, f))

        # ---- 预置测试租户（必须在实例启动前写，tenants 是启动时加载的）----
        a = "isotest-a-%s@invalid.local" % TS
        b = "isotest-b-%s@invalid.local" % TS
        hc_a = "box-isotest-a-%s" % TS
        hc_b = "box-isotest-b-%s" % TS
        tp = os.path.join(tmp, "tenants.json")
        try:
            td = json.load(open(tp, encoding="utf-8")) if os.path.exists(tp) else {}
        except Exception:
            td = {}
        td.setdefault("_member_type", 2)
        td[a] = []                 # A 稍后自己认领一台
        td[b] = [hc_b]             # B 有自己的家
        td["_member_perm"] = {b: 8}   # B = 只读访客（8 不在 control/edit 白名单）
        with open(tp, "w", encoding="utf-8") as f:
            json.dump(td, f, ensure_ascii=False, indent=2)
        os.makedirs(os.path.join(tmp, "logs"), exist_ok=True)

        env = dict(os.environ)
        env.update({
            "PLAIN": "1", "PORT": str(PORT),
            "TENANTS": tp,
            "TOKENS": os.path.join(tmp, "tokens.json"),
            "IPUID": os.path.join(tmp, "ipuid.json"),
            "ACCOUNTS": os.path.join(tmp, "accounts.json"),
            "ADMIN_FILE": os.path.join(tmp, "admin.json"),
            "GATEWAYS": os.path.join(tmp, "gateways.json"),
            "LOGDIR": os.path.join(tmp, "logs"),
        })
        out = open(os.path.join(tmp, "stdout.log"), "wb")
        proc = subprocess.Popen([PY, os.path.join(tmp, "cloud4.py")],
                                cwd=tmp, env=env, stdout=out, stderr=subprocess.STDOUT)
        if not wait_port(proc):
            print("✗ 临时实例没起来，日志尾部：")
            try:
                out.flush()
                with open(os.path.join(tmp, "stdout.log"), "rb") as f:
                    print(f.read()[-800:].decode("utf-8", "replace"))
            except Exception:
                pass
            return 2
        print("✓ 临时实例已就绪（数据是线上副本，改动只落在临时目录）\n")

        pw = "IsoTest-%s-Pw" % TS

        # ---- 准备两个账号 ----
        for uid in (a, b):
            st, js = http("POST", "/users", {"id_type": "email", "id": uid,
                                             "credential": pw, "verification_code_id": "x"})
            if sc(js) != 20000:
                print("✗ 注册失败 %s: %s" % (uid, str(js)[:120]))
                return 2
        ta = tb = ""
        for uid in (a, b):
            st, js = http("POST", "/users/authenticate",
                          {"id_type": "email", "id": uid, "credential": pw})
            tk = (js.get("token") or "") if isinstance(js, dict) else ""
            if uid == a:
                ta = tk
            else:
                tb = tk
        if not (ta and tb):
            print("✗ 登录失败，拿不到 token")
            return 2

        print("[1] A 认领一台全新家庭中心")
        st, js = http("POST", "/devices/%s/association" % hc_a, {}, token=ta)
        if sc(js) == 20000:
            ok("A 认领成功", "hc=%s" % hc_a)
        else:
            bad("A 认领成功", "status_code=%s" % sc(js))

        print("[2] B 试图抢注同一台（一房两主）")
        st, js = http("POST", "/devices/%s/association" % hc_a, {}, token=tb)
        if sc(js) == 40100:
            ok("B 抢注被拒", sc(js))
        else:
            bad("B 抢注被拒", "status_code=%s（期望 40100）" % sc(js))

        print("[3] 跨账号 roster")
        st, ja = http("GET", "/users/~/roster", token=ta)
        hcs_a = [h.get("uuid") for h in (ja.get("home_centers") or [])] if isinstance(ja, dict) else []
        if hc_a in hcs_a:
            ok("A 能看到自己的 hc", len(hcs_a))
        else:
            bad("A 能看到自己的 hc", "hcs=%s" % hcs_a)
        st, jb = http("GET", "/users/~/roster", token=tb)
        hcs_b = [h.get("uuid") for h in (jb.get("home_centers") or [])] if isinstance(jb, dict) else []
        if hc_a not in hcs_b:
            ok("B 看不到 A 的 hc", "B 有 %d 台" % len(hcs_b))
        else:
            bad("B 看不到 A 的 hc", "B 竟然看到 %s" % hc_a)

        print("[4] 权限位按成员生效")
        perm_a = None
        for it in ((ja.get("roster") or []) if isinstance(ja, dict) else []):
            if it.get("Username") == hc_a:
                perm_a = it.get("Permission")
        perm_b = None
        for it in ((jb.get("roster") or []) if isinstance(jb, dict) else []):
            if it.get("Username") == hc_b:
                perm_b = it.get("Permission")
        if perm_a == 14:
            ok("A 默认全权 (14)", perm_a)
        else:
            bad("A 默认全权 (14)", "拿到 %r" % (perm_a,))
        if perm_b == 8:
            ok("B 只读 (8)", perm_b)
        else:
            bad("B 只读 (8)", "拿到 %r（_member_perm 未生效？）" % (perm_b,))

        print("[5] 跨 hc 成员表")
        st, js = http("GET", "/users/%s/roster" % hc_a, token=tb)
        mem = (js.get("members") or []) if isinstance(js, dict) else []
        if not mem:
            ok("B 读不到 A 的成员表", "members=[]")
        else:
            bad("B 读不到 A 的成员表", "泄露 %d 条" % len(mem))
        st, js = http("GET", "/users/%s/roster" % hc_a)
        mem = (js.get("members") or []) if isinstance(js, dict) else []
        if not mem:
            ok("匿名读不到成员表", "members=[]")
        else:
            bad("匿名读不到成员表", "泄露 %d 条" % len(mem))

        print("[6] 跨 uid 成员条目（A2 回归）")
        st, js = http("GET", "/users/%s/roster" % b, token=ta)
        names = [m.get("Username") for m in (js.get("members") or [])] if isinstance(js, dict) else []
        if b not in names:
            ok("A 读不到 B 的条目", "names=%s" % names)
        else:
            bad("A 读不到 B 的条目", "泄露 %s" % b)

        print("\n" + "=" * 52)
        print("通过 %d / 失败 %d" % (len(PASS), len(FAIL)))
        if FAIL:
            print("失败项: " + ", ".join(FAIL))
            return 1
        return 0
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
