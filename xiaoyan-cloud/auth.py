# -*- coding: utf-8 -*-
"""
账号与密码（自注册 / 校验 / 改密）
====================================
背景：v4 之前 `/users/authenticate` 既不校验密码也不校验验证码 —— 知道账号名就能
完整冒充（REVIEW.md P0）。本模块把「账号 -> 密码哈希」落成独立文件，
由 cloud4.py 在登录分支强制校验。

设计取舍：
  · 独立 accounts.json，不塞进 tenants.json
      → tenants.json 会被运行时改写（自动认领 / association），两份数据分开更安全，
        管理员手工编辑归属表时也不会误伤密码。
  · PBKDF2-HMAC-SHA256，12 万轮，每账号独立盐
      → 纯 stdlib（服务器 Python 3.6.8 没有 bcrypt/argon2），单次校验约 60ms，
        对「一天几次登录」的量级完全够用；哈希串里自带算法/轮数/盐，日后可平滑升级。
  · 邮箱统一转小写；手机号保持数字
      → 否则 Test@x.com 与 test@x.com 会变成两个账号。

文件格式：
    {
      "13800000000": {"pw": "pbkdf2_sha256$120000$<salt>$<digest>",
                       "created": 1750000000, "last_login": 0,
                       "nickname": "主人", "enabled": true}
    }
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_FILE = os.environ.get("ACCOUNTS", os.path.join(BASE, "accounts.json"))

ITERATIONS = 120000
MIN_PW_LEN = 8
MAX_PW_LEN = 128

_LOCK = threading.Lock()
_CACHE = None          # uid -> dict


def log(msg):
    # 由 cloud4 覆盖成它的 log，避免这里另开一套 logging handler
    print("[auth] " + str(msg))


# ---------------------------------------------------------------- 账号格式
# 2026-10-20 决策：**只允许邮箱账号**。
# 原因（真机实锤）：App 对邮箱给「密码框」，对手机号只给「获取验证码」，
# 而本服务器没有短信通道 → 手机号账号注册完就再也登不进去。
# 与其留一个能注册不能登录的死账号，不如从一开始就只收邮箱。
EMAIL_ONLY = True

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_MOBILE_RE = re.compile(r"^1\d{10}$")


def normalize(uid):
    """账号归一化：邮箱小写，其它去空白。"""
    u = (uid or "").strip()
    if "@" in u:
        u = u.lower()
    return u


def valid_uid(uid):
    """注册/建号只接受邮箱。"""
    u = normalize(uid)
    return bool(_EMAIL_RE.match(u))


def is_mobile(uid):
    """仅用于给出友好提示（不参与合法性判断）。"""
    return bool(_MOBILE_RE.match(normalize(uid)))


def uid_kind(uid):
    return "email"


def uid_problem(uid):
    """账号格式的友好错误提示；None 表示通过。"""
    u = normalize(uid)
    if not u:
        return "请填写邮箱"
    if is_mobile(u):
        return "本服务器只支持邮箱登录，请填邮箱（手机号收不到验证码）"
    if "@" not in u:
        return "账号格式不对，请填完整邮箱"
    if not valid_uid(u):
        return "邮箱格式不对"
    return None


def pw_problem(pw):
    """返回错误提示；None 表示通过。"""
    if not pw or len(pw) < MIN_PW_LEN:
        return "密码至少 %d 位" % MIN_PW_LEN
    if len(pw) > MAX_PW_LEN:
        return "密码太长（最多 %d 位）" % MAX_PW_LEN
    if pw.strip() == "":
        return "密码不能全是空格"
    return None


# ---------------------------------------------------------------- 哈希
def hash_pw(pw):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt.encode("ascii"), ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (ITERATIONS, salt, dk.hex())


def check_pw(pw, stored):
    """恒定时间比较。格式不认识时返回 False（宁可拒绝，不放过）。"""
    try:
        algo, iters, salt, digest = (stored or "").split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", (pw or "").encode("utf-8"),
                                 salt.encode("ascii"), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


# ---------------------------------------------------------------- 存储
def _empty():
    return {}


def load(force=False):
    global _CACHE
    with _LOCK:
        if _CACHE is not None and not force:
            return _CACHE
        if not os.path.exists(ACCOUNTS_FILE):
            _CACHE = _empty()
            return _CACHE
        try:
            raw = json.load(open(ACCOUNTS_FILE, encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("not a dict")
        except Exception as e:
            log("读取 %s 失败: %s: %s —— 视为空表" % (ACCOUNTS_FILE, type(e).__name__, e))
            raw = {}
        _CACHE = dict((normalize(k), v) for k, v in raw.items()
                      if not str(k).startswith("_") and isinstance(v, dict))
        return _CACHE


def save():
    with _LOCK:
        data = dict(_CACHE or {})
        try:
            out = {"_readme": "账号 -> 密码哈希（PBKDF2-SHA256）。请用后台 /admin 增删改，"
                               "手工编辑后需 systemctl restart xiaoyan-cloud。"}
            out.update(data)
            tmp = ACCOUNTS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, ACCOUNTS_FILE)
            return True
        except Exception as e:
            log("写入 %s 失败: %s: %s" % (ACCOUNTS_FILE, type(e).__name__, e))
            return False


# ---------------------------------------------------------------- 业务操作
def get(uid):
    return load().get(normalize(uid))


def has_password(uid):
    a = get(uid)
    return bool(a and a.get("pw"))


def create(uid, pw, nickname="", must_change=False):
    """新建账号。返回 (ok, message)。已存在则失败（改密请用 set_password）。"""
    u = normalize(uid)
    bad_uid = uid_problem(u)
    if bad_uid:
        return False, bad_uid
    bad = pw_problem(pw)
    if bad:
        return False, bad
    acc = load()
    if u in acc and acc[u].get("pw"):
        return False, "该账号已注册"
    with _LOCK:
        acc[u] = {"pw": hash_pw(pw), "created": int(time.time()), "last_login": 0,
                  "nickname": nickname or u, "enabled": True,
                  "must_change": bool(must_change)}
    save()
    log("新建账号 %s" % u)
    return True, "ok"


def set_password(uid, pw):
    u = normalize(uid)
    bad = pw_problem(pw)
    if bad:
        return False, bad
    acc = load()
    with _LOCK:
        a = acc.get(u) or {"created": int(time.time()), "last_login": 0,
                           "nickname": u, "enabled": True}
        a["pw"] = hash_pw(pw)
        a["must_change"] = False
        acc[u] = a
    save()
    log("重置密码 %s" % u)
    return True, "ok"


def set_enabled(uid, on):
    u = normalize(uid)
    acc = load()
    if u not in acc:
        return False, "账号不存在"
    acc[u]["enabled"] = bool(on)
    save()
    return True, "ok"


def delete(uid):
    u = normalize(uid)
    acc = load()
    if u not in acc:
        return False, "账号不存在"
    with _LOCK:
        acc.pop(u, None)
    save()
    log("删除账号 %s" % u)
    return True, "ok"


def verify(uid, pw):
    """密码登录校验。返回 (ok, reason)。reason 仅供日志，别回给客户端。"""
    u = normalize(uid)
    if is_mobile(u):
        return False, "手机号账号已停用（只支持邮箱登录）"
    a = load().get(u)
    if not a or not a.get("pw"):
        return False, "账号未注册"
    if not a.get("enabled", True):
        return False, "账号已停用"
    if not check_pw(pw, a.get("pw")):
        return False, "密码错误"
    return True, "ok"


def touch_login(uid):
    u = normalize(uid)
    acc = load()
    if u in acc:
        acc[u]["last_login"] = int(time.time())
        save()


def count():
    return len(load())


# ---------------------------------------------------------------- 登录限速
# 内存级：进程重启即清零。目的只是挡暴力猜密码，不做持久化惩罚。
_FAILS = {}
_FAILS_LOCK = threading.Lock()
FAIL_LIMIT = 8
FAIL_WINDOW = 600          # 10 分钟内最多 8 次失败


def throttled(key):
    """返回还需等待的秒数；0 表示可以继续尝试。"""
    now = time.time()
    with _FAILS_LOCK:
        rec = _FAILS.get(key)
        if not rec:
            return 0
        cnt, first = rec
        if now - first > FAIL_WINDOW:
            _FAILS.pop(key, None)
            return 0
        if cnt < FAIL_LIMIT:
            return 0
        return int(FAIL_WINDOW - (now - first)) + 1


def note_fail(key):
    now = time.time()
    with _FAILS_LOCK:
        cnt, first = _FAILS.get(key, (0, now))
        if now - first > FAIL_WINDOW:
            cnt, first = 0, now
        _FAILS[key] = (cnt + 1, first)


def clear_fails(key):
    with _FAILS_LOCK:
        _FAILS.pop(key, None)


def gen_password(n=12):
    """给迁移账号用的随机密码（去掉了 0/O/1/l/I 这种看错的字符）。"""
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))
