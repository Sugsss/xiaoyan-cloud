#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
libapp.so 文案补丁（只做**等长**替换，纯字节覆盖）
====================================================
背景：业务已经改成「只支持邮箱 + 密码」，但 App 界面还是「手机号码/邮箱」「未注册的手机号
将自动创建账号」这些旧文案。这些中文在 Dart 快照里是 **TwoByteString（UTF-16LE，每字 2 字节）**，
只要**字符数完全一致**，替换就只是覆盖那一片字节 —— 长度头（0x9F 之类）不用动，
快照结构零改动，和改主机名是同一安全等级。

⚠️ 不要在这里写「比原文短/长」的替换。缩短要改快照的长度字段并处理尾部残留，
   历史上走过那条路（patch_hosts 的手术分支）→ 快照损坏 → App 启动即 SIGSEGV。

用法：
    python3 patch_text.py <patched_dir>          # patched_dir 里有 lib/<abi>/libapp.so
    python3 patch_text.py --list                 # 只列出表里的替换
    python3 patch_text.py --dry-run <apk>        # 对着原版 APK 检查命中情况，不写文件
"""
import os
import sys
import zipfile

# (旧文案, 新文案) —— 必须字符数相同
REPLACEMENTS = [
    # 登录/注册页的输入框提示
    ("请输入手机号码/邮箱", "请输入完整的邮箱地址"),
    # 注册页下方说明（带前导逗号的版本优先，见下方两种都试）
    ("，未注册的手机号将自动创建账号", "，未注册的新邮箱会自动创建账号"),
    ("未注册的手机号将自动创建账号", "未注册的新邮箱会自动创建账号"),
    # 手机号输入时的区域提示
    ("目前仅支持中国地区手机号", "目前仅支持邮箱账号登录。"),
    # 重复注册的报错
    ("手机号已被绑定至其他账号", "该邮箱已注册，请直接登录"),
    # 校验失败提示
    ("请输入正确的手机号或邮箱", "请输入有效的邮箱地址即可"),
    # 账号页的绑定状态
    ("未绑定手机", "未绑定邮箱"),
    # 登录页第三方登录区标题（微信/QQ/Google/Apple 已被服务端拒绝）
    ("其它登录方式", "已停用的方式"),
]

ABIS = ("arm64-v8a", "armeabi-v7a")


def enc(s):
    return s.encode("utf-16-le")


def check_table():
    bad = []
    for old, new in REPLACEMENTS:
        if len(old) != len(new):
            bad.append((old, new, len(old), len(new)))
    return bad


def patch_one(path, verbose=True):
    """返回 (替换计数, 差异字节数)"""
    with open(path, "rb") as f:
        data = bytearray(f.read())
    total = 0
    for old, new in REPLACEMENTS:
        if len(old) != len(new):
            if verbose:
                print("  ✗ 跳过（字数不等）%r -> %r (%d/%d)" % (old, new, len(old), len(new)))
            continue
        ob, nb = enc(old), enc(new)
        n = 0
        start = 0
        while True:
            i = data.find(ob, start)
            if i < 0:
                break
            data[i:i + len(ob)] = nb
            n += 1
            start = i + len(ob)
        if n:
            total += n
            if verbose:
                print("  ✓ %r -> %r  ×%d" % (old, new, n))
    with open(path, "wb") as f:
        f.write(data)
    return total


def verify(path):
    """确认旧串已清空、新串都在"""
    data = open(path, "rb").read()
    problems = []
    for old, new in REPLACEMENTS:
        if len(old) != len(new):
            continue
        if enc(old) in data:
            # 兼容「带逗号/不带逗号」两种：只要这一条在别的变体里已覆盖，就不算问题
            problems.append("旧文案残留: %r" % old)
        if enc(new) not in data:
            problems.append("新文案缺失: %r" % new)
    return problems


def main():
    args = sys.argv[1:]
    bad = check_table()
    if bad:
        print("替换表里有字数不相等的项，拒绝打补丁：")
        for old, new, a, b in bad:
            print("   %r(%d) -> %r(%d)" % (old, a, new, b))
        return 2
    if not args or args[0] in ("--list", "-l"):
        for old, new in REPLACEMENTS:
            print("%-18s -> %-18s (%d 字)" % (old, new, len(old)))
        return 0

    if args[0] == "--dry-run":
        apk = args[1]
        z = zipfile.ZipFile(apk)
        for abi in ABIS:
            name = "lib/%s/libapp.so" % abi
            if name not in z.namelist():
                continue
            data = z.read(name)
            print("[%s]" % abi)
            for old, new in REPLACEMENTS:
                c = data.count(enc(old))
                print("   %-18r 命中 %d" % (old, c))
        return 0

    root = args[0]
    grand = 0
    for abi in ABIS:
        p = os.path.join(root, "lib", abi, "libapp.so")
        if not os.path.isfile(p):
            print("[%s] 不存在，跳过" % abi)
            continue
        print("[%s] %s" % (abi, p))
        grand += patch_one(p)
        probs = verify(p)
        for x in probs:
            print("   ⚠ " + x)
    print("文案补丁完成，共替换 %d 处" % grand)
    return 0 if grand else 1


if __name__ == "__main__":
    sys.exit(main())
