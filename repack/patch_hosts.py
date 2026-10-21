#!/usr/bin/env python3
"""小燕(Terncy) App 服务器地址补丁工具 v3 —— 快照字符串手术版
==============================================================
实锤的 Dart AOT 快照字符串格式(2026-10-17 逆向确认):

  arm64-v8a:  [0x80|(len<<1)][data]  连续排列, 无哈希无对齐
              (v2 脚本"arm64 无本地长度字段"的判断是错的)
  armeabi-v7a:[38 units 55 00][len<<1 (4B LE)][4字节标识][data][零填充至 units*8]
              (v2 脚本在 O-4 找长度字段也是错的, 真长度在 O-8; O-4 是标识字段)

因此新主机可以短于原串: 修正长度字段, 缺口用
  - arm64: 空串标记 0x80 填充 (每个 0x80 = 一个空 one-byte 串)
  - v7a : 记录内零填充 (units 字节不动, 下一记录位置不变)
保持字符串表链条同步, 快照可正常反序列化。

修补点(两 ABI 偏移均已实证):
  api.terncy.com 独立串 / https://api.terncy.com/users/ URL 字面量(整体重写)
  ws.terncy.com / api.sg|tw.terncy.com / ws.sg|tw.terncy.com (sg/tw 一并改)

用法:
    python3 patch_hosts.py <api_host> <ws_host> [--out 目录]
        [--api-sg H --api-tw H --ws-sg H --ws-tw H]
    各槽位上限(原串长度): api<=14, ws<=13, api.sg/tw<=17, ws.sg/tw<=16
    强烈建议全部等长(纯字符替换, 零结构改动); 非等长会自动手术(有快照破坏风险)
示例(example.com 全等长组):
    python3 patch_hosts.py apis.example.com wss.example.com \
        --api-sg apis.sg.example.com --api-tw apis.tw.example.com \
        --ws-sg wss.sg.example.com --ws-tw wss.tw.example.com --out out/patched
"""
import os
import struct
import sys

# 原厂 APK 解包后的目录（含 lib/<abi>/libapp.so）。
# ★ 2026-10-21：改成可用环境变量覆盖 —— 脚本单独搬到别的目录时也能用。
EXTRACTED = os.environ.get("APK_EXTRACTED") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "apk-extracted")

LIB_FILES = {
    "arm64-v8a": "lib/arm64-v8a/libapp.so",
    "armeabi-v7a": "lib/armeabi-v7a/libapp.so",
}

# (名称, 原串, arm64数据偏移, v7a数据偏移, 类型, 槽位)
# 槽位长度上限 = 原串长度; 新主机等长时纯字符替换(零结构改动, 最安全)
PATCH_POINTS = [
    ("api 独立串",     "api.terncy.com",               0xAC08F,  0x494534, "host", "api"),
    ("api URL 字面量", "https://api.terncy.com/users/", 0xC9B10,  0x4C85BC, "url",  "api"),
    ("ws 主机",        "ws.terncy.com",                0x7500E,  0x435CDC, "host", "ws"),
    ("api.sg 主机",    "api.sg.terncy.com",            0x139CDF, 0x58626C, "host", "api-sg"),
    ("api.tw 主机",    "api.tw.terncy.com",            0x18266D, 0x5F77AC, "host", "api-tw"),
    ("ws.sg 主机",     "ws.sg.terncy.com",             0x785E2,  0x43B88C, "host", "ws-sg"),
    ("ws.tw 主机",     "ws.tw.terncy.com",             0x5D2F4,  0x40C814, "host", "ws-tw"),
]

# 各槽位原串长度上限
SLOT_MAX = {"api": 14, "ws": 13, "api-sg": 17, "api-tw": 17, "ws-sg": 16, "ws-tw": 16}
EMPTY_MARK = 0x80  # arm64 空串长度字节


def valid_host(h):
    return h and all(c.isalnum() or c in ".-" for c in h) and not h.startswith("-") \
        and not h.endswith("-") and ".." not in h


def patch_arm64_string(data, off, old, new, label):
    """arm64: [len字节][data]; 缩短时长度字节改写 + 0x80 空串填充"""
    if len(new) > len(old):
        raise SystemExit(f"[{label}] 新串长 {len(new)} > 原串长 {len(old)}, 原地替换不可能")
    if len(old) >= 64 or len(new) >= 64:
        raise SystemExit(f"[{label}] 长度 >=64 的串使用扩展长度编码, 不支持")
    actual = data[off:off + len(old)]
    if actual != old.encode():
        raise SystemExit(f"[{label}] 偏移 0x{off:x} 内容不匹配(期望 {old!r}, 实际 {actual[:24]!r})")
    lb = off - 1
    expect_lb = EMPTY_MARK | (len(old) << 1)
    if data[lb] != expect_lb:
        raise SystemExit(f"[{label}] arm64 长度字节 0x{data[lb]:02x} != 期望 0x{expect_lb:02x}, 格式异常")
    out = bytearray(data)
    out[lb] = EMPTY_MARK | (len(new) << 1)
    out[off:off + len(new)] = new.encode()
    for i in range(len(new), len(old)):
        out[off + i] = EMPTY_MARK  # 空串标记, 保持链条
    return bytes(out)


def patch_v7a_string(data, off, old, new, label):
    """v7a: [38 units 55 00][len<<1][标识4B][data][零填充至 units*8]; 记录内缩短"""
    if len(new) > len(old):
        raise SystemExit(f"[{label}] 新串长 {len(new)} > 原串长 {len(old)}")
    actual = data[off:off + len(old)]
    if actual != old.encode():
        raise SystemExit(f"[{label}] 偏移 0x{off:x} 内容不匹配(期望 {old!r}, 实际 {actual[:24]!r})")
    hdr = off - 12
    if data[hdr] != 0x38 or data[hdr + 3] != 0x00 or data[hdr + 2] not in (0x55, 0x56):
        raise SystemExit(f"[{label}] v7a 记录头异常: {data[hdr:hdr+4].hex()} (期望 38 XX 55/56 00)")
    units = data[hdr + 1]
    rec_size = units * 8
    if rec_size < 12 + len(old) or rec_size < 12 + len(new):
        raise SystemExit(f"[{label}] v7a 记录大小 {rec_size} 放不下 (units={units})")
    lf = off - 8
    cur = struct.unpack("<I", data[lf:lf + 4])[0]
    if cur != len(old) * 2:
        raise SystemExit(f"[{label}] v7a 长度字段 0x{cur:x} != {len(old)*2}")
    out = bytearray(data)
    struct.pack_into("<I", out, lf, len(new) * 2)
    out[off:off + len(new)] = new.encode()
    for i in range(off + len(new), hdr + rec_size):
        out[i] = 0  # 记录内零填充(units 不变 -> 下一记录位置不变)
    return bytes(out)


# ---------------- 验证 ----------------
def verify_arm64_chain(data, off, old_len, new_len, new_str, label):
    """重解析 arm64 链条: 长度字节/新串/后续串连续性"""
    lb = off - 1
    assert data[lb] == (EMPTY_MARK | (new_len << 1)), f"{label}: 长度字节未写对"
    got = data[off:off + new_len]
    assert got == new_str.encode(), f"{label}: 新串内容不符 {got!r}"
    # 后续应能继续解析出至少 3 个非空串(注意 bit0=1 是双字节串, 数据 2 倍)
    i = off + old_len
    n = 0
    while n < 3 and i < len(data):
        b = data[i]
        if not (b & EMPTY_MARK):
            break
        ln = (b & 0x7F) >> 1
        if ln > 200:
            break
        i += 1 + ln * (2 if (b & 1) else 1)
        n += 1
    assert n >= 3, f"{label}: 后续链条断裂(只解析出 {n} 个)"


def verify_v7a_record(data, orig, off, old_len, new_len, new_str, label):
    hdr = off - 12
    assert data[hdr] == 0x38 and data[hdr + 3] == 0x00
    units = data[hdr + 1]
    rec_size = units * 8
    lf = off - 8
    assert struct.unpack("<I", data[lf:lf + 4])[0] == new_len * 2, f"{label}: 长度字段未写对"
    got = data[off:off + new_len]
    assert got == new_str.encode(), f"{label}: 新串内容不符 {got!r}"
    # 记录尾部到下一记录头之间应全零
    for i in range(off + new_len, hdr + rec_size):
        assert data[i] == 0, f"{label}: 填充区 0x{i:x} 非零"
    # 下一记录起 16 字节应与原文件完全一致(证明记录边界未动)
    nxt = hdr + rec_size
    assert data[nxt:nxt + 16] == orig[nxt:nxt + 16], \
        f"{label}: 下一记录被意外改动 @0x{nxt:x}"


def verify_only_expected_bytes_changed(orig, new, ranges, label):
    """整文件 diff: 只允许预期区间(长度字段+原数据区)发生变化"""
    assert len(orig) == len(new), f"{label}: 文件长度变了"
    allowed = set()
    for s, e in ranges:
        allowed.update(range(s, e))
    bad = [i for i in range(len(orig)) if orig[i] != new[i] and i not in allowed]
    assert not bad, f"{label}: 预期外字节改动 @ {[hex(i) for i in bad[:10]]}"
    return True


def main():
    argv = sys.argv[1:]
    positional, out_dir = [], "./patched"
    opts = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--out":
            out_dir = argv[i + 1]; i += 2; continue
        if a.startswith("--") and i + 1 < len(argv):
            opts[a.lstrip("-").replace("-", "_")] = argv[i + 1]; i += 2; continue
        if a.startswith("--"):
            i += 1; continue
        positional.append(a); i += 1
    if len(positional) < 2:
        print(__doc__); return 2
    api_host, ws_host = positional[0], positional[1]

    # sg/tw 区服独立主机(默认与 api/ws 相同; 等长方案显式传入)
    hosts = {
        "api": api_host, "ws": ws_host,
        "api-sg": opts.get("api_sg", api_host),
        "api-tw": opts.get("api_tw", api_host),
        "ws-sg":  opts.get("ws_sg",  ws_host),
        "ws-tw":  opts.get("ws_tw",  ws_host),
    }
    for slot, h in hosts.items():
        mx = SLOT_MAX[slot]
        if len(h) > mx:
            raise SystemExit(f"{slot}_host 长度 {len(h)} > {mx} (槽位上限), 原地替换不可能")
        if not valid_host(h):
            raise SystemExit(f"{slot}_host 含非法字符: {h!r}")
    if len(hosts["api-sg"]) != 17 or len(hosts["api-tw"]) != 17 \
       or len(hosts["ws-sg"]) != 16 or len(hosts["ws-tw"]) != 16:
        print("!! 注意: sg/tw 主机未严格等长, 将动用缩短手术(有快照破坏风险)")

    os.makedirs(out_dir, exist_ok=True)
    total = 0
    for abi, rel in LIB_FILES.items():
        src = os.path.join(EXTRACTED, rel)
        dst = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        orig = open(src, "rb").read()
        data = orig
        orig_len = len(orig)
        ranges = []  # 预期改动区间(与原始文件 diff 用)
        for name, old, o64, o32, kind, slot in PATCH_POINTS:
            off = o64 if abi == "arm64-v8a" else o32
            host = hosts[slot]
            new = f"https://{host}/users/" if kind == "url" else host
            label = f"{abi} {name}"
            if len(new) != len(old):
                print(f"[{abi}] {name}: 缩短手术 {len(old)}->{len(new)} (有风险)")
            if abi == "arm64-v8a":
                data = patch_arm64_string(data, off, old, new, label)
                ranges.append((off - 1, off + len(old)))
            else:
                data = patch_v7a_string(data, off, old, new, label)
                units = data[off - 12 + 1]
                ranges.append((off - 12, off - 12 + units * 8))
            print(f"[{abi}] {name} @0x{off:x}: {old!r} -> {new!r}")
            total += 1
        assert len(data) == orig_len, "补丁后文件长度发生变化!"
        open(dst, "wb").write(data)
        print(f"[{abi}] 已写出 {dst} ({len(data):,} bytes)\n")

    # ---- 写出后验证(重新读盘 + 与原始文件对比) ----
    print("==> 验证补丁结果")
    for abi, rel in LIB_FILES.items():
        orig = open(os.path.join(EXTRACTED, rel), "rb").read()
        data = open(os.path.join(out_dir, rel), "rb").read()
        ranges = []
        for name, old, o64, o32, kind, slot in PATCH_POINTS:
            off = o64 if abi == "arm64-v8a" else o32
            host = hosts[slot]
            new = f"https://{host}/users/" if kind == "url" else host
            label = f"{abi} {name}"
            if abi == "arm64-v8a":
                verify_arm64_chain(data, off, len(old), len(new), new, label)
                ranges.append((off - 1, off + len(old)))
            else:
                verify_v7a_record(data, orig, off, len(old), len(new), new, label)
                units = data[off - 12 + 1]
                ranges.append((off - 12, off - 12 + units * 8))
        verify_only_expected_bytes_changed(orig, data, ranges, abi)
        for gone in ("api.terncy.com", "ws.terncy.com", "api.sg.terncy.com",
                     "api.tw.terncy.com", "ws.sg.terncy.com", "ws.tw.terncy.com"):
            assert gone.encode() not in data, f"[{abi}] 旧主机 {gone} 仍存在!"
        for slot, h in hosts.items():
            assert h.encode() in data, f"[{abi}] 新主机 {h} 不存在!"
        print(f"[{abi}] 验证通过: 7 处修补 + 链条连续 + 记录边界未动 + 旧主机已清除")
    print(f"\n完成, 共修补 {total} 处。补丁后的 libapp.so 在: {out_dir}/lib/*/libapp.so")
    return 0


if __name__ == "__main__":
    sys.exit(main())
