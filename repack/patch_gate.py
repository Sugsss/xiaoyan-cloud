#!/usr/bin/env python3
"""
patch_gate.py —— 把 HomeCenter::hasControlPermission 改成恒返回 true。

背景
----
`device_view.onTap` / `device_detail_popup` 在真正下发 RPC 前会调用
`HomeCenter::hasControlPermission`（libapp.so:0xae1890）：

    defaultSession().field_13 == "LOCAL" → true
    否则要求 hc.field_43 ∈ [4, 6, 12, 14]

field_43 来自 roster 项的 `Permission` 字段（session.dart 0x8dfab4 会覆盖
构造函数默认值 14）。假云端早期一直返回 `Permission: 0` → 判无权限 →
点击被静默丢弃。云端侧已改为 14（见 xiaoyan-cloud/cloud4.py），本脚本是
客户端侧兜底。

为什么不用「改函数入口直接 ret」
--------------------------------
Dart AOT 里 `true` 不是整数 1，而是压缩对象指针；在函数入口写
`movz w0,#1; ret` 会让调用方把 1 当指针解引用 → SIGSEGV（已实测踩坑）。
直接抄 `add x0, x22, #0x20` 也不稳（x22 不一定是 null 寄存器）。

安全做法：只把 0xae1914 那条「session 不是 LOCAL 就跳去白名单比对」的
条件跳转改成 NOP，让函数**无条件走原有的 `return true` 代码路径**——
栈帧进出、LeaveFrame、ret 全部由原代码自己完成，零副作用。

   原始:
     0xae1914  a0 00 20 37   tbnz  w0, #4, 0xae1928   ; 非 LOCAL → 跳去白名单
     0xae1918  910082c0      add   x0, x22, #0x20      ; r0 = true
     0xae191c  aa1d03ef      mov   x15, x29           ; LeaveFrame
     0xae1920  a8c179fd      ldp   x29, x30, [sp], #16
     0xae1924  d65f03c0      ret
   补丁后:
     0xae1914  d503201f      nop

用法
----
  python3 patch_gate.py <patched_dir>     # 目录里有 lib/<abi>/libapp.so
只处理 arm64-v8a（手机是 arm64；v7a 不动，手机不会加载）

地址→文件偏移：libapp.so 的 .text 段 VMA == 文件偏移（已验证，多个函数
入口读到的都是 `fd 79 bf a9` = stp x29,x30,[sp,#-0x10]!）。
"""
import os
import sys

ORIG = bytes.fromhex("a00020 37".replace(" ", ""))   # tbnz w0,#4,<白名单>
PATCH = bytes.fromhex("1f2003d5")                    # nop

# 所有「远程会话下要用 field_43 白名单卡权限」的函数。
# 局域网（session.field_13 == "LOCAL"）时会短路返回 true，所以原始 App 在局域网里
# 从来不暴露这个问题；但走假云端（远程会话）时必然进白名单比对。
#
#   tbnz w0, #4, <白名单>     ; == 的结果是 false（指针 NULL+0x30，bit4=1）→ 跳去比对
#   紧接着就是 add x0, NULL, #0x20 ; return true
# 所以把这条 tbnz NOP 掉，函数就无条件走原有的 return true 路径，栈帧/ret 全由原码完成。
GATES = [
    # (地址, 函数, 白名单位掩码)
    (0xae1914, "HomeCenter::hasControlPermission", "{4,6,12,14} CONTROL"),
    (0x940c8c, "HomeCenter::hasEditPermission",    "{2,6,10,14} EDIT"),
]

# 参考：还有两处「内联」判断（不在上面两个 getter 里），只影响设置页/管理页的
# 按钮置灰，不影响主流程，暂不打：
#   home_center_setting_detail.dart  0xca7330
#   home_center_manager_page.dart    0xfd1b14


def main():
    if len(sys.argv) < 2:
        print("用法: python3 patch_gate.py <patched_dir>")
        return 1
    root = sys.argv[1]
    so = os.path.join(root, "lib", "arm64-v8a", "libapp.so")
    if not os.path.isfile(so):
        print(f"找不到 {so}")
        return 1

    rc = 0
    with open(so, "r+b") as f:
        for addr, name, mask in GATES:
            f.seek(addr)
            cur = f.read(4)
            if cur == PATCH:
                print(f"  {name} @0x{addr:x} 已打过，跳过")
                continue
            if cur != ORIG:
                print(f"⚠️ {name} @0x{addr:x} 处是 {cur.hex()}，期望 {ORIG.hex()}，地址映射不对，中止")
                rc = 2
                continue
            f.seek(addr)
            f.write(PATCH)
            print(f"✅ {name} 已打穿 @0x{addr:x}  {ORIG.hex()} -> {PATCH.hex()}  (tbnz→nop, 白名单 {mask})")
    if rc == 0:
        print(f"门禁补丁完成: {so}（共 {len(GATES)} 处）")
    return rc


if __name__ == "__main__":
    sys.exit(main())
