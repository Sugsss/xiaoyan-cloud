#!/bin/bash
# restore_drill.sh —— 备份恢复演练（"备份没恢复过 = 没有备份"）
# ============================================================================
# 做什么：取最新（或指定）备份 → 解到临时目录 → 校验文件与 JSON → 用**另一个端口**
#         真起一个实例 → 打 /v1/speed 确认能服务 → 打印统计 → 清理。
# 不碰线上：临时目录 + 独立端口 + 不读线上 tenants/tokens（全部用备份里的）。
# 用法：
#   ./restore_drill.sh                       # 用最新备份
#   ./restore_drill.sh /path/to/xxx.tar.gz   # 用指定备份
#   PORT=19444 ./restore_drill.sh            # 换端口（默认 19444）
# 退出码：0=通过，1=备份缺失/解包失败，2=文件或 JSON 校验失败，3=实例起不来
# ============================================================================
set -uo pipefail

SRC="${SRC:-/opt/xiaoyan-cloud}"
PORT="${PORT:-19444}"
ARC="${1:-$(ls -1t "$SRC"/backups/*.tar.gz 2>/dev/null | head -1)}"
PY="${PY:-python3}"

TMP=$(mktemp -d /tmp/restore-drill.XXXXXX) || exit 1
PID=""
cleanup() {
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null
        wait "$PID" 2>/dev/null      # 显式 wait，避免 shell 打印 "Terminated"
        kill -9 "$PID" 2>/dev/null
    fi
    rm -rf "$TMP"
} 2>/dev/null
trap cleanup EXIT

echo "=== 备份恢复演练 ==="
echo "备份包 : ${ARC:-<未找到>}"
echo "临时目录: $TMP"
echo "演练端口: $PORT"
echo

if [ -z "${ARC:-}" ] || [ ! -f "$ARC" ]; then
    echo "✗ 找不到备份包（$SRC/backups/*.tar.gz）"; exit 1
fi
echo "包大小 : $(du -h "$ARC" | cut -f1)"

# ---- 1) 解包 ---------------------------------------------------------------
if ! tar xzf "$ARC" -C "$TMP" 2>/dev/null; then
    echo "✗ 解包失败（备份可能已损坏）"; exit 1
fi
echo "✓ 解包成功"

# ---- 2) 关键文件 + JSON 校验 ----------------------------------------------
MISS=0
for f in tenants.json accounts.json tokens.json cloud4.py auth.py admin_web.py terncy_proto.py; do
    if [ -f "$TMP/$f" ]; then
        printf "  ✓ %-18s %6s\n" "$f" "$(du -h "$TMP/$f" | cut -f1)"
    else
        printf "  ✗ %-18s 缺失\n" "$f"; MISS=$((MISS+1))
    fi
done
[ "$MISS" -gt 0 ] && { echo "✗ 有 $MISS 个关键文件缺失（terncy_proto.py 缺失=备份不完整，恢复必崩）"; exit 2; }

"$PY" - "$TMP" <<'PY' || exit 2
import json, os, sys
d = sys.argv[1]
def load(n):
    p = os.path.join(d, n)
    with open(p, encoding="utf-8") as f:
        return json.load(f)
try:
    t = load("tenants.json"); a = load("accounts.json"); k = load("tokens.json")
except Exception as e:
    print("  ✗ JSON 解析失败: %s: %s" % (type(e).__name__, e)); sys.exit(2)
users = {u: h for u, h in t.items() if not str(u).startswith("_")}
hcs = sorted({h for hs in users.values() for h in (hs or [])})
accs = [u for u in a if not str(u).startswith("_")]
print("  ✓ JSON 全部可解析")
print("  · 归属账号 %d 个 / 家庭中心 %d 台 / 已注册账号 %d 个 / token %d 条"
      % (len(users), len(hcs), len(accs), len(k)))
print("  · _vg_bridge=%r _member_type=%r _mqtt_acl=%r"
      % (t.get("_vg_bridge", "<缺>"), t.get("_member_type"), t.get("_mqtt_acl")))
PY

# ---- 3) 真起一个实例 -------------------------------------------------------
echo
echo "--- 起演练实例 ---"
cd "$TMP" || exit 3
PLAIN=1 PORT="$PORT" \
TENANTS="$TMP/tenants.json" TOKENS="$TMP/tokens.json" IPUID="$TMP/ipuid.json" \
ACCOUNTS="$TMP/accounts.json" ADMIN_FILE="$TMP/admin.json" \
GATEWAYS="$TMP/gateways.json" LOGDIR="$TMP/logs" \
"$PY" "$TMP/cloud4.py" >"$TMP/stdout.log" 2>&1 &
PID=$!

CODE=""
for _ in $(seq 1 30); do
    sleep 1
    CODE=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "http://127.0.0.1:$PORT/v1/speed" 2>/dev/null)
    [ "$CODE" = "200" ] && break
    kill -0 "$PID" 2>/dev/null || break
done

if [ "$CODE" = "200" ]; then
    echo "✓ 实例起来了，/v1/speed = 200"
    ROSTER=$(curl -s -m 5 "http://127.0.0.1:$PORT/users/~/roster" 2>/dev/null | head -c 80)
    echo "  /users/~/roster（匿名应为空）: $ROSTER"
else
    echo "✗ 实例没起来（最后状态码='$CODE'）"
    echo "--- 启动日志尾部 ---"; tail -15 "$TMP/stdout.log" 2>/dev/null
    exit 3
fi

echo
echo "=== 演练通过：这份备份可以用于整机恢复 ==="
echo "注意：演练只验证「能起来 + 数据完整」，不代表网关会立刻重连（那取决于线上身份）。"
