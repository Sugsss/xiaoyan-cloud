#!/bin/bash
# watchdog_cloud.sh —— 小燕家庭云本机探活 + 自动重启（部署到 /opt/xiaoyan-cloud/watchdog.sh）
# ============================================================================
# 每 2 分钟由 cron 调用：
#   1) systemd 服务是否 active
#   2) https://api.example.com/v1/speed 是否 200（走完整 nginx → cloud4 链路）
#   3) 任一失败 → 重启服务（5 分钟冷却，避免崩溃循环里反复重启）
#   4) 配了 HEALTH_PING（如 healthchecks.io 的 ping URL）就顺带上报
#
# 局限（必须知道）：本机 watchdog 解决「进程挂了」，**解决不了整机宕机 / 断网**。
# 真正的外部探活需要在服务器之外跑（healthchecks.io / UptimeRobot / 另一台机器）。
# ============================================================================
set -uo pipefail

SERVICE="${SERVICE:-xiaoyan-cloud}"
URL="${HEALTH_URL:-https://api.example.com/v1/speed}"
STATE="${STATE:-/run/xiaoyan-cloud-watchdog.last}"
COOLDOWN="${COOLDOWN:-300}"

now=$(date +%s)
last=$(cat "$STATE" 2>/dev/null || echo 0)
[ -z "$last" ] && last=0
can_restart=0
[ $(( now - last )) -gt "$COOLDOWN" ] && can_restart=1

fail() {
    local why="$1"
    echo "[$(date '+%F %T')] ✗ $why"
    if [ "$can_restart" = "1" ]; then
        systemctl restart "$SERVICE"
        echo "$now" > "$STATE" 2>/dev/null || true
        sleep 5
        if systemctl is-active --quiet "$SERVICE"; then
            echo "[$(date '+%F %T')] ↻ 已重启，服务恢复"
        else
            echo "[$(date '+%F %T')] ✗✗ 重启后仍不正常，需人工介入" >&2
        fi
    else
        echo "[$(date '+%F %T')] ⏸ 冷却中（距上次重启 $((now - last))s，阈值 ${COOLDOWN}s），跳过重启"
    fi
    exit 1
}

systemctl is-active --quiet "$SERVICE" || fail "systemd 服务未运行"

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$URL" 2>/dev/null || echo 000)
[ "$code" = "200" ] || fail "HTTP $code ($URL)"

# 外部探活上报（可选）
if [ -n "${HEALTH_PING:-}" ]; then
    curl -s -m 8 -o /dev/null "$HEALTH_PING" 2>/dev/null || true
fi

echo "[$(date '+%F %T')] ✓ 服务正常 (HTTP $code)"
