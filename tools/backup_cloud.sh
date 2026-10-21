#!/bin/bash
# backup_cloud.sh —— 小燕家庭云每日备份（部署到 /opt/xiaoyan-cloud/backup.sh）
# ============================================================================
# 备份内容：归属表 / 账号 / 后台密码 / token / IP 登录记录 + 三个代码文件
# 落盘位置：/opt/xiaoyan-cloud/backups/xiaoyan-cloud-YYYYmmdd-HHMMSS.tar.gz（600）
# 保留策略：最近 14 份（约两周）
# 校验：打包后 `tar tzf` 必须成功，失败返回非 0（cron 会记录）
# ============================================================================
set -euo pipefail

SRC="${SRC:-/opt/xiaoyan-cloud}"
DST="$SRC/backups"
KEEP="${KEEP:-14}"
TS=$(date +%Y%m%d-%H%M%S)
OUT="$DST/xiaoyan-cloud-$TS.tar.gz"

mkdir -p "$DST"
chmod 700 "$DST"

# 只备份存在的数据文件；代码 + 前端静态资源一并带上，便于整机恢复
FILES=()
for f in tenants.json accounts.json admin.json tokens.json ipuid.json \
         cloud4.py auth.py admin_web.py admin_assets; do
    [ -e "$SRC/$f" ] && FILES+=("$f")
done

if [ ${#FILES[@]} -eq 0 ]; then
    echo "[$(date '+%F %T')] ✗ 没有可备份的文件（SRC=$SRC）" >&2
    exit 1
fi

# ★ 2026-10-21 恢复演练发现：cloud4.py 依赖**上一级目录**的 terncy_proto.py
#   （`sys.path.insert(0, dirname(dirname(__file__)))`），而它不在 SRC 里。
#   只打 SRC 的话，恢复出来的实例 import 就崩 —— 备份等于无效。
#   这里用第二个 -C 把它一并打到包根，恢复时放进服务目录（脚本目录自动进 sys.path）即可。
PARENT_PY="$(dirname "$SRC")/terncy_proto.py"
if [ -f "$PARENT_PY" ]; then
    tar czf "$OUT" -C "$SRC" "${FILES[@]}" -C "$(dirname "$SRC")" terncy_proto.py
else
    echo "[$(date '+%F %T')] ⚠ 未找到 $PARENT_PY —— 备份将缺少 proto 模块，恢复会失败" >&2
    tar czf "$OUT" -C "$SRC" "${FILES[@]}"
fi
chmod 600 "$OUT"

# 校验：能列目录才算成功
if ! tar tzf "$OUT" >/dev/null 2>&1; then
    echo "[$(date '+%F %T')] ✗ 备份校验失败：$OUT" >&2
    exit 2
fi

# 清理旧备份（按修改时间倒序，保留前 KEEP 份）
COUNT=$(ls -1t "$DST"/xiaoyan-cloud-*.tar.gz 2>/dev/null | wc -l | tr -d ' ')
if [ "$COUNT" -gt "$KEEP" ]; then
    ls -1t "$DST"/xiaoyan-cloud-*.tar.gz | tail -n +$((KEEP + 1)) | xargs rm -f
fi

SIZE=$(du -h "$OUT" | cut -f1)
echo "[$(date '+%F %T')] ✓ $OUT ($SIZE, ${#FILES[@]} 个文件, 现有 $((COUNT > KEEP ? KEEP : COUNT)) 份)"
