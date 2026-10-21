#!/bin/bash
# build_apk.sh —— 小燕 App 补丁一键流水线（可移植版，供他人自部署使用）
# ============================================================================
# 作用：把**你自己合法取得的原厂 APK**，改成指向**你自己的服务器**、并可选地
#       去掉控制权限门禁，然后重新签名，得到能装到手机上的包。
#
# 用法：
#   ./build_apk.sh <api_host> <ws_host> [输出APK名]
#
# 环境变量（都有默认值，按需覆盖）：
#   PROJ            项目根目录（默认：本脚本的上一级目录）
#   ORIG_APK        原厂 APK 路径（默认：$PROJ/xiaoyan_app_v3.0.64.apk）
#   KS / KS_PASS / KS_ALIAS   签名密钥（默认 $PROJ/tools/xiaoyan.keystore / 无 / xiaoyan）
#   BUILD_TOOLS     Android build-tools 目录（需含 zipalign、apksigner）
#   APKSIG_JAR      apksig.jar 路径
#   JAVA_HOME       JDK 17（含 javac）
#   GATE_PATCH      1=打穿控制权限门禁（默认），0=保留原厂权限判定
#   TEXT_PATCH      1=把「手机号/邮箱」旧文案改成「只支持邮箱」（默认）
#   PATCH_OUT       中间产物目录（默认 $PROJ/out/patched）
#
# 槽位长度上限（超了会失败，这是二进制的硬约束）：
#   api<=14  ws<=13  api.sg/api.tw<=17  ws.sg/ws.tw<=16
#
# ⚠️ 签名密钥必须自己保管。换密钥 = 所有已装用户必须卸载重装。
# ⚠️ 本项目只提供"改自己合法取得的 APK"的工具，不提供、也不建议分发改好的 APK。
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="${PROJ:-$(cd "$HERE/.." && pwd)}"

API_HOST="${1:?用法: ./build_apk.sh <api_host> <ws_host> [输出名]}"
WS_HOST="${2:?用法: ./build_apk.sh <api_host> <ws_host> [输出名]}"
OUT_NAME="${3:-xiaoyan-patched.apk}"
API_SG="${API_SG:-$API_HOST}"
API_TW="${API_TW:-$API_HOST}"
WS_SG="${WS_SG:-$WS_HOST}"
WS_TW="${WS_TW:-$WS_HOST}"

ORIG_APK="${ORIG_APK:-$PROJ/xiaoyan_app_v3.0.64.apk}"
KS="${KS:-$PROJ/tools/xiaoyan.keystore}"
KS_PASS="${KS_PASS:-}"
KS_ALIAS="${KS_ALIAS:-xiaoyan}"
APKSIG_JAR="${APKSIG_JAR:-$PROJ/tools/apksig.jar}"
PATCHED_DIR="${PATCH_OUT:-$PROJ/out/patched}"
WORK="$PROJ/out/.rebuild"
OUT_APK="$PROJ/out/$OUT_NAME"

PY="${PY:-python3}"
JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@17}"
if [ -x "$JAVA_HOME/bin/java" ]; then
    JAVA="$JAVA_HOME/bin/java"; JAVAC="$JAVA_HOME/bin/javac"
else
    JAVA="$(command -v java || true)"; JAVAC="$(command -v javac || true)"
fi

# build-tools：优先 $BUILD_TOOLS，其次 PATH
if [ -n "${BUILD_TOOLS:-}" ]; then
    ZIPALIGN="$BUILD_TOOLS/zipalign"; APKSIGNER="$BUILD_TOOLS/apksigner"
else
    ZIPALIGN="$(command -v zipalign || true)"; APKSIGNER="$(command -v apksigner || true)"
fi

die() { echo "✗ $*" >&2; exit 1; }

[ -f "$ORIG_APK" ]  || die "找不到原厂 APK：$ORIG_APK（请自己合法取得后放到该路径，或设 ORIG_APK=）"
[ -x "${ZIPALIGN:-}" ]  || die "找不到 zipalign（设 BUILD_TOOLS=.../build-tools/<ver>）"
[ -x "${APKSIGNER:-}" ] || die "找不到 apksigner（同上）"
[ -n "${JAVA:-}" ]  || die "找不到 java（设 JAVA_HOME）"
[ -n "${JAVAC:-}" ] || die "找不到 javac（需要 JDK 而不是 JRE）"
[ -f "$APKSIG_JAR" ] || die "找不到 apksig.jar（见 README 的获取方式）"

echo "==> 0/5 环境检查"
echo "    原厂 APK : $ORIG_APK ($(du -h "$ORIG_APK" | cut -f1))"
echo "    输出     : $OUT_APK"
echo "    主机     : api=$API_HOST ws=$WS_HOST api.sg=$API_SG api.tw=$API_TW ws.sg=$WS_SG ws.tw=$WS_TW"
echo "    门禁补丁 : ${GATE_PATCH:-1}    文案补丁: ${TEXT_PATCH:-1}"

echo "==> 1/5 打主机名补丁"
# 补丁工具需要"解包后的原厂 lib"。第一次跑自动解，省得用户手动 unzip。
EXTRACTED="${APK_EXTRACTED:-$PROJ/apk-extracted}"
if [ ! -f "$EXTRACTED/lib/arm64-v8a/libapp.so" ]; then
    echo "    首次运行：自动解包 $ORIG_APK → $EXTRACTED"
    mkdir -p "$EXTRACTED"
    unzip -o -q "$ORIG_APK" 'lib/*' -d "$EXTRACTED" || die "解包失败"
fi
export APK_EXTRACTED="$EXTRACTED"

"$PY" "$HERE/patch_hosts.py" \
  "$API_HOST" "$WS_HOST" --out "$PATCHED_DIR" \
  --api-sg "$API_SG" --api-tw "$API_TW" --ws-sg "$WS_SG" --ws-tw "$WS_TW"

if [ "${GATE_PATCH:-1}" = "1" ]; then
  echo "==> 1.5/5 打穿控制权限门禁（GATE_PATCH=1）"
  echo "    注意：打完之后 Permission 位彻底失效，**无法做只读访客**。"
  "$PY" "$HERE/patch_gate.py" "$PATCHED_DIR"
else
  echo "==> 1.5/5 跳过门禁补丁（GATE_PATCH=0）—— 保留原厂权限判定，可做只读访客"
fi

if [ "${TEXT_PATCH:-1}" = "1" ]; then
  echo "==> 1.6/5 文案对齐（只支持邮箱）"
  "$PY" "$HERE/patch_text.py" "$PATCHED_DIR"
fi

echo "==> 2/5 替换 libapp.so 并重打包"
rm -rf "$WORK"; mkdir -p "$WORK"
cp "$ORIG_APK" "$WORK/unsigned.apk"
zip -q -d "$WORK/unsigned.apk" "META-INF/CERT.SF" "META-INF/MANIFEST.MF" "META-INF/CERT.RSA" 2>/dev/null || true
( cd "$PATCHED_DIR" && zip -q "$WORK/unsigned.apk" lib/arm64-v8a/libapp.so lib/armeabi-v7a/libapp.so )

echo "==> 3/5 zipalign（.so 按 4096 页对齐）"
"$ZIPALIGN" -p -f 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"

echo "==> 4/5 签名 v1+v2+v3"
if [ ! -f "$KS" ]; then
  [ -n "$KS_PASS" ] || die "密钥不存在且没给 KS_PASS，无法生成：$KS"
  mkdir -p "$(dirname "$KS")"
  "$JAVAC" -version >/dev/null 2>&1
  "$JAVA_HOME/bin/keytool" -genkeypair -keystore "$KS" -storetype PKCS12 \
    -alias "$KS_ALIAS" -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$KS_PASS" -keypass "$KS_PASS" \
    -dname "CN=Xiaoyan Patch, O=Xiaoyan, C=CN" >/dev/null
  echo "    已生成新密钥：$KS（**务必备份**，丢了没法给已装用户升级）"
fi
mkdir -p "$WORK/classes"
"$JAVAC" -cp "$APKSIG_JAR" -d "$WORK/classes" "$HERE/SignTool.java"
"$JAVA" \
  --add-exports java.base/sun.security.x509=ALL-UNNAMED \
  --add-exports java.base/sun.security.util=ALL-UNNAMED \
  --add-exports java.base/sun.security.pkcs=ALL-UNNAMED \
  --add-exports java.base/sun.security.provider=ALL-UNNAMED \
  -cp "$APKSIG_JAR:$WORK/classes" SignTool \
  "$WORK/aligned.apk" "$OUT_APK" "$KS" "$KS_PASS" "$KS_ALIAS"

echo "==> 5/5 校验"
"$APKSIGNER" verify --print-certs "$OUT_APK" 2>&1 | grep -E "Signer #1 certificate DN" || true
"$PY" - "$OUT_APK" "$API_HOST" "$WS_HOST" "$API_SG" "$API_TW" "$WS_SG" "$WS_TW" <<'EOF'
import sys, zipfile
p = sys.argv[1]
hosts = sys.argv[2:8]
z = zipfile.ZipFile(p)
for abi in ("arm64-v8a", "armeabi-v7a"):
    try:
        data = z.read('lib/%s/libapp.so' % abi)
    except KeyError:
        print("  (跳过 %s，包里没有)" % abi); continue
    for gone in (b'api.terncy.com', b'ws.terncy.com'):
        assert gone not in data, "%s 旧主机 %s 未清除干净" % (abi, gone)
    for h in hosts:
        assert h.encode() in data, "%s 新主机 %s 未写入" % (abi, h)
print("  ✓ 主机替换校验通过:", " | ".join(hosts))
EOF
ls -lh "$OUT_APK"
echo ""
echo "完成：$OUT_APK"
echo "安装：adb install -r $OUT_APK"
echo "      （签名与原版不同 → 首次必须卸载原版；用同一个 keystore 重签则可覆盖升级）"
