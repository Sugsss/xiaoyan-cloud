# repack —— 小燕 App 补丁打包工具包

把**你自己合法取得的原厂 APK**，改成指向**你自己的服务器**（可选：去掉控制权限门禁），
再重新签名，得到一个能装到手机上的包。

> ⚠️ **法律边界**：APK 是第三方的版权软件。本工具只做"改自己手里的 APK"，
> **不提供、也不建议分发改好的 APK**。要给别人用，把工具给对方，让他自己打。
> 服务端（本项目自己写的代码）开源没问题。

---

## 一、前置条件

| 依赖 | 说明 |
|---|---|
| **JDK 17**（含 `javac`） | 签名工具需要 |
| **Android build-tools** | 需要其中的 `zipalign`、`apksigner`。设 `BUILD_TOOLS=/path/to/build-tools/36.0.0` |
| **apksig.jar** | Google 的签名库。从 Maven 取：`com.android.tools.build:apksig`（放 `tools/apksig.jar`） |
| **原厂 APK** | 你自己合法取得，放 `xiaoyan_app_v3.0.64.apk`（或设 `ORIG_APK=`） |
| **签名密钥** | 首次会自动生成；**必须备份**，换密钥 = 所有已装用户要卸载重装 |

---

## 二、用法

```bash
BUILD_TOOLS=/path/to/build-tools/36.0.0 \
JAVA_HOME=/path/to/jdk-17 \
APKSIG_JAR=/path/to/apksig.jar \
KS_PASS='你的密钥口令' \
API_SG=apis.sg.example.cn API_TW=apis.tw.example.cn \
WS_SG=api.sg.example.cn  WS_TW=api.tw.example.cn  \
./build_apk.sh apis.example.cn api.example.cn my-app.apk
```

参数说明：

| 位置 | 含义 |
|---|---|
| `$1` | API 主机（HTTP 接口用） |
| `$2` | WS 主机（MQTT over WebSocket 用） |
| `$3` | 输出文件名（落到 `out/`） |

可选环境变量：`GATE_PATCH=0` 关掉门禁补丁、`TEXT_PATCH=0` 关掉文案补丁、
`PATCH_OUT=` 中间目录、`KS=`/`KS_ALIAS=` 换密钥。

---

## 三、**最重要的一条：六个槽位必须等长**

`libapp.so` 里是 Dart AOT 快照，主机名以"带长度前缀的字符串"存在。**只要新串比原串短，
就要改动长度字段和后续偏移 —— 极易把快照改坏**（实测：改短 4 个字符 → 装上去直接 SIGSEGV 闪退，
连登录页都进不去）。

原厂六个槽位的**准确长度**：

| 槽位 | 原串 | 长度 | 含义 |
|---|---|---|---|
| api | `api.terncy.com` | **14** | 主 API |
| ws | `ws.terncy.com` | **13** | MQTT WebSocket |
| api.sg | `api.sg.terncy.com` | **17** | 新加坡 API |
| api.tw | `api.tw.terncy.com` | **17** | 台湾 API |
| ws.sg | `ws.sg.terncy.com` | **16** | 新加坡 WS |
| ws.tw | `ws.tw.terncy.com` | **16** | 台湾 WS |

**你的域名必须凑出这六个长度。** 拼不出来怎么办：
- 短的槽位用更长的前缀补（`api.` → `apis.`，正好多 1 个字符）
- 还是不够就加子域（`api.sg.` / `api.tw.` 天然是 17/16）
- 实在不行就别改 sg/tw —— 那两栏只在 App 里切"区域"时才用，填成和主站一样即可（但**必须等长**）

### 已验证可用的配方（本机实测，2026-10-21）

```
api    = apis.example.com      (14 = 14)
ws     = api.example.com       (13 = 13)
api.sg = apis.sg.example.com   (17 = 17)
api.tw = apis.tw.example.com   (17 = 17)
ws.sg  = api.sg.example.com    (16 = 16)
ws.tw  = api.tw.example.com    (16 = 16)
```

产物装到真机上：启动正常、登录态保留、设备列表正常、控制正常。
（`out/xiaoyan-final.apk`，md5 `83f1cc04cffb125468be956a876ed20c`）

---

## 四、`GATE_PATCH` 是什么，要不要开

`HomeCenter::hasControlPermission` 决定"点了设备能不能控"：

```
LOCAL 会话 → true
否则      → 要求 roster 的 Permission ∈ {4,6,12,14}
```

`GATE_PATCH=1`（默认）会把"非 LOCAL 才去比对白名单"那条条件跳转 **NOP 掉**，
函数变成恒 `true`。

| | 开（1） | 关（0） |
|---|---|---|
| 控制 | 一定可用 | 依赖云端返回正确 Permission（本服务返回 14，正常） |
| 只读访客 | ❌ **不可能**（权限位彻底失效） | ✅ 可以（访客给 8） |

> 早期云端返回 `Permission: 0` 导致"看得见控不动"，所以当时必须开。
> 现在云端已正确返回 14，**如果不需要只读访客，开不开都行；需要只读就必须关**。
> ⚠️ 关掉之前请先在真机（4G 环境）验证控制仍可用。

---

## 五、签名与升级

- 签名方案：v1 + v2 + v3（`SignTool.java` 调 apksig）
- **同一个 keystore 重签 → 可以覆盖升级**（`adb install -r`，数据不丢）
- 换 keystore → 必须卸载重装
- 签名与原厂不同 → 应用商店永远无法更新（好处是不会被官方版本冲掉）

---

## 六、故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 装完点开就闪退（SIGSEGV） | 快照被改坏，通常是**槽位长度不匹配** | 看构建输出有没有 `缩短手术`；有就换等长域名重打 |
| 卡在"正在获取数据" | WS 主机不可达（DNS/证书） | `dig` 两个主机都要能解析；证书 SAN 要包含它们 |
| 装不上，提示签名冲突 | 与原版签名不同 | `adb uninstall com.xiaoyan.ui` 后重装 |
| 控制点了没反应 | `GATE_PATCH=0` 且云端 Permission 不在白名单 | 改回 `GATE_PATCH=1`，或让云端返回 14 |
