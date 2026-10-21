# ONBOARD.md —— 把朋友的网关接入你的家庭云

> 本文分两层：**上半部分「给朋友的一页纸」**（转发即可，不含技术细节）；
> **下半部分「给管理员」**（改服务器地址、排查、兜底脚本）。
> 最后更新：2026-10-21 12:00

---

## 📱 给朋友：一页纸（照做，约 5 分钟）

> 你需要的两样东西：① 我发你的安装包 `xiaoyan-app-3.0.64-patched.apk`；② 你的邮箱。

| 步骤 | 做什么 | 注意 |
|---|---|---|
| 1 | 安装我发你的 APK | 提示「未知来源」时选**允许**（这是自签名包，不是病毒） |
| 2 | 手机连上**家里的 WiFi** | 必须和你家网关同一个 WiFi，第一次认领需要"同网络"证明 |
| 3 | 打开 App，**先不要登录**，点「**局域网登录**」 | 会列出局域网内的家庭中心 |
| 4 | 选你自己的那台 → 进首页后点右上角 →「**家庭中心设置**」→「**切换服务器**」→ 选「**中国**」→ 确定 | 等 10~20 秒，网关会自动连过来 |
| 5 | 退出登录 → 用**邮箱**注册（**手机号注册会被拒**）→ 登录 | 密码自己设，8 位以上 |
| 6 | 登录后应该能看到你的家庭中心 | 看不到 → 把 App 从后台彻底划掉，重开一次 |

**常见误会**

- **手机号注册为什么不行？** 这台服务器只支持邮箱，手机号/验证码/微信登录都会被拒。这是有意的，不是 bug。
- **为什么一定要在家里的 WiFi？** 第一次认领时，服务器要确认"注册的人"和"网关"在同一个网络里，否则谁都能把你家网关绑走。
- **以后在外网能用吗？** 能。认领完成后，4G/公司网都能控制，只是会走云端中转（比局域网慢 200~400ms）。
- **App 能升级吗？** 不能。这个包是签名过的补丁版，应用商店覆盖不了 —— 好处是不会被官方版本冲掉，坏处是版本停在 3.0.64。

---

## 一句话原理（给管理员）

小燕网关连哪个服务器，只由网关本机一个文件决定：

```
/data/xlive/net/mqtt_cloud_daemon.json
```

把里面的 `server` / `ws_server` 改成你的域名，重启一下进程，网关就永久改用你的家庭云了。
**改一次，永久生效**，之后网关开机自动连，不需要再操作。

---

## 方式一：App 内自助切换（✅ 推荐，不需要电脑）

**2026-10-19 实测通过。朋友只需要一台手机。**

前提只有一个：手机上装的是**补丁版 App**（`out/xiaoyan-gate-ok.apk`），
并且手机和网关在**同一个 WiFi**。

| 步骤 | 操作 |
|---|---|
| 1 | 打开小燕 App，停在首屏（**不要登录**） |
| 2 | 点「**局域网登录**」 |
| 3 | 弹出「当前局域网内发现 N 个家庭中心，点击可直接登录」→ 点**自己的那台** |
| 4 | 进入家庭首页后，点右上角进入「**家庭中心设置**」 |
| 5 | 找到「**切换服务器**」→ 选「**中国**」→ 确定 |
| 6 | 等 10~20 秒，网关自动连上假云端 |

**怎么确认成功**：网关上的 `server` 会从 `api.xiaoyan.io` 变成 `apis.example.com`；
服务器日志出现 `网关上线 hc=box-...`。

实测数据（备用网关 11-29）：

```
切换前: server=api.xiaoyan.io  ws_server=ws.xiaoyan.io  server_mode=auto
切换后: server=apis.example.com  ws_server=api.example.com  server_mode=manual
耗时:   约 15 秒（16:31:30 点击 → 16:31:47 网关上线）
```

> ⚠️ 注意两点：
> 1. 「切换服务器」只有 **中国 / 澳大利亚 / 新加坡** 三个选项，选**中国**。
> 2. 局域网登录会顶掉当前的云端登录态，之后要用账号登录才能回到"云端模式"。
> 3. 这一步只解决"网关连谁"，**账号还看不到这台网关** —— 还需要在
>    `tenants.json` 里加一行（见下面「多租户已就绪」一节），或者等自动认领功能。

---

## 方式二：脚本接入（需要电脑 + adb，作为兜底）

## 前提

| 项 | 要求 |
|---|---|
| 网络 | 操作的电脑和网关在**同一个局域网** |
| 工具 | 装了 `adb`（macOS: `brew install android-platform-tools`） |
| 网关 | adb 5555 是开着的。小燕固件**默认开启**（售后调试用），密码是固件统一的 `<网关root密码>` |
| 域名 | 你的服务器域名（本项目是 `api.example.com`），已在公网可解析 |

---

## 一键接入

```bash
# 1. 拿到脚本
scp root@<你的服务器>:/opt/xiaoyan-cloud/join_cloud.sh .    # 或直接从项目 tools/ 拷

# 2. 跑（默认 api.example.com）
./join_cloud.sh

# 自定义域名
./join_cloud.sh my.domain.com

# 网关密码不是默认值
GW_PASS='别的密码' ./join_cloud.sh
```

脚本会：
1. 扫本机 `/24` 网段找开着 5555 的设备
2. 识别 `ro.product.model` 是不是 `TerncyGW01`（不是就跳过）
3. 读出网关自己的 `username`（hc uuid）和 `password`，**原样保留**
4. 只改 `server` / `ws_server` / `port` / `tls_enabled` / `server_mode` 五个字段
5. 备份成 `mqtt_cloud_daemon.json.bak.<时间戳>`
6. `setprop ctl.restart mqttcloud` 重启云端进程

> 已实测：改完 5 秒内网关就会重连，日志出现 `网关上线 hc=box-...`。

输出示例：

```
发现候选设备:
  192.168.1.10
  192.168.1.10
───── 192.168.1.10:5555 ─────
  ✓ 小燕网关 model=TerncyGW01
  家庭中心: box-aa-bb-cc-dd-ee-ff
  当前云端: apis.example.com
  ✓ 配置已写入（备份 /data/xlive/net/mqtt_cloud_daemon.json.bak.1792382401）
  ✓ 云端进程已重启（init.svc.mqttcloud=running）
```

---

## 手工接入（脚本跑不动时）

```bash
PASS='<网关root密码>'
GW=192.168.1.50          # 换成网关 IP

# 1. 连上（网关的 adb shell 会要密码，必须用管道喂）
printf '%s\n' "$PASS" | adb connect $GW:5555
printf '%s\n' "$PASS" | adb -s $GW:5555 shell 'cat /data/xlive/net/mqtt_cloud_daemon.json'

# 2. 先备份！
printf '%s\n' "$PASS" | adb -s $GW:5555 shell \
  'cp /data/xlive/net/mqtt_cloud_daemon.json /data/xlive/net/mqtt_cloud_daemon.json.bak'

# 3. 改四个字段（username / password 千万别动，那是网关身份）
printf '%s\n' "$PASS" | adb -s $GW:5555 shell '
F=/data/xlive/net/mqtt_cloud_daemon.json
sed -i "\"server\" : \"[^\"]*\"|\"server\" : \"api.example.com\"|" \$F
'

# 4. 更稳妥：整份重写（推荐，避免 sed 匹配到 ws_server 的歧义）
#    见 tools/join_cloud.sh 里的 NEWJSON 段，照抄即可

# 5. 重启云端进程
printf '%s\n' "$PASS" | adb -s $GW:5555 shell 'setprop ctl.restart mqttcloud'
```

---

## 怎么确认成功

在**服务器**上看：

```bash
ssh root@<你的服务器>
grep 网关上线 /opt/xiaoyan-cloud/logs/cloud4.log | tail
# 期望看到：网关上线 hc=box-xx-xx-xx-xx-xx-xx
```

在**网关**上看（可选）：

```bash
printf '<网关root密码>\n' | adb -s <网关IP>:5555 shell 'getprop init.svc.mqttcloud'
# 期望：running
```

---

## 出问题怎么办

| 现象 | 原因 / 处理 |
|---|---|
| 脚本说"没有发现设备" | 电脑不在同一 WiFi；或网关 5555 没开；可手工指定 `GW_IPS=...` |
| adb 连上了但 shell 没输出 | 忘了喂密码，必须 `printf '密码\n' \| adb ... shell ...` |
| 写完网关一直不重连 | `getprop init.svc.mqttcloud` 不是 running → `setprop ctl.start mqttcloud` |
| 想回滚 | `cp /data/xlive/net/mqtt_cloud_daemon.json.bak.<时间戳> .../mqtt_cloud_daemon.json` 再重启 |
| 网关离线但局域网还能用 | 正常：局域网 `wsserver` 和云端 `mqttagent_cloud` 是**两个独立进程**，云端挂了不影响局域网控制 |

---

## ✅ 多租户：自动认领已上线，通常不需要手工配置

**2026-10-19 16:47 起**，朋友切完服务器后**不需要你做任何事**：

> 他注册登录时，只要人还在那个 WiFi 下，云端会发现「有一台已连上但没人认领的网关，
> 且它连过来的公网 IP 和你手机一样」→ 自动绑给他，并写回 `tenants.json`。

日志长这样：

```
[tenant] ★ 自动认领：uid=guest@example.com <- box-aa-bb-cc-dd-ee-ff（公网 IP 198.51.100.20 一致）
[tenant] 归属表已落盘 /opt/xiaoyan-cloud/tenants.json（3 个用户）
```

**什么时候需要手工配置**（下面这一节）：

- 朋友是用 **4G / 在外面**注册的（公网 IP 对不上，认领不触发）
- 同一时刻有**多台**未认领网关（系统会放弃认领以免绑错，日志里有 `自动认领放弃`）
- 你想**提前**把某台网关指定给某人

---

## 手工配置归属表（备用）

改完网关地址只是让**网关**连上了服务器。要让朋友的 App 显示**他自己的家**，
正常情况下自动认领会处理；如果要手工指定，就在服务器的归属表里加一行：

```bash
ssh root@<你的服务器>
vi /opt/xiaoyan-cloud/tenants.json
```

```json
{
  "13800000000": ["box-aa-bb-cc-dd-ee-ff"],
  "朋友的手机号": ["朋友的网关 hc uuid"]
}
```

改完重启一次：

```bash
systemctl restart xiaoyan-cloud
grep tenant /opt/xiaoyan-cloud/logs/cloud4.log | tail -1
# 期望：严格模式 2 个用户: 13800000000->box-..., 138...->box-...
```

### 怎么拿到"朋友的网关 hc uuid"

网关一连上服务器，日志里就有：

```bash
grep 网关上线 /opt/xiaoyan-cloud/logs/cloud4.log | tail
# 网关上线 hc=box-aa-bb-cc-dd-ee-ff
```

也可以从 `join_cloud.sh` 的输出里直接读（它会打印「家庭中心: box-…」）。

### 怎么拿到"朋友的手机号（uid）"

让他先用补丁版 App 登录一次，然后：

```bash
grep -E "users 200 uid=|SUBSCRIBE \['message/" /opt/xiaoyan-cloud/logs/cloud4.log | tail
```

### 配好之后的效果（已实测）

| 场景 | 结果 |
|---|---|
| 朋友登录 | 只看到自己的家，看不到你的 |
| 朋友点灯 | 只发到他自己家的网关 |
| 朋友越权（改包直接发到你的 hc） | 服务端静默丢弃，日志 `[tenant] 拒绝越权 RPC` |
| 陌生人登录 | roster 为空，一个家都没有 |

> ⚠️ 只配了 1 个账号时，系统保留「单租户兜底」（身份识别失败时仍显示默认那台网关）。
> **加上第 2 个账号后兜底自动关闭**，这是刻意的设计：自用不锁死，分享即收紧。

> ⚠️ `15-ab` 这种 `box-vg-…` 的虚拟组 master **不要**写进 `tenants.json`，否则 App 里会多出一个"家"。

---

---

## 常见问题

### Q0：朋友注册后看不到任何家庭中心

按顺序查（每条都有明确判据）：

| 可能原因 | 怎么确认 | 怎么办 |
|---|---|---|
| **不在同一网络** | 朋友注册时的公网 IP 与网关连上来的 IP 不同 → 自动认领不触发 | 让他**回家、连家里 WiFi** 再登录一次；或手工在 `tenants.json` 里登记 |
| **网关还没连过来** | 服务器日志没有 `网关上线 hc=box-...` | 先解决"网关连不上"，见 Q2 |
| **网关已被别人认领** | 日志有 `拒绝 association：hc=... 已属于 uid=...` | 改 `tenants.json` 手工指派，或让原主人解绑 |
| **App 缓存没刷新** | 日志里 `roster 200` 但列表为空 | 把 App 从后台彻底划掉再打开（家人页/首页都吃启动缓存） |

自查命令（在服务器上）：

```bash
grep -a "网关上线\|自动认领\|拒绝 association" /opt/xiaoyan-cloud/logs/run.out | tail -20
python3 -c "import json;d=json.load(open('/opt/xiaoyan-cloud/tenants.json'));print({k:v for k,v in d.items() if not k.startswith('_')})"
```

### Q0.5：想给访客「只能看、不能控」

在 `tenants.json` 里按成员指定权限位：

```json
"_member_perm": { "guest@example.com": 8 }
```

位含义：`2=编辑`、`4=控制`、`8=只看`，默认 `14`（全权）。
App 的控制门禁白名单是 `{4,6,12,14}`、编辑门禁是 `{2,6,10,14}`，
所以 **8 两个都过不去 = 只读**。

> ⚠️ 这是 2026-10-21 新加的能力，**只做了接口层验证**（`tenant_isolation_test.py` 里断言
> A=14 / B=8 通过），**还没在真机上确认 App 是否真的会禁用控制按钮**。改之前先拿一个测试账号试。

### Q1：登录后出现「请求加入」/「请求函」点不掉

**根因**：网关 `lanaccess.db` 的 `permission` 表为空 → App 认为账号未授权 → 显示请求函。

**解决**（在局域网内执行一次即可）：

```bash
# 1. 修复三台网关的 permission 表（为 user 表里每个已关联账号写入 VIEW+CONTROL+EDIT 权限）
./tools/fix_gateway_permissions.sh

# 2. 重启 App，请求函应消失
```

> 原理：假云端实现了 `POST /devices/<hc>/association` 接口，同意操作会更新 `tenants.json`，
> 但网关本地的 `permission` 表需要由局域网内的 adb 直接写入（假云端在公网服务器，无法直接连网关 5555）。
> 新用户自动认领后，管理员需要为他执行一次此脚本。

### Q2：局域网登录模式为什么只能看到一个网关 / 没有「添加家庭中心」入口

**不是 bug，是正常行为**：

- 局域网登录弹窗里的「添加」是**下拉列表的末项**，只有列表里已有 ≥2 个家时才会渲染。
- 补丁版 App 是新装的，本地 HC 列表为空，第一次局域网登录后只有 1 个家 → 列表退化成单条 → 看不到「添加」行。
- **原版 App 能显示多个**，是因为用了很久，本地累积了历史 HC（云端时代残留的）。
- **云端账号登录**后，roster 会返回你名下的全部家庭中心（3 个），App 本地会持久化这些 HC。
  之后即使退出登录，本地仍有这 3 个 HC 的缓存，再进局域网模式就能看到多个 + 添加入口。
- 实测：**云端登录本身就自动走局域网直连**（`use default session LOCAL`），速度和局域网登录一样快。
  平时直接用云端账号登录即可，不需要特意切局域网模式。

**结论**：局域网登录的唯一用途是「帮朋友切服务器」（方式一步骤 1~4）。
日常控制用自己的云端账号登录，会自动局域网直连，速度一样，且能看到完整的多网关列表。

### Q3：能用邮箱 + 密码登录吗

**可以。** App 输入邮箱后会**自动切换成密码模式**（多出密码输入框），确定按钮正常可用。

假云端不校验密码，任意密码都能登录（uid 直接取自输入框，credential 原样记录但不验证）。
所以邮箱 + 任意密码即可注册/登录，不需要验证码。

---

## 配套：App 怎么给朋友

1. 发 **`out/xiaoyan-text.apk`**（90MB）。
   ★ 2026-10-21 核对：手机上实际安装的包 md5 = `b8b3488a40b17da2fec92d61969fbbef`，
   与 `out/xiaoyan-text.apk` **完全一致**；`out/xiaoyan-gate-ok.apk` 是更早的构建（md5 `3ec2bd1c…`），
   别发错。原厂包 `xiaoyan_app_v3.0.64.apk` 是唯一的签名回滚源，**不要发人、不要删**。
2. 朋友必须先**卸载原版小燕 App**（签名不同，两个装不上）。
3. 装好后用**邮箱 + 自设密码**注册/登录。

> ⚠️ **已过期的旧说明（2026-10-21 作废）**：以前这里写着「假云端不校验密码，任意密码都能登录」
> 以及「手机号 + 任意验证码也能登录」—— **现在都不成立**：
> 密码是 PBKDF2 真校验（`auth.py`），手机号/验证码/微信/Google 登录一律返回 `40100`。
> 谁按旧说明操作都会登不进去。

注意：补丁版 App 的 `libapp.so` 里 `api/ws` 域名是**编译时写死的**，
如果你以后换域名，App 和网关两边都要重新弄。
