# 小燕家庭云（xiaoyan-cloud）

自建的小燕（Terncy）智能家居**云服务端** + **客户端补丁工具**。
用来替代官方云，让原厂 App 在自家服务器上继续工作：远程看状态、控设备、跑场景、管家人。

> ⚠️ 先读 [`COMPLIANCE.md`](COMPLIANCE.md)：用途边界、法律红线、以及**不要**拿它做什么。

## 它能做什么

| 能力 | 说明 |
|---|---|
| 远程控制设备 | 局域网直连 + 4G 云端中转 |
| 设备状态实时回流 | MQTT 推送 |
| 场景执行 / 编辑 | 配置存在网关，云端零参与 |
| 多家庭中心 / 多账号隔离 | 每账号只看到自己名下的家庭中心 |
| 家人邀请 / 取消分享 | App 内完成，云端写归属表 |
| 数据备份 + 恢复演练 | 每日备份，脚本可验证备份是否可恢复 |

## 架构

```
   手机 App（补丁版）                       家庭网关（原厂硬件）
        │                                        │
        │  ① 局域网直连（同一 WiFi，最快）        │
        └────────────────────────────────────────┤
        │                                        │
        │  ② HTTPS + MQTT over WebSocket          │  MQTT
        └──────────► 云服务（本仓库）◄───────────┘
                    cloud4.py :9443                │
                        ▲                          │ Zigbee / 私有协议
                        │ nginx :443 (TLS)         ▼
                    你的域名                    灯 / 开关 / 窗帘 / 传感器
```

- **云服务**：`xiaoyan-cloud/cloud4.py`（单文件，Python 3.6+）
- **后台**：`admin_web.py`（SPA + JSON API）、`auth.py`（PBKDF2 账号）
- **客户端**：`repack/` 把原厂 APK 改成指向你的服务器并重签名

## 目录

| 路径 | 内容 |
|---|---|
| `xiaoyan-cloud/` | 服务端主体（cloud4 / auth / admin_web / 前端静态资源） |
| `repack/` | 客户端打包工具（改域名 + 可选门禁补丁 + 重签名） |
| `tools/` | 运维与测试脚本（备份 / 探活 / 冒烟 / 隔离回归 / 恢复演练） |
| `deploy/` | systemd 参考配置 |
| `docs/` | 账号体系、后台 API 契约、接入手册 |

## 适用对象（先说清楚门槛）

**这不是"clone 下来就能用"的项目。**

| 你需要 | 说明 |
|---|---|
| 一台公网服务器 + 自己的域名 | 服务端要能被 App 访问 |
| 一张覆盖该域名的 TLS 证书 | 否则 App 连不上 |
| 会改网关的云端地址 | 需要网关 adb（root），**绕不过** |
| 会打补丁 APK | 用 `repack/`，要 JDK + Android build-tools |
| 接受客户端冻结在原厂版本 | 签名与原厂不同，商店更新不了 |

如果你只是想要"能用"，官方云更省事；这个项目适合**想自己掌控数据**、且愿意折腾的人。

## 快速开始

### 0. 目录布局（**最容易踩坑的一步**）

`cloud4.py` 会 `sys.path.insert(0, dirname(dirname(__file__)))`，
所以 **`terncy_proto.py` 必须在服务目录的上一级**（或直接放进服务目录）：

```
/opt/xiaoyan-cloud/
    cloud4.py  auth.py  admin_web.py  admin_assets/
    tenants.json  accounts.json  tokens.json  ipuid.json  admin.json
    logs/
/opt/terncy_proto.py          ← 必须在这一级，否则 import 直接崩
```

### 1. 启动

```bash
cd /opt/xiaoyan-cloud
PLAIN=1 PORT=9443 \
TENANTS=/opt/xiaoyan-cloud/tenants.json \
TOKENS=/opt/xiaoyan-cloud/tokens.json \
IPUID=/opt/xiaoyan-cloud/ipuid.json \
ACCOUNTS=/opt/xiaoyan-cloud/accounts.json \
ADMIN_FILE=/opt/xiaoyan-cloud/admin.json \
PUBLIC_API=api.你的域名.com  PUBLIC_WS=ws.你的域名.com \
python3 cloud4.py
```

- `PLAIN=1`：不自己开 TLS，交给 nginx（推荐）
- **不设 `TENANTS` 会退回"单租户兼容模式"**，行为不是你想要的
- 首次启动会生成 `admin_initial.txt`（后台初始密码，600 权限）

### 2. 反向代理 + 证书

```bash
certbot --nginx -d api.你的域名.com -d ws.你的域名.com
```

```nginx
server {
    listen 443 ssl;
    server_name api.你的域名.com ws.你的域名.com;
    ssl_certificate     /etc/letsencrypt/live/你的域名.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/你的域名.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:9443;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

> `X-Real-IP` 那行**必须写** —— 服务端靠它识别真实客户端 IP，身份判定和 MQTT ACL 都用它。

### 3. 客户端

用 `repack/` 把**你自己合法取得的原厂 APK** 改成指向你的域名并重签名。
**域名长度必须凑满六个槽位**，否则 App 会闪退 —— 详见 [`repack/README.md`](repack/README.md)。

### 4. 接入

手机装补丁版 → 局域网登录 → 切服务器 → 邮箱注册 → 自动认领。详见 [`docs/ONBOARD.md`](docs/ONBOARD.md)。

## 依赖

| 组件 | 依赖 |
|---|---|
| 主路径（HTTP + MQTT） | Python 3.6+ **标准库**，无第三方 |
| `websockets` | 仅 `GatewayConn`（`/ws/json` 的 HA 插件路线）和 `tools/smoke_test.py` 需要 |
| `repack/` | JDK 17 + Android build-tools（见其 README） |

## 文档

| 文档 | 用途 |
|---|---|
| [`COMPLIANCE.md`](COMPLIANCE.md) | 用途边界、红线、发布检查清单 |
| [`CHANGELOG.md`](CHANGELOG.md) | 版本变更 |
| [`docs/AUTH.md`](docs/AUTH.md) | 账号体系、注册/登录/改密 |
| [`docs/ADMIN_UI.md`](docs/ADMIN_UI.md) | 后台 API 契约 |
| [`docs/ONBOARD.md`](docs/ONBOARD.md) | 接入手册 |
| [`repack/README.md`](repack/README.md) | 打包工具用法与长度约束 |

## 许可与免责

代码以 MIT 许可发布，**按"现状"提供，不承诺任何担保**。
本项目基于对官方协议的分析实现，仅供**自有设备**使用；详见 [`COMPLIANCE.md`](COMPLIANCE.md)。
