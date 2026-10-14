---
title: QQ 流量分析实验：Wireshark 抓包还原
date: 2026-10-14 19:00:00
tags:
  - 计算机网络
  - Wireshark
  - QQ
  - 流量分析
---
# QQ 流量分析实验：Wireshark 抓包还原

> 实验内容：使用 Wireshark 捕获 QQ 流量，分析其传输层协议（TCP / UDP）、数据加密状态，并尝试从明文中恢复图片文件。
>
> 抓包文件：`qq_pc2pc_20261014.pcapng`，共 **359,354 个数据包**，约 **286 MB**。
>
> 说明：本文所有截图中的 QQ 号、IP 地址、昵称、聊天内容均已打码处理。

---

## 一、实验环境

| 项目 | 配置 |
|---|---|
| 抓包主机 | Windows 11 |
| 抓包工具 | Wireshark 4.x（Npcap） |
| QQ 版本 | QQ PC 版最新版 |
| 本机 IP | `192.168.x.x`（内网，已打码） |
| 抓包时长 | 约 250 秒 |
| 操作 | 登录 QQ、浏览联系人列表、收发消息、接收图片 |

---

## 二、整体流量概览

抓完包后先看协议分层统计（`统计 → 协议分级`）：

```text
frame     359,354 帧
└── ip    359,336 帧
    ├── tcp   358,187 帧   ← 绝对主导
    │   ├── tls   34,983 帧  ← 加密的 HTTPS
    │   └── http     71 帧   ← 明文 HTTP（关键！）
    │       └── image-jfif 15 帧  ← 明文 JPG 图片
    └── udp     1,149 帧
        ├── dns     352 帧
        ├── quic    427 帧
        └── gquic   333 帧
```

![协议分级统计](images/01-io-phs.png)

**初步结论**：
- QQ 流量 **99% 以上走 TCP**，UDP 几乎只有 DNS 和 QUIC（HTTP/3），**老版本的 UDP 8000 心跳已经不存在了**。
- TCP 流量里绝大部分是 TLS 加密，但存在一小部分 **明文 HTTP**，而且里面藏着 **15 个 JPG 图片**。

---

## 三、如何在一堆包里识别出 QQ 流量

### 方法 1：按 QQ 号搜（最直接）

新版 QQ 虽然聊天内容加密，但**部分信令仍然走明文 HTTP**。在过滤栏输入：

```
http
```

然后展开任意一个 HTTP 请求，能直接在 URL 里看到自己的 QQ 号：

```
GET /httpconn?htcmd=0x6ff0082&uin=******** HTTP/1.1
Host:     szshort.qq.com
```

> `uin` 就是 QQ 号（本次抓包中明文出现）。这说明 QQ 早期登录/信令阶段还有一部分 HTTP 明文请求。

![HTTP 明文请求中出现 uin](images/02-http-uin.png)

### 方法 2：按服务器 IP 过滤

QQ 主服务器 IP 段（本次抓包实际观察到，已部分打码）：

| IP | 用途 |
|---|---|
| `39.136.x.x` | QQ 主连接服务器（约 277 MB，占总流量 97%） |
| `120.233.x.x` | `qh.qlogo.cn` 头像 CDN |
| 其他 `39.x`、`117.x`、`120.x` 段 | 其他信令服务器 |

过滤栏输入：
```
ip.addr == 39.136.x.x
```

### 方法 3：按域名过滤

```
http.host == "qh.qlogo.cn"
```

---

## 四、问题 1：UDP 还是 TCP？

### 4.1 实际数据

| 传输层 | 包数 | 占比 | 主要内容 |
|---|---|---|---|
| **TCP** | 358,187 | 99.7% | TLS 加密聊天、HTTP 头像下载、信令 |
| **UDP** | 1,149 | 0.3% | DNS 查询、QUIC/gQUIC（HTTP/3） |

### 4.2 观察到的 TCP 连接

- **主连接**：`192.168.x.x:10039 ↔ 39.136.x.x:443`，34 万帧，全是 `SSLv2 / Encrypted Data`。
- **头像下载**：`192.168.x.x:随机端口 ↔ 120.233.x.x:80`，明文 HTTP，返回 `image/jpeg`。
- **信令请求**：`192.168.x.x ↔ 各种 QQ 服务器:80`，明文 HTTP GET。

![TCP 443 加密主连接](images/03-tcp-443.png)

### 4.3 观察到的 UDP

- **没有 UDP 8000（irdmi）流量**——老教材里"QQ 用 UDP 8000"的说法在新版 QQ 上已经不成立。
- UDP 主要是 DNS（53 端口）和 QUIC（443 端口的 HTTP/3）。

### 结论

> **新版 QQ 已经基本全部使用 TCP**（主要是 443 端口的 TLS，以及少量 80 端口的明文 HTTP 信令）。UDP 只用于 DNS 解析和 QUIC 传输，不再承担聊天心跳。

---

## 五、问题 2：加密还是明文？

### 5.1 加密的部分（绝大多数）

主连接 `39.136.x.x:443` 上的所有数据：

- 展开包 → 能看到 `Transport Layer Security` / `TLSv1.2 Record Layer`
- Payload 全是随机十六进制，没有任何可读字符串
- 包含文字消息、登录 token、好友列表同步等

![加密的 TLS Payload](images/04-tls-payload.png)

### 5.2 明文的部分（关键发现）

通过 HTTP 80 端口可以看到三类明文数据：

#### ① QQ 号明文出现在 URL 里

```
GET /httpconn?htcmd=0x6ff0082&uin=******** HTTP/1.1
```

#### ② 头像图片明文下载

```
GET /g?b=qq&ek=...&s=100 HTTP/1.1
Host: qh.qlogo.cn

HTTP/1.1 200 OK
Content-Type: image/jpeg
```

返回的 body 直接就是 JPG 文件内容，开头是 `FF D8 FF E0 ...`。

#### ③ 其他 HTTP 信令

URL 里的 `htcmd` 字段是命令字（如 `0x6ff0082`、`0x6ff0087`），可以理解为 QQ 自定义的 HTTP API。

![明文 HTTP 请求](images/05-http-plaintext.png)

### 5.3 加密状态总表

| 业务 | 端口 | 加密状态 | 能否看到内容 |
|---|---|---|---|
| 聊天消息 / 登录认证 | TCP 443 | **TLS 加密** | 否 |
| 好友列表 / 状态同步 | TCP 443 | **TLS 加密** | 否 |
| QQ 早期信令 | TCP 80 | **明文 HTTP** | 能看到 QQ 号、命令字 |
| 头像图片下载 | TCP 80 | **明文 HTTP** | 能直接还原 JPG |
| DNS 解析 | UDP 53 | 明文 | 能看到域名 |

### 结论

> **新版 QQ 的核心通信（聊天、登录）已经全部 TLS 加密**；但仍有一部分辅助功能（早期信令、头像 CDN）走 **明文 HTTP 80**，这是本次实验能从流量中还原出文件的入口。

---

## 六、问题 3：从明文流量中恢复图片文件

### 6.1 原理：文件头特征码（Magic Number）

每种文件开头都有固定的字节序列，可以作为定位特征：

| 文件类型 | 文件头（十六进制） | 结尾 |
|---|---|---|
| JPG | `FF D8 FF` | `FF D9` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `IEND` |
| GIF | `47 49 46 38`（"GIF8"） | `3B` |
| PDF | `25 50 44 46`（"%PDF"） | `%%EOF` |
| ZIP / docx / xlsx | `50 4B 03 04`（"PK"） | `50 4B 05 06` |

### 6.2 本次实验的恢复过程

因为明文图片是通过 **HTTP** 传输的，Wireshark 提供了更方便的导出方式，不需要手动 Follow TCP Stream：

#### 步骤 1：定位明文图片

过滤栏输入：
```
http.content_type == "image/jpeg"
```

能看到所有返回 `image/jpeg` 的 HTTP 响应包。

![过滤 image/jpeg](images/06-filter-jpeg.png)

#### 步骤 2：使用"导出对象"功能

菜单：`文件 → 导出对象 → HTTP...`（English: `File → Export Objects → HTTP...`）。

Wireshark 会自动把所有 HTTP 响应的 body 重组并列出，包括：
- 文件名（URL）
- MIME 类型
- 大小
- 服务器 IP

![Export Objects HTTP 列表](images/07-export-objects.png)

#### 步骤 3：批量保存

点 **Save All**，选择一个目录（如 `D:\Wireshark\exported_http\`），Wireshark 会自动把每个 HTTP 对象存成一个文件。

#### 步骤 4：按文件头验证

导出的文件没有扩展名，需要自己判断类型。用十六进制编辑器（HxD）打开，看前几个字节：

- 以 `FF D8 FF` 开头 → JPG，重命名为 `.jpg`
- 以 `89 50 4E 47` 开头 → PNG，重命名为 `.png`
- 以 `50 4B 03 04` 开头 → ZIP，重命名为 `.zip`

本次实验导出的 124 个文件中，**有 15 个以 `FF D8 FF` 开头**，全部是 JPG 头像。

![十六进制验证文件头](images/08-hex-verify.png)

#### 步骤 5：验证恢复结果

把这 15 个文件重命名为 `.jpg`，双击打开：

- 最大的一张 **88 KB**（640×640 的高清头像）
- 其余是 2~5 KB 的小头像（100×100）

**全部可以正常打开**，说明从明文 HTTP 流量中完整还原出了图片。

![恢复出的图片示例](images/09-recovered-sample.jpg)

### 6.3 手动方式（Follow TCP Stream）

如果想手动验证某一张图，可以：

1. 右键任意一个 `image/jpeg` 响应包 → `Follow → TCP Stream`
2. 左下角 **Show data as** 选 **Raw**
3. 点 **Save as**，存成 `.jpg`
4. 因为 HTTP 响应头（`HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n...\r\n\r\n`）在前面，需要用 HxD 把 `FF D8 FF` 之前的字节删掉

### 6.4 关于"在线传输方式"

作业里提到的"在线传输方式"，结合本次抓包实际观察，QQ 取头像走的是 **HTTP 直连 CDN**（`qh.qlogo.cn`），不是 P2P 也不是中继。这种方式：

- **优点**：服务器负载低，头像这种公共资源适合 CDN 分发
- **安全问题**：**没有加密**，任何同网段的人都能通过抓包拿到你下载的所有头像

---

## 七、实验结论

1. **传输层**：新版 QQ **几乎全部使用 TCP**（99.7%），UDP 仅用于 DNS 和 QUIC。老版本的 UDP 8000 心跳在本次抓包中**完全没有出现**。
2. **加密状态**：
   - 聊天、登录、好友同步等核心业务：**TLS 加密**（TCP 443），无法看到内容；
   - 早期信令、头像下载等辅助功能：**明文 HTTP**（TCP 80），QQ 号、头像 URL、图片内容都可以直接看到。
3. **明文文件恢复**：通过 `文件 → 导出对象 → HTTP` 功能，从 pcap 中**成功恢复 15 个 JPG 头像**，最大 88 KB，全部可正常打开。
4. **隐私启示**：虽然 QQ 聊天内容已经加密，但**头像下载、部分信令仍然走明文 HTTP**。在公共 WiFi 环境下，同网段的人可以直接抓到你访问的所有 QQ 头像和 QQ 号。

---

## 八、隐私保护说明

本文所有截图均已做如下处理：

- QQ 号在 URL 中统一打码（`uin=********`）；
- IP 地址（本机 `192.168.x.x`、服务器 `39.136.x.x`、CDN `120.233.x.x`）全部打码；
- 恢复出的头像图片来自 CDN 公开资源，未涉及他人隐私；
- 聊天内容、登录 token 一律不展示。

抓包实验仅用于课程学习，请勿用于监听他人通信。

---

## 附：本次实验用到的过滤表达式

```text
# 协议分级统计
统计 → 协议分级

# 只看 HTTP 明文流量
http

# 只看 JPEG 图片响应
http.content_type == "image/jpeg"

# 按 QQ 主服务器过滤
ip.addr == 39.136.x.x

# 按头像 CDN 域名过滤
http.host == "qh.qlogo.cn"

# 搜索 JPG 文件头（Ctrl+F → Hex）
ff d8 ff

# 导出所有 HTTP 对象
文件 → 导出对象 → HTTP
```

