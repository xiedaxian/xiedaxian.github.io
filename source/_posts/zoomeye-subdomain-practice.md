---
title: 网络空间测绘与子域名收集实践（ZoomEye 作业）
date: 2026-10-20 20:00:00
tags:
  - 网络安全
  - 网络空间测绘
  - ZoomEye
  - 信息收集
  - 子域名
categories: 网络安全
---

## 一、与 ZoomEye 功能类似的搜索引擎

ZoomEye（钟馗之眼）是北京知道创宇开发的网络空间测绘引擎，主要用于探测和识别互联网空间中的设备、网站及其组成的网络空间。与之功能类似的搜索引擎主要有：

### 1. 国外主流引擎

| 引擎 | 开发方 | 特点 |
| --- | --- | --- |
| **Shodan** | 美国 Shodan 公司 | 网络空间搜索引擎的鼻祖，号称"黑客版谷歌"，主要扫描联网设备（IoT、工控、服务器、摄像头等），收录的端口和 banner 信息非常全 |
| **Censys** | 密歇根大学团队 | 基于证书和主机扫描，对 HTTPS 证书、指纹识别做得较好，学术研究常用 |
| **BinaryEdge** | 法国 BinaryEdge | 覆盖全球 IPv4 地址、域名和漏洞数据，提供 API 服务 |
| **Criminal IP** | 韩国 S1 Corp | 主打威胁情报，集成 IP 风险评分、漏洞和攻击面分析 |
| **Netcraft** | 英国 Netcraft | 老牌网站技术栈识别、主机托管和钓鱼检测服务 |

### 2. 国内主流引擎

| 引擎 | 开发方 | 特点 |
| --- | --- | --- |
| **FOFA** | 白帽汇 | 国内最常用的资产搜索引擎，语法为 `title="" body="" host="" domain=""` |
| **Hunter（鹰图）** | 奇安信 | 奇安信旗下，支持网站、APP、IoT 设备等资产测绘 |
| **Quake（360 鹰图）** | 360 | 资产覆盖面广，支持 JS 指纹、图标 hash 检索 |

> 国内最常用的三大测绘引擎是 **ZoomEye、FOFA、Hunter**，国外则以 **Shodan、Censys** 为代表。它们的共同原理都是主动扫描全球 IPv4 地址，抓取端口 banner、HTTP 头、证书、favicon 等指纹，建立可搜索的资产数据库。

### 3. 辅助收集类工具

- **crt.sh**：基于证书透明度（CT）日志查询子域名
- **DNSdumpster**：DNS 记录和子域名可视化
- **Wayback Machine（web.archive.org）**：网站历史快照，可找历史暴露的子域名

<!-- more -->

## 二、使用 ZoomEye 进行实际搜索

ZoomEye 访问地址：<https://www.zoomeye.org>，注册登录后即可在搜索框输入查询语句。常用语法如下：

| 语法 | 含义 | 示例 |
| --- | --- | --- |
| `app=""` | 指定组件 / 产品 | `app="Tomcat"` |
| `title=""` | 网站标题 | `title="后台管理系统"` |
| `body=""` | 网页正文内容 | `body="IIS Windows Server"` |
| `site=""` | 指定站点域名 | `site="guet.edu.cn"` |
| `ip=""` | 指定 IP 或网段 | `ip="1.1.1.1/24"` |
| `port=""` | 指定端口 | `port="3389"` |
| `country=""` | 地理位置 | `country="CN"` |

下面是三次实际搜索的结果。

### 2.1 按标题搜索暴露的后台管理系统

搜索语句：

```
title="后台管理系统"
```

结果：约 **162,121** 条，用时 0.649 秒。

结果中可以看到大量暴露在外网的后台登录页面，例如：

- `a.001power.com:80` — 今电共享充电宝后台管理系统（广东深圳，Nginx）
- `134.175.8.36:5001` — 房产信息管理系统（广东广州）
- `8.163.29.69:81` — 广州合浦学会后台管理系统（阿里云）

这类后台如果弱口令或存在未授权访问，很容易被直接打穿。

![ZoomEye 搜索 title="后台管理系统"](/images/zoomeye-title.png)

### 2.2 按组件指纹搜索 Tomcat 服务器

搜索语句：

```
app="Tomcat"
```

结果：约 **596 万**条（近一年数据 148 万条），用时 0.215 秒。

ZoomEye 不仅识别出了 Tomcat 的存在，还精确到了具体版本：

- `181.110.73.128:3525` — Apache Tomcat/9.0.79（阿根廷）
- `transport.educanet.pro:443` — Apache Tomcat/7.0.57（法国，OVH 机房）

版本号的意义在于可以直接对照 CVE 漏洞库判断该版本是否存在已知漏洞（比如 Tomcat AJP 幽灵猫 CVE-2020-1938）。

![ZoomEye 搜索 app="Tomcat"](/images/zoomeye-app-tomcat.png)

### 2.3 按端口和国家搜索暴露的远程桌面

搜索语句：

```
port="3389" && country="CN"
```

结果：约 **821 万**条（近一年 85 万条），用时 0.129 秒。

右侧统计显示，全网 3389 端口记录约 **2367 万**条，其中"Remote Desktop"组件约 **1470 万**条。结果中一大批北京联通 IP 的 3389 端口 banner 是 `\x03\x00\x00\x0b\x06\xe0\x00\x00`，这是标准的 RDP 协议握手指纹。

这说明仅仅两个筛选条件，就能从全网拉出数量惊人的暴露远程桌面服务，也是勒索软件、暴力破解最常盯上的目标之一。

![ZoomEye 搜索 port="3389" country="CN"](/images/zoomeye-port-3389.png)

## 三、子域名收集实践

子域名收集是信息收集（OSINT / 资产测绘）的第一步，目标是找到目标主域名下所有可能存在的子域名，例如 `guet.edu.cn` → `www.guet.edu.cn`、`lib.guet.edu.cn`、`zabbix.guet.edu.cn` 等。

### 3.1 常见方法概览

| 方法 | 原理 | 代表工具 |
| --- | --- | --- |
| 证书透明度（CT 日志） | CA 签发证书时会把包含的所有域名写入公开 CT 日志 | crt.sh |
| 在线工具查询 | 第三方已聚合好的子域名数据库 | 站长工具、微步在线、DNSdumpster |
| 字典爆破 | 枚举常见子域名字典并做 DNS 解析 | OneForAll、Sublist3r、Amass、Layer 子域名挖掘机 |
| 搜索引擎语法 | Google 收录过的子域名页面 | `site:example.com` |
| 测绘引擎反查 | 测绘引擎主动扫描过的资产 | ZoomEye `site=`、FOFA `domain=` |

### 3.2 本次实操：用 ZoomEye 反查 guet.edu.cn

本次作业中我选择以 `guet.edu.cn`（桂林电子科技大学）为目标，使用 ZoomEye 的 `site=` 语法进行子域名收集。

搜索语句：

```
site="guet.edu.cn"
```

结果：共 **214** 条，用时 0.866 秒。从结果列表中提取出的部分子域名如下：

| 子域名 | 用途 / 备注 |
| --- | --- |
| `www.guet.edu.cn` | 学校主站 |
| `lib.guet.edu.cn` | 图书馆 |
| `xb.guet.edu.cn` | 学报 |
| `portal.guet.edu.cn` | 门户（当前返回 404） |
| `pay.guet.edu.cn` | 缴费系统（Windows + IIS/ASP.NET） |
| `zhsx.guet.edu.cn` | 网络应用认证 |
| `zabbix.guet.edu.cn` | Zabbix 监控系统 |

![ZoomEye site="guet.edu.cn" 子域名收集结果](/images/zoomeye-subdomain.png)

### 3.3 收获与思考

通过这一次反查，可以看到几个有意思的点：

1. **覆盖面广**：一条 `site=` 语句就枚举出了主站、图书馆、学报、缴费、认证、监控等多个业务子域名，相当于把学校的对外资产面摸了一遍。
2. **意外发现敏感系统**：`zabbix.guet.edu.cn` 是 Zabbix 监控系统，这类系统通常不应该直接暴露在公网，一旦被弱口令或未授权访问攻破，攻击者就能拿到全校服务器的拓扑和状态信息。
3. **技术栈暴露**：`pay.guet.edu.cn` 跑的是 Windows + IIS/ASP.NET，后续可以针对该技术栈做进一步漏洞排查。

## 四、总结

1. **同类引擎**：ZoomEye 的同类产品国外有 Shodan、Censys、BinaryEdge，国内有 FOFA、Hunter、Quake，它们都属于"网络空间测绘"类别，核心能力都是主动扫描全球 IP、抓取指纹、建立可搜索资产库。
2. **ZoomEye 实操**：通过 `title`、`app`、`port+country` 三类查询，分别验证了它在"暴露后台识别、中间件指纹识别、按端口地理筛选"三个场景下的能力。
3. **子域名收集**：综合使用 CT 日志、在线工具、字典爆破、搜索引擎语法、测绘引擎反查，可以最大程度覆盖目标资产面。本次实操使用 ZoomEye `site="guet.edu.cn"` 一条语句就枚举出 214 条资产，既完成了子域名收集，也顺便发现了像 Zabbix 监控这类不该暴露的敏感系统。
