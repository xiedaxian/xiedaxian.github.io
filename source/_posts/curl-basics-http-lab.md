---
title: curl 入门：一条命令把 HTTP 请求拆开看
date: 2026-11-09 20:40:00
categories: 笔记
tags:
  - curl
  - HTTP
  - 命令行
  - 安全测试
  - Pikachu
---

浏览器里点一下，页面就出来了——中间发生了什么，其实看不见。

这周的作业是"任意用 curl，截图记进 blog"。我干脆搭了个本地靶场，用 curl 把 HTTP 的每一层都戳了一遍：看状态码、看响应头、跟重定向、发 JSON、带 Cookie、传文件、调超时、限速，最后拿它去打 Pikachu 的注入点。

**一句话结论：curl 不是"命令行版浏览器"，它是一把螺丝刀——不渲染、不执行 JS、不存 Cookie，只把服务器真正回给你的字节摆出来。**

<!-- more -->

## 0. 环境

| 项目 | 说明 |
|---|---|
| 系统 | Windows 11，PowerShell 7 |
| curl | 8.11.1（Windows 自带，`C:\Windows\System32\curl.exe`） |
| 服务端 | PHP 7.3.4 内置服务器 `127.0.0.1:8087` |
| 靶场 | Pikachu + 我自己写的 6 个测试接口（`/demo/`） |
| 数据 | 一个 8MB 的 `big.bin`，用来验证下载、上传和限速 |

所有请求都指向 `127.0.0.1`。**这套东西只在自己机器上跑，别拿去扫别人的站。**

## 1. 先躲开 PowerShell 的坑

第一件事就翻车了：

```powershell
PS> curl --version
curl : 无法将"curl"项识别为 cmdlet...
```

因为 PowerShell 里 `curl` 是 `Invoke-WebRequest` 的**别名**：

```powershell
PS> (Get-Command curl).CommandType; (Get-Command curl).Definition
Alias
Invoke-WebRequest
```

两种解法：写全名 `curl.exe`，或者 `Remove-Item Alias:curl`。我选了前者——脚本里写得别扭一点，但换台机器也能跑。

[![curl 版本、别名、状态码与响应头](/images/01_basic.png)](/images/01_basic.png)

### 看状态码和耗时

```powershell
curl.exe -s -o NUL -w "code=%{http_code}  time=%{time_total}s  bytes=%{size_download}`n" http://127.0.0.1:8087/pikachu/
# code=200  time=0.017903s  bytes=35389
```

`-s` 静音（不打印进度条），`-o NUL` 把正文丢掉，`-w` 只输出我要的变量。

这三个数比"打开网页感觉挺快"有用得多：**状态码说明结果，字节数说明拿到多少，耗时说明快不快**。写监控脚本时，解析这三个变量就够了。

### 只看响应头

```powershell
curl.exe -sI http://127.0.0.1:8087/pikachu/
```

```text
HTTP/1.1 200 OK
Host: 127.0.0.1:8087
Date: Mon, 09 Nov 2026 20:09:05 +0800
X-Powered-By: PHP/7.3.4
Set-Cookie: PHPSESSID=r0bh5jgaedcnu813cl1pks2p40; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
```

`-I` 发的是 HEAD 请求。排查问题时，这一屏信息往往比正文更有用：`X-Powered-By` 直接告诉你后端是 PHP 7.3.4，`Set-Cookie` 告诉你它发了会话。

## 2. 重定向：加不加 `-L`，是两种世界

```powershell
curl.exe -s -o NUL -w "不加 -L: code=%{http_code}  location=%{redirect_url}`n" http://127.0.0.1:8087/demo/redirect.php
# 不加 -L: code=302  location=http://127.0.0.1:8087/demo/index.php?from=redirect

curl.exe -sL -o NUL -w "加了 -L: code=%{http_code}  跳了 %{num_redirects} 次  终点=%{url_effective}`n" http://127.0.0.1:8087/demo/redirect.php
# 加了 -L: code=200  跳了 1 次  终点=http://127.0.0.1:8087/demo/index.php?from=redirect
```

不带 `-L`，curl 把 302 原样交给你；带了 `-L`，它自己跟过去，`url_effective` 是真正落地的地址。

**这两个数很有用**：`num_redirects` 突然变多，通常意味着登录态丢了或者被劫持到别处。

## 3. 下载与校验：别只看"下完了"

```powershell
curl.exe -s -o big.bin -w "下载完成: %{size_download} 字节, 用时 %{time_total}s`n" http://127.0.0.1:8087/demo/big.bin
# 下载完成: 8388608 字节, 用时 0.140372s

(Get-Item big.bin).Length
# 8388608
(Get-FileHash big.bin -Algorithm SHA256).Hash.Substring(0,16)
# C1BA29C26468DD8A
```

`-o` 写文件（`-O` 用 URL 里的文件名）。下完顺手核一下大小和哈希，是我这次养成的习惯——**"下载成功"和"文件是对的"是两件事**。

[![重定向与下载校验](/images/02_redirect_download.png)](/images/02_redirect_download.png)

## 4. POST：表单与 JSON

表单很简单，`-d` 默认就是 `application/x-www-form-urlencoded`：

```powershell
curl.exe -s -X POST -d "name=zhangsan&age=20" http://127.0.0.1:8087/demo/index.php
```

```json
{
    "method": "POST",
    "form": { "name": "zhangsan", "age": "20" },
    "ctype": "application/x-www-form-urlencoded",
    "body": "name=zhangsan&age=20"
}
```

发 JSON 时我踩了个坑：直接在 PowerShell 里写 `-d '{"name":"zhangsan"}'`，引号会被吃掉，服务端收到的是 `{name:zhangsan}` —— 不是合法 JSON。

正确姿势是把 JSON 放进文件，用 `--data-binary "@文件"`：

```powershell
# payload.json 内容： {"name":"zhangsan","age":20,"tags":["curl","demo"]}
curl.exe -s -X POST -H "Content-Type: application/json" --data-binary "@payload.json" http://127.0.0.1:8087/demo/index.php
```

```json
{
    "ctype": "application/json",
    "body": { "name": "zhangsan", "age": 20, "tags": ["curl", "demo"] }
}
```

**`-d` 和 `--data-binary` 的区别**：前者会去掉换行、按表单处理；后者原样发送。发 JSON、发 XML、发二进制，一律用后者。

[![表单 POST 与 JSON POST](/images/03_post.png)](/images/03_post.png)

## 5. Cookie：`-c` 写，`-b` 读

```powershell
curl.exe -s -c cookies.txt http://127.0.0.1:8087/demo/setcookie.php
# cookie set
Get-Content cookies.txt | Select-String demo_sid
# 127.0.0.1  FALSE  /  FALSE  1794229746  demo_sid  sid-9738092a

curl.exe -s -b cookies.txt http://127.0.0.1:8087/demo/cookie.php
# {"cookie_in_request":{"demo_sid":"sid-9738092a"}}
```

`-c` 把服务器 `Set-Cookie` 的内容存成 Netscape 格式的文本文件，`-b` 下次带上去。

这就是"登录一次，后面都用这个会话"的最小实现——**写爬虫、做接口联调时，先 `-c` 拿一次票，再 `-b` 反复用**，比在代码里手动拼 Cookie 头省事。

## 6. 上传：`-F` 走 multipart

```powershell
curl.exe -s -F "file=@big.bin" http://127.0.0.1:8087/demo/upload.php
```

```json
{
    "ok": true,
    "name": "big.bin",
    "size": 8388608,
    "sha256": "c1ba29c26468dd8a2029a63295d24b9182b1bc03860de5e38f42927a22296efa"
}
```

服务端算出的 sha256，和本地 `Get-FileHash` 的结果一致——**一个字节都没丢**。这比"上传成功"四个字可信。

`-F` 还能带别的字段：`-F "file=@a.png" -F "name=头像"`。要指定 MIME，用 `-F "file=@a.png;type=image/png"`。

[![Cookie 会话与文件上传](/images/04_cookie_upload.png)](/images/04_cookie_upload.png)

## 7. 超时、重试、限速：脚本稳不稳，看这三个

### 超时

```powershell
curl.exe -s --max-time 2 -o NUL -w "服务端要 5 秒, 我 2 秒就断: code=%{http_code}`n" http://127.0.0.1:8087/demo/slow.php
# 服务端要 5 秒, 我 2 秒就断: code=000
"curl 退出码 = " + $LASTEXITCODE
# curl 退出码 = 28
```

服务端故意睡 5 秒，客户端 2 秒就掐断。注意 **`code=000` 不是服务器返回的状态码，而是"压根没拿到响应"**；真正的判据是退出码 28。

脚本里判断超时，看退出码，别去正则匹配错误文案——文案会随版本和语言变。

### 重试

```powershell
curl.exe -s --retry 3 --retry-all-errors -w "重试次数=%{num_retries}`n" http://127.0.0.1:8087/demo/flaky.php
# attempt 1: boom
# attempt 2: boom
# attempt 3: ok
# 重试次数=2
```

接口前两次返回 500，第三次好了，curl 自己重试了 2 次。

`--retry` 默认就会重试 5xx 和连接类错误；加上 `--retry-all-errors` 才会对 4xx 之类也重试。**别对着"扣库存"这种接口乱加重试**——重试是双刃剑。

### 限速

```powershell
curl.exe -s -o NUL --limit-rate 2M -w "限速 2MB/s: 8MB 用了 %{time_total}s`n" http://127.0.0.1:8087/demo/big.bin
# 限速 2MB/s: 8MB 用了 4.013053s
```

8MB ÷ 2MB/s ≈ 4 秒，实测 4.01 秒。做压测、模拟弱网、给下载脚本限速时用它。

[![超时、重试、限速](/images/05_timeout_retry_rate.png)](/images/05_timeout_retry_rate.png)

## 8. 伪装与认证：两个常用开关

```powershell
# 换 UA、伪造 Referer
curl.exe -s -A "Mozilla/5.0 (curl-demo)" -e "http://example.com/" "http://127.0.0.1:8087/demo/index.php?from=ua"
# {"ua": "Mozilla/5.0 (curl-demo)", "referer": "http://example.com/", "query": {"from": "ua"}}

# HTTP Basic 认证
curl.exe -s -o NUL -w "code=%{http_code}`n" http://127.0.0.1:8087/demo/auth.php
# code=401
curl.exe -s -u demo:s3cret http://127.0.0.1:8087/demo/auth.php
# {"ok":true,"user":"demo"}
```

`-A` 改 User-Agent，`-e` 改 Referer，`-u` 带 Basic 认证（curl 自动做 base64，不用手拼）。

**注意**：`-u` 的密码会出现在进程列表和 shell 历史里。真要用，用 `-u demo` 让它交互式输入，或者 `--netrc-file`。

## 9. 调试：`-v` 与 `--trace-ascii`

```powershell
curl.exe -s -o NUL --trace-ascii trace.log -w "建连 %{time_connect}s  首字节 %{time_starttransfer}s`n" http://127.0.0.1:8087/demo/index.php
# 建连 0.001344s  首字节 0.001889s
```

`--trace-ascii` 把收发的每个字节写进文件（含请求行、请求头、响应头）。`-v` 是同一类信息，打到终端。

**排查"为什么 403 / 为什么慢"时，先看 trace**：请求头到底带了什么、服务端回了什么，一目了然。`time_connect` 大说明网络/握手慢，`time_starttransfer` 大说明服务端处理慢——两个数把问题分成了两半。

## 10. 拿 curl 打靶场：SQL 注入和 XSS

最后一步，用它打 Pikachu 的注入点。先把地址存成变量，命令短一点：

```powershell
$base = "http://127.0.0.1:8087/pikachu/vul/sqli/sqli_str.php"
curl.exe -s "$base`?name=vince&submit=1" -o r1.html
Select-String -Path r1.html -Pattern "email is: [^<]+" | ForEach-Object { $_.Matches.Value }
# email is: vince@pikachu.com
```

正常查一个用户。然后换成 payload `' or 1=1 #`（URL 编码后是 `%27%20or%201%3D1%20%23`）：

```powershell
curl.exe -s "$base`?name=%27%20or%201%3D1%20%23&submit=1" -o r2.html
Select-String -Path r2.html -Pattern "email is: [^<]+" -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -First 3
# email is: vince@pikachu.com
# email is: allen@pikachu.com
# email is: kobe@pikachu.com
```

一个不该存在的账号，带出了全表 7 条记录。

XSS 更有意思：

```powershell
$xss = "http://127.0.0.1:8087/pikachu/vul/xss/xss_reflected_get.php"
curl.exe -s "$xss`?message=%3Cscript%3Ealert(1)%3C%2Fscript%3E&submit=submit" -o r3.html
Select-String -Path r3.html -Pattern "who is" | ForEach-Object { $_.Line.Trim() }
# <p class='notice'>who is <script>alert(1)</script>,i don't care!</p>
```

**脚本原样回显，说明过滤没做。** 但 curl 不会给你弹窗——它不执行 JS。

这正好说明了 curl 的定位：**验证"服务端返回了什么"，不验证"浏览器会怎么执行"**。要证明 XSS 真能弹，还得用浏览器；要证明服务端有漏洞，curl 更快更干净。

[![用 curl 验证 SQL 注入与反射型 XSS](/images/06_security.png)](/images/06_security.png)

## 11. 踩过的 5 个坑

| 坑 | 现象 | 解法 |
|---|---|---|
| PowerShell 别名 | `curl` 报"无法识别"或行为怪 | 写 `curl.exe`，或删掉别名 |
| 引号被吃 | JSON 到服务端变成 `{name:zhangsan}` | 用 `--data-binary "@file.json"` |
| 中文乱码 | `-w` 里的中文变成问号 | 先 `chcp 65001`，脚本存成 UTF-8 with BOM |
| 以为超时是 000 状态码 | 脚本判断错 | 看退出码 28，不要看 http_code |
| `-I` 拿到 405 | 某些接口不支持 HEAD | 用 `-s -o NUL -D -` 只取头 |

## 12. 速查表

```bash
curl -s -o NUL -w "%{http_code} %{time_total}s\n" URL   # 只看结果
curl -sI URL                                             # 只看响应头
curl -sL -o file URL                                     # 跟重定向 + 存文件
curl -s -X POST -d "a=1&b=2" URL                         # 表单
curl -s -X POST -H "Content-Type: application/json" --data-binary @x.json URL
curl -s -c c.txt URL && curl -s -b c.txt URL             # 会话
curl -s -F "file=@a.bin" URL                             # 上传
curl -s --max-time 5 --retry 3 URL                       # 超时 + 重试
curl -s --limit-rate 2M -o f URL                         # 限速
curl -s -A "UA" -e "Referer" URL                         # 伪装
curl -s -u user:pass URL                                 # Basic 认证
curl -s --trace-ascii t.log URL                          # 抓包级调试
```

## 小结

以前我理解的 curl 就是"命令行下个网页"。这次跑完 22 条命令，改观挺大：

1. **它是 HTTP 的显微镜**——状态码、响应头、跳转链路、耗时，全都能单独拎出来看；
2. **它和浏览器是两种视角**——浏览器执行 JS、管 Cookie、跟重定向，curl 什么都不替你做，所以你能看到"原始的那一层"；
3. **它天然适合做安全验证**——注入有没有回显、上传有没有落地、重定向去了哪，一条命令一个证据；
4. **它的退出码比输出更适合写脚本**——0 成功、28 超时、7 连不上，判断这些比匹配文本可靠。

下一步想把 `-w` 的输出接进一个小脚本，定时巡检自己的服务，出问题就发通知——那就是"轻量监控"的雏形了。
