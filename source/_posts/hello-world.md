---
title: 欢迎来到我的博客
date: 2026-09-23 10:00:00
tags:
  - 公告
  - Hexo
---

你好，欢迎来到我的博客！这个站点由 [Hexo](https://hexo.io/) 静态生成，并通过 GitHub Actions 自动部署到 GitHub Pages。

## 这个博客是怎么搭起来的

1. 用 `hexo init` 在本地生成项目骨架；
2. 在 GitHub 上创建名为 `<用户名>.github.io` 的仓库；
3. 把源码 push 到 `main` 分支；
4. 仓库 Settings → Pages → Source 选择 **GitHub Actions**；
5. 每次 push，GitHub 自动执行 `.github/workflows/pages.yml`，构建并发布到线上。

## 常用命令

```bash
hexo new post "文章标题"   # 新建一篇文章
hexo server                # 本地预览，默认 http://localhost:4000
hexo clean && hexo generate # 清理并重新生成
```

文章都放在 `source/_posts/` 目录下，用 Markdown 编写。写好 push 到 GitHub 后，稍等几十秒就能在线上看到。

接下来我会陆续在这里记录学习笔记、踩坑经验和一些随想。感谢来访。
