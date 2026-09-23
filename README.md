# 我的 Hexo 博客（GitHub Pages）

基于 Hexo 7 + GitHub Actions 自动部署到 GitHub Pages 的个人博客。
本地项目目录：`D:\hexo-blog`

## 目录结构

```
D:\hexo-blog
├── _config.yml              # 站点配置（标题、作者、url 等）
├── package.json
├── .gitignore               # 已排除 public/、node_modules/
├── .github/workflows/pages.yml   # GitHub Actions 自动部署工作流
├── scaffolds/               # 文章模板
├── source/_posts/          # 你的文章都放这里（Markdown）
└── themes/landscape/       # 主题
```

## 本地常用命令

在 `D:\hexo-blog` 目录下打开终端（PowerShell）执行：

```bash
hexo new post "文章标题"     # 新建文章（生成在 source/_posts/）
hexo server                  # 本地预览，浏览器打开 http://localhost:4000
hexo clean && hexo generate  # 清理并重新生成静态文件
```

## 部署到 GitHub Pages（按官方文档）

> ⚠️ 你电脑当前**没有安装 git**，部署前请先安装 Git for Windows：
> https://git-scm.com/download/win  （或安装 GitHub Desktop）

### 1. 创建仓库
登录 GitHub，新建一个仓库，名字必须是：
```
你的GitHub用户名.github.io
```
（例如用户名叫 `zhangsan`，仓库名就是 `zhangsan.github.io`）

### 2. 改配置
打开 `_config.yml`，把第 16 行的 url 改成你自己的：
```yaml
url: https://你的GitHub用户名.github.io
```

### 3. 初始化 git 并推送
在 `D:\hexo-blog` 目录下：
```bash
git init
git add .
git commit -m "init my blog"
git branch -M main
git remote add origin https://github.com/你的GitHub用户名/你的GitHub用户名.github.io.git
git push -u origin main
```

### 4. 开启 Pages
到 GitHub 仓库页面：**Settings → Pages → Source**，把 Source 改成 **GitHub Actions**，保存。

### 5. 等待部署
push 后 GitHub 会自动运行 `.github/workflows/pages.yml`（仓库的 Actions 标签页可看进度）。
约 1～2 分钟后，访问 `https://你的GitHub用户名.github.io` 即可看到博客。

## 以后写新文章的流程
1. `hexo new post "新文章标题"`，编辑 `source/_posts/新文章标题.md`
2. 本地 `hexo server` 预览满意后：
   ```bash
   git add . && git commit -m "new post" && git push
   ```
3. push 后自动重新部署，几十秒上线。
