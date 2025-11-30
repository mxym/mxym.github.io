# 💌 DearNikki

> 基于 [Fuwari](https://github.com/saicaca/fuwari) 开发的静态博客模板。
>
> ❗ 警告：该项目的修改部分有来自 AI 的帮助

![预览](https://raw.githubusercontent.com/Rabbit0w0/dear-nikki/main/nikki-screenshot.png)

## 🚀 使用方法

### 1️⃣ 克隆仓库并安装依赖

```sh
git clone https://github.com/Rabbit0w0/dear-nikki.git
cd DearNikki
pnpm install
pnpm add sharp
```

> 若未安装 pnpm：
> `npm install -g pnpm`

---

### 2️⃣ 自定义配置

修改文件：

```
src/config.ts
```

可以修改：

* 博客标题、副标题
* 头像、社交链接
* 主题色
* 导航菜单等

---

### 3️⃣ 创建文章（手动）

文章放在：

```
src/content/posts/
```

新建 Markdown 或 MDX 文件，例如：

```
src/content/posts/hello-world.md
```

并添加 Frontmatter：

```yaml
---
title: Hello World
published: 2023-09-09
description: My first post using DearNikki 💌
image: ./cover.jpg
tags: [Life, Diary]
category: Notes
draft: false
lang: zh
---
```

正文写在下方即可。

---

### 4️⃣ 本地开发 / 部署

```sh
pnpm dev
```

浏览器访问：

➡️ [http://localhost:4321](http://localhost:4321)

构建 & 预览：

```sh
pnpm build
pnpm preview
```

部署请参考 Astro 官方指南：
Vercel / Netlify / GitHub Pages 等均可使用
➡️ 编辑 `astro.config.mjs` 中的 `site` 配置

---

## 🧞 常用命令

| Command                           | Action          |
| :-------------------------------- | :-------------- |
| `pnpm install` & `pnpm add sharp` | 安装依赖            |
| `pnpm dev`                        | 启动开发环境          |
| `pnpm build`                      | 打包至 `./dist/`   |
| `pnpm preview`                    | 预览打包结果          |
| `pnpm astro ...`                  | 执行 Astro CLI 命令 |
| `pnpm astro --help`               | 查看帮助信息          |

---

> 本项目基于原仓库 [Fuwari](https://github.com/saicaca/fuwari) 的代码进行 fork 和修改。
> 原项目的许可证：MIT License (见 LICENSE-Fuwari 文件)
> 新增内容仍遵循 MIT License
