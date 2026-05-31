<div align="center">

# ☁️ CloudShare

**基于 Cloudflare Workers + R2 的轻量级文件分享系统**

无服务器 · 全球加速 · 秒传去重 · 单文件部署

[![License: GPL-3.0-only](https://img.shields.io/badge/License-GPL%203.0--only-blue.svg)](./LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![Storage: R2](https://img.shields.io/badge/Storage-R2-F38020?logo=cloudflare&logoColor=white)](https://developers.cloudflare.com/r2/)
[![Zero Dependencies](https://img.shields.io/badge/Runtime%20Deps-0-success.svg)](#-技术架构)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#-参与贡献)

</div>

---

## 📖 简介

CloudShare 是一个跑在 [Cloudflare Workers](https://workers.cloudflare.com/) 边缘网络上的文件管理与分享系统。整个应用是 **一个零运行时依赖的 `worker.js`**，前端页面、API 与存储逻辑全部内联其中，部署后即可获得一个带管理后台的私有网盘 + 公开分享服务。

文件通过内容寻址（SHA-256）存入 R2，相同内容只占一份空间并实现 **秒传**；分享链接支持密码与有效期，并由签名 Cookie 守护管理后台。没有数据库，没有构建步骤，没有服务器要维护。

## ✨ 功能特性

- 📂 **文件管理后台** — 卡片式网格界面，支持多级文件夹、面包屑导航、拖拽上传与浏览器前进/后退。
- ⚡ **秒传与去重** — 上传前在浏览器端流式计算 SHA-256，命中已有内容直接秒传，R2 中相同文件只存一份（引用计数管理生命周期）。
- 🧩 **大文件分片上传** — 超过 40 MB 自动切换 R2 Multipart，分片并发上传、可随时取消、失败自动清理。
- 🔗 **灵活的分享链接** — 文件或整个文件夹一键生成分享链接，支持设置 **访问密码** 与 **有效期**（1 小时 / 24 小时 / 7 天 / 30 天 / 自定义 / 永久）。
- 🛠️ **分享管理** — 集中查看、续期、改密码、生成免密直链或随时取消已有分享。
- ⬇️ **断点续传下载** — 下载完整支持 HTTP Range 请求（206），可被播放器拖动进度、被下载器分段抓取。
- 🔐 **安全可靠** — 管理后台由 HMAC 签名的 HttpOnly Cookie 守护，密码使用 PBKDF2（100k 迭代）哈希，登录失败限流，常量时间比较防时序攻击。
- 🌍 **边缘加速** — 全部跑在 Cloudflare 全球网络，下载响应带 CDN 缓存头，就近分发。
- 📦 **零依赖单文件** — 整个系统就是一个 `worker.js`，无前端框架、无构建、无运行时依赖。

## 🏗️ 技术架构

| 层 | 技术 | 说明 |
| --- | --- | --- |
| 运行时 | Cloudflare Workers | 边缘无服务器，处理所有 HTTP 请求 |
| 对象存储 | Cloudflare R2 | 存放文件内容（内容寻址 blob）与去重指针 |
| 元数据 | Cloudflare KV | 存放分享令牌、引用计数、登录限流记录 |
| 前端 | 内联 HTML / CSS / 原生 JS | 管理后台、分享页、登录页全部内联在 Worker 中 |

**存储模型**：实际内容以 `__blob__/<sha256>` 为 key 存入 R2；每个可见文件是一个体积为 0、带 `sha256` 元数据的「指针」对象。`fhash:<sha256>` 记录在 KV 中维护引用计数，删除时计数归零才真正清除 blob，从而实现跨文件夹的去重与秒传。

## 🚀 部署指南

### 前置条件

- 一个 [Cloudflare 账号](https://dash.cloudflare.com/sign-up)（R2 需在面板中开通）
- 已安装 [Node.js](https://nodejs.org/) 18+
- 包管理器：`npm` / `pnpm` / `yarn` 任选其一

### 1. 克隆与安装

```bash
git clone https://github.com/b1ankcat/cloudshare.git
cd cloudshare
npm install        # 或 pnpm install
```

### 2. 登录 Cloudflare

```bash
npx wrangler login
```

### 3. 创建 R2 存储桶与 KV 命名空间

```bash
# 创建 R2 桶（存放文件内容）
npx wrangler r2 bucket create <bucket_name>

# 创建 KV 命名空间（存放分享元数据），记下返回的 id
npx wrangler kv namespace create cloudshare-shares
```

### 4. 配置 `wrangler.toml`

基于模板生成自己的配置：

```bash
cp wrangler.toml.template wrangler.toml
```

然后填入上一步得到的资源名与 KV `id`：

```toml
name = "cloudshare"
main = "worker.js"
compatibility_date = "2025-05-31"

[[r2_buckets]]
binding = "FILES_BUCKET"
bucket_name = "在此填入 Bucket name"

[[kv_namespaces]]
binding = "cloudshare_shares"
id = "在此填入 KV namespace id"
```

> ⚠️ 绑定名称 `FILES_BUCKET` 与 `cloudshare_shares` 已被 `worker.js` 引用，请勿改动。

### 5. 设置管理员密码（必需）

管理后台凭据来自 `ADMIN_PASSWORD` 这一 Secret，**未配置时后台无法登录**。请用 Secret 而非明文写进配置：

```bash
npx wrangler secret put ADMIN_PASSWORD
# 按提示输入一个高强度密码
```

### 6. 本地预览 / 部署上线

```bash
npm run dev     # 本地开发预览 (wrangler dev)
npm run ship    # 部署到 Cloudflare (wrangler deploy)
npm run tail    # 实时查看线上日志
```

部署完成后访问 `https://cloudshare.<your-subdomain>.workers.dev`，使用 `ADMIN_PASSWORD` 登录即可进入管理后台。

## 📂 项目结构

```
cloudshare/
├── worker.js              # 全部逻辑：路由 / API / 存储 / 内联前端页面
├── wrangler.toml.template # 配置模板（复制为 wrangler.toml 后填写）
├── package.json           # dev / ship / tail 脚本
└── LICENSE                # GPL-3.0-only
```

## 🧭 使用说明

- **管理后台 `/`** — 上传、新建文件夹、下载、删除、发起分享。支持拖拽上传与多级目录。
- **分享管理 `/manage`** — 查看全部分享，续期、改密码、复制（免密）链接或取消。
- **分享页 `/s/:token`** — 访客访问入口；若设有密码会先要求验证。
- **下载 `/dl/:token`（文件）/ `/dl/:token/:filename`（文件夹内文件）** — 实际文件流，支持断点续传。

上传逻辑会根据文件大小自动选择策略：≤ 40 MB 走普通直传，更大的文件走 R2 分片并发上传；任意大小在上传前都会先做 SHA-256 指纹比对以触发秒传。

## 🔒 安全说明

- **务必设置高强度 `ADMIN_PASSWORD`**，它既是登录凭据，也是 HMAC 会话签名密钥。修改它会使所有已登录会话失效。
- 分享密码以 PBKDF2-SHA256（100,000 次迭代 + 随机盐）哈希存储，不保存明文。
- 登录失败按客户端 IP 限流（10 分钟内 5 次），缓解暴力破解。
- 会话 Cookie 为 `HttpOnly` + `SameSite=Lax`，HTTPS 下自动加 `Secure`，有效期 7 天。
- 「复制带密码链接」会把密码以明文 query 参数附在 URL 上以便免密访问，请仅在可信渠道分发此类链接。

## 🤝 参与贡献

欢迎提交 Issue 与 Pull Request。提交前请确保改动能通过 `npm run dev` 本地验证。

## 📜 开源协议

本项目基于 **[GPL-3.0-only](./LICENSE)** 协议开源。你可以自由使用、修改和分发，但衍生作品须以相同协议开源。

---

<div align="center">

用 ☁️ Cloudflare Workers + R2 构建 · 如果这个项目对你有帮助，欢迎点亮 ⭐

</div>

