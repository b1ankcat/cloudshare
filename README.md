<div align="center">

# ☁️ CloudShare

**基于 Cloudflare Workers + R2 的轻量级文件分享系统**

无服务器 · 全球加速 · 秒传去重 · 内容寻址

[![License: GPL-3.0-only](https://img.shields.io/badge/License/GPL%203.0--only-blue.svg)](./LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare/Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![Storage: R2](https://img.shields.io/badge/Storage/R2-F38020?logo=cloudflare&logoColor=white)](https://developers.cloudflare.com/r2/)
[![Tests](https://img.shields.io/badge/Tests-214%20passing-success.svg)](#-测试)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#-参与贡献)

</div>

---

## 📖 简介

CloudShare 是一个跑在 [Cloudflare Workers](https://workers.cloudflare.com/) 边缘网络上的文件管理与分享系统。

文件通过内容寻址（SHA-256）存入 R2，相同内容只占一份空间并实现 **秒传**；分享链接支持密码与有效期，并由签名 Cookie 守护管理后台。没有数据库，没有服务器要维护。

代码组织为多个 ESM 模块（`src/*.ts`），每个模块职责单一；内联的 HTML/CSS/JS 仍按页面拆分到 `src/pages/`。零运行时依赖，TypeScript 严格模式。

## ✨ 功能特性

- 📂 **文件管理后台** — 卡片式网格界面，支持多级文件夹、面包屑导航、拖拽上传与浏览器前进/后退。
- ⚡ **秒传与去重** — 上传前在浏览器端流式计算 SHA-256，命中已有内容直接秒传，R2 中相同文件只存一份（引用计数管理生命周期）。
- 🧩 **大文件分片上传** — 超过 40 MB 自动切换 R2 Multipart，分片并发上传、可随时取消、失败自动清理。
- 🔗 **灵活的分享链接** — 文件或整个文件夹一键生成分享链接，支持设置 **访问密码** 与 **有效期**（1 小时 / 24 小时 / 7 天 / 30 天 / 自定义 / 永久）。
- 🛠️ **分享管理** — 集中查看、续期、改密码、生成免密直链或随时取消已有分享。
- ⬇️ **断点续传下载** — 下载完整支持 HTTP Range 请求（206），可被播放器拖动进度、被下载器分段抓取。
- 🔐 **安全可靠**
  - 管理后台由 HMAC 签名的 HttpOnly Cookie 守护
  - 密码使用 PBKDF2-SHA256（100,000 次迭代 + 16 字节随机盐）哈希
  - 登录失败按 IP 限流（10 分钟内 5 次）
  - 常量时间比较防时序攻击
  - 前后端双重转义防 XSS；文件名严格白名单
  - 敏感页面强制 `Cache-Control: no-store`，防后退看到已退登内容
  - 错误响应只回通用消息，详细信息仅写入服务端日志
- 🌍 **边缘加速** — 全部跑在 Cloudflare 全球网络，下载响应带 CDN 缓存头，就近分发。
- 📦 **零运行时依赖** — Worker 自身不依赖任何第三方库（dev deps 不计入）。

## 🏗️ 技术架构

| 层 | 技术 | 说明 |
| --- | --- | --- |
| 运行时 | Cloudflare Workers (workerd) | 边缘无服务器，处理所有 HTTP 请求 |
| 对象存储 | Cloudflare R2 | 存放文件内容（内容寻址 blob）与去重指针 |
| 元数据 | Cloudflare KV | 存放分享令牌、引用计数、登录限流记录 |
| 前端 | 内联 HTML / CSS / 原生 JS | 管理后台、分享页、登录页内联在 Worker 中 |
| 源码 | TypeScript (ESM) | `src/` 下按职责分模块，零运行时依赖 |
| 测试 | Vitest + `@cloudflare/vitest-pool-workers` | workerd runtime + R2/KV 真实绑定 |

**存储模型**：实际内容以 `__blob__/<sha256>` 为 key 存入 R2；每个可见文件是一个体积为 0、带 `sha256` 元数据的「指针」对象。`fhash:<sha256>` 记录在 KV 中维护引用计数，删除时计数归零才真正清除 blob，从而实现跨文件夹的去重与秒传。

## 📂 项目结构

```
cloudshare/
├── src/
│   ├── index.ts                 # Worker 入口
│   ├── router.ts                # 路由分发
│   ├── auth.ts                  # 登录 / 会话 / 限流
│   ├── crypto.ts                # PBKDF2 / HMAC / base64url / 常量时间比较
│   ├── encoding.ts              # URL 编码 / XSS 防御 / 文件名校验
│   ├── validation.ts            # 请求参数解析
│   ├── responses.ts             # Response 构造（Cache-Control / CORS）
│   ├── storage.ts               # R2 去重 + 引用计数生命周期
│   ├── download.ts              # Range 解析 / R2 流式下载
│   ├── upload.ts                # 单文件 / 分片上传 handler
│   ├── files.ts                 # 列表 / 删除 / 文件夹 handler
│   ├── share.ts                 # 分享 CRUD / 密码验证
│   ├── types.ts                 # 共享类型 (Env, ShareData, ...)
│   └── pages/                   # 内联 HTML 模板
│       ├── login.ts
│       ├── main.ts              # 管理主页
│       ├── manage.ts            # 分享管理页
│       ├── share.ts             # 访客分享页
│       └── not-found.ts
├── test/
│   └── integration.test.ts      # 公有 API 集成测试 (workerd + 真实 R2/KV)
├── wrangler.toml.template       # 部署配置模板（复制为 wrangler.toml 后填写）
├── wrangler.toml                # 本地 / CI 使用（gitignored）
├── vitest.config.ts             # Vitest + cloudflare pool 配置
├── tsconfig.json                # TypeScript 严格模式
├── package.json
└── LICENSE
```

## 🚀 部署指南

### 前置条件

- 一个 [Cloudflare 账号](https://dash.cloudflare.com/sign-up)（R2 需在面板中开通）
- **Node.js 22+**（wrangler 4.x 与 vitest 4.x 要求）
- **pnpm**（推荐；也可用 npm / yarn）

### 1. 克隆与安装

```bash
git clone https://github.com/b1ankcat/cloudshare.git
cd cloudshare
pnpm install
```

### 2. 登录 Cloudflare

```bash
pnpm exec wrangler login
```

### 3. 创建 R2 存储桶与 KV 命名空间

```bash
# 创建 R2 桶（存放文件内容）
pnpm exec wrangler r2 bucket create <bucket_name>

# 创建 KV 命名空间（存放分享元数据），记下返回的 id
pnpm exec wrangler kv namespace create cloudshare-shares
```

### 4. 配置 `wrangler.toml`

```bash
cp wrangler.toml.template wrangler.toml
```

填入上一步得到的资源名与 KV `id`，以及入口 `main = "src/index.ts"`。

> ⚠️ 绑定名称 `FILES_BUCKET` 与 `cloudshare_shares` 已在 `src/storage.ts` / `src/auth.ts` 等模块中引用，请勿改动。

### 5. 设置管理员密码（必需）

管理后台凭据来自 `ADMIN_PASSWORD` 这一 Secret，**未配置时后台无法登录**：

```bash
pnpm exec wrangler secret put ADMIN_PASSWORD
# 按提示输入一个高强度密码
```

### 6. 本地预览 / 部署上线

```bash
pnpm dev      # 本地开发预览 (wrangler dev)
pnpm ship     # 部署到 Cloudflare (wrangler deploy)
pnpm tail     # 实时查看线上日志
pnpm test     # 跑全部测试 (vitest run)
```

部署完成后访问 `https://cloudshare.<your-subdomain>.workers.dev`，使用 `ADMIN_PASSWORD` 登录即可进入管理后台。

### 7. （可选）限制 CORS 跨域来源

默认所有响应都不带 CORS 头（同源才能调用）。如需开放给特定前端域名：

```bash
pnpm exec wrangler secret put ALLOWED_ORIGIN
# 输入形如 https://share.example.com
# 留空表示继续走同源策略
```

## 🧭 使用说明

- **管理后台 `/`** — 上传、新建文件夹、下载、删除、发起分享。支持拖拽上传与多级目录。
- **分享管理 `/manage`** — 查看全部分享，续期、改密码、复制（免密）链接或取消。
- **分享页 `/s/:token`** — 访客访问入口；若设有密码会先要求验证。
- **下载 `/dl/:token`（文件）/ `/dl/:token/:filename`（文件夹内文件）** — 实际文件流，支持断点续传。

上传逻辑会根据文件大小自动选择策略：≤ 40 MB 走普通直传，更大的文件走 R2 分片并发上传；任意大小在上传前都会先做 SHA-256 指纹比对以触发秒传。

## ✅ 测试

```bash
pnpm test                # 全部 (214 用例)
pnpm test:unit           # 仅单元测试 (src/*.test.ts, 私有 API)
pnpm test:integration    # 仅集成测试 (test/*.test.ts, 公有 API)
pnpm test:watch          # watch 模式
pnpm typecheck           # TypeScript 严格类型检查
```

测试策略：

- **私有 API** (纯函数: `escapeHtml` / `jsAttrString` / `validateName` / `parseRangeHeader` / PBKDF2 / HMAC / Cookie 解析 / `isAdminRoute` ...) → 单元测试，adjacent `.test.ts` 文件
- **公有 API** (Worker `fetch` handler + 所有路由) → 集成测试，跑在 workerd runtime 中，使用真 R2 + KV 绑定

## 🔒 安全说明

- **务必设置高强度 `ADMIN_PASSWORD`**，它既是登录凭据，也是 HMAC 会话签名密钥。修改它会使所有已登录会话失效。
- 分享密码以 PBKDF2-SHA256（100,000 次迭代 + 16 字节随机盐）哈希存储，不保存明文。
- 登录失败按客户端 IP 限流（10 分钟内 5 次），缓解暴力破解。
- 会话 Cookie 为 `HttpOnly` + `SameSite=Lax`，HTTPS 下自动加 `Secure`，有效期 7 天。
- 会话时钟容差为 ±60 秒（避免过大导致重放窗口过宽）。
- 文件名 / 文件夹名在服务端严格校验，禁止 `< > : " ' | ? * \ /` 与控制字符；前端用 `jsAttrString`（`JSON.stringify` + HTML 实体转义）做防御性编码，杜绝 `escapeJsArg` 时代的 `"` 破属性 XSS。
- 「复制带密码链接」会把密码以明文 query 参数附在 URL 上以便免密访问，请仅在可信渠道分发此类链接。
- 错误响应只返回通用消息（`服务器内部错误`），内部异常仅写入 `console.error`，不向客户端泄露 R2/KV 路径或 API 版本。

## 🤝 参与贡献

欢迎提交 Issue 与 Pull Request。提交前请确保：

1. `pnpm typecheck` 通过
2. `pnpm test` 全部通过（包括你的新测试）
3. 新增/修改的私有 API 有单元测试，新增/修改的公有 API 有集成测试
4. 不引入 fallback / 兼容代码 / 静默失败 —— 错误应当明确抛出

## 📜 开源协议

本项目基于 **[GPL-3.0-only](./LICENSE)** 协议开源。你可以自由使用、修改和分发，但衍生作品须以相同协议开源。

---

<div align="center">

用 ☁️ Cloudflare Workers + R2 构建 · 如果这个项目对你有帮助，欢迎点亮 ⭐

</div>
