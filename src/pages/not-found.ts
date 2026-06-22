/** 404 page rendered for unknown routes. */

import { escapeHtml } from "../encoding";

export function notFoundHTML(message = "页面不存在"): string {
  const safe = escapeHtml(message);
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${safe} - CloudShare</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #f0f2f5; color: #1e293b; }
  .error-card { text-align: center; }
  .error-card .icon { font-size: 64px; }
  .error-card h2 { font-size: 24px; margin: 16px 0; }
  .error-card p { color: #64748b; }
  .error-card a { color: #3b82f6; text-decoration: none; }
</style>
</head>
<body>
<div class="error-card">
  <div class="icon">🔗</div>
  <h2>${safe}</h2>
  <p>分享链接可能已过期，或文件已被删除。</p>
  <p><a href="/">→ 返回 CloudShare 主页</a></p>
</div>
</body>
</html>`;
}
