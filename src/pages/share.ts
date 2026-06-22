/** HTML template for the public share access page (/s/:token). */

export function sharePageHTML(token: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudShare</title>
<style>
  :root {
    --bg: #f0f2f5; --surface: #ffffff; --primary: #3b82f6; --primary-hover: #2563eb;
    --danger: #ef4444; --text: #1e293b; --text-secondary: #64748b; --border: #e2e8f0;
    --radius: 16px; --radius-sm: 10px;
    --shadow: 0 4px 16px rgba(0,0,0,0.06), 0 1px 4px rgba(0,0,0,0.04);
    --shadow-lg: 0 12px 40px rgba(0,0,0,0.1);
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .card { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow-lg); max-width: 640px; width: 100%; overflow: hidden; animation: slideUp 0.3s ease; }
  .card-header { background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); padding: 32px 28px; color: #fff; text-align: center; }
  .card-header .share-icon { font-size: 48px; display: block; margin-bottom: 8px; }
  .card-header h2 { font-size: 22px; font-weight: 700; word-break: break-all; }
  .card-header .share-meta { font-size: 13px; opacity: 0.85; margin-top: 6px; }
  .card-body { padding: 24px 28px; }
  .card-footer { text-align: center; padding: 16px 28px 28px; color: var(--text-secondary); font-size: 12px; }
  .file-table { width: 100%; border-collapse: collapse; }
  .file-table th { text-align: left; font-size: 11px; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; padding: 8px 12px; border-bottom: 2px solid var(--border); }
  .file-table td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  .file-table tr:last-child td { border-bottom: none; }
  .file-table tr:hover td { background: #f8fafc; }
  .file-icon { font-size: 28px; margin-right: 10px; vertical-align: middle; }
  .file-name { font-size: 14px; font-weight: 500; vertical-align: middle; word-break: break-all; color: var(--text); }
  .size-col { color: var(--text-secondary); font-size: 13px; white-space: nowrap; width: 80px; }
  .action-col { text-align: right; width: 100px; }
  .btn-download { display: inline-block; padding: 8px 18px; background: var(--primary); color: #fff; text-decoration: none; border-radius: 20px; font-size: 13px; font-weight: 500; transition: all 0.2s; border: none; cursor: pointer; white-space: nowrap; }
  .btn-download:hover { background: var(--primary-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.3); }
  .big-download { display: block; width: 100%; padding: 16px; background: var(--primary); color: #fff; text-align: center; text-decoration: none; border-radius: var(--radius-sm); font-size: 16px; font-weight: 600; margin-top: 8px; transition: all 0.2s; border: none; cursor: pointer; }
  .big-download:hover { background: var(--primary-hover); transform: translateY(-2px); box-shadow: 0 8px 24px rgba(59,130,246,0.3); }
  .pw-form { text-align: center; padding: 8px 0; }
  .pw-form h3 { font-size: 16px; margin-bottom: 16px; color: var(--text); }
  .pw-input { width: 100%; padding: 12px 16px; border: 2px solid var(--border); border-radius: var(--radius-sm); font-size: 15px; text-align: center; outline: none; transition: border-color 0.2s; letter-spacing: 2px; }
  .pw-input:focus { border-color: var(--primary); }
  .pw-error { color: var(--danger); font-size: 13px; margin-top: 8px; display: none; }
  .pw-submit { margin-top: 16px; width: 100%; padding: 12px; background: var(--primary); color: #fff; border: none; border-radius: var(--radius-sm); font-size: 15px; font-weight: 500; cursor: pointer; transition: background 0.2s; }
  .pw-submit:hover { background: var(--primary-hover); }
  .pw-submit:disabled { opacity: 0.6; cursor: not-allowed; }
  .status-box { text-align: center; padding: 20px; }
  .status-box .icon { font-size: 56px; }
  .status-box h3 { margin: 12px 0 6px; font-size: 18px; }
  .status-box p { color: var(--text-secondary); font-size: 14px; }
  .status-box .expiry-note { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }
  .loader { display: inline-block; width: 36px; height: 36px; border: 3px solid var(--border); border-top-color: var(--primary); border-radius: 50%; animation: spin 0.6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes slideUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
  @media (max-width: 500px) { .card-header { padding: 24px 16px; } .card-body { padding: 16px; } .file-table { font-size: 12px; } .btn-download { padding: 6px 14px; font-size: 12px; } }
</style>
</head>
<body>
<div class="card">
  <div id="cardContent"></div>
  <div class="card-footer">Powered by <strong>CloudShare</strong></div>
</div>
<script>
const TOKEN = ${JSON.stringify(token)};
let SHARE_PASSWORD = new URLSearchParams(window.location.search).get('pw') || '';

function shareQuery() {
  return SHARE_PASSWORD ? '?pw=' + encodeURIComponent(SHARE_PASSWORD) : '';
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML.replace(/'/g, '&#39;');
}

function fmtSize(b) {
  if (!b || b === 0) return '0 B';
  const u = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(b)/Math.log(1024));
  return (b/Math.pow(1024,i)).toFixed(i>0?1:0) + ' ' + u[i];
}

function fileEmoji(n) {
  const ext = (n||'').split('.').pop()?.toLowerCase();
  const m = {jpg:'🖼',jpeg:'🖼',png:'🖼',gif:'🖼',webp:'🖼',svg:'🖼',pdf:'📕',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',ppt:'📽',pptx:'📽',zip:'📦',rar:'📦','7z':'📦',gz:'📦',mp3:'🎵',wav:'🎵',flac:'🎵',mp4:'🎬',avi:'🎬',mov:'🎬',mkv:'🎬',js:'💛',ts:'💙',py:'🐍',html:'🌐',css:'🎨',json:'📋',txt:'📄',md:'📝'};
  return m[ext] || '📎';
}

function renderLoading() {
  document.getElementById('cardContent').innerHTML = '<div class="card-header"><span class="share-icon">☁</span><h2>CloudShare</h2></div><div class="card-body"><div class="status-box"><div class="loader"></div><p style="margin-top:12px;">加载中...</p></div></div>';
}

function renderExpired(name) {
  document.getElementById('cardContent').innerHTML = '<div class="card-header"><span class="share-icon">⏰</span><h2>' + esc(name) + '</h2></div><div class="card-body"><div class="status-box"><div class="icon">⏰</div><h3>分享已过期</h3><p>此分享链接已超过有效期，请联系分享者重新获取。</p></div></div>';
}

function renderNotFound(msg) {
  document.getElementById('cardContent').innerHTML = '<div class="card-header"><span class="share-icon">🔗</span><h2>链接无效</h2></div><div class="card-body"><div class="status-box"><div class="icon">🔗</div><h3>' + esc(msg||'分享不存在') + '</h3><p>分享链接可能已被删除或从未存在。</p></div></div>';
}

function renderPasswordForm(name) {
  document.getElementById('cardContent').innerHTML = '<div class="card-header"><span class="share-icon">🔒</span><h2>' + esc(name) + '</h2><div class="share-meta">此分享需要密码访问</div></div><div class="card-body"><div class="pw-form"><h3>请输入访问密码</h3><input type="password" class="pw-input" id="pwInput" placeholder="输入密码" autofocus onkeydown="if(event.key===\\'Enter\\')verifyAndShow()"><div class="pw-error" id="pwError">密码错误，请重试</div><button class="pw-submit" id="pwSubmit" onclick="verifyAndShow()">🔓 验证并访问</button></div></div>';
}

async function verifyAndShow() {
  const pw = document.getElementById('pwInput').value;
  const btn = document.getElementById('pwSubmit');
  const err = document.getElementById('pwError');
  if (!pw) { err.style.display = 'block'; err.textContent = '请输入密码'; return; }
  btn.disabled = true;
  btn.textContent = '验证中...';
  try {
    const res = await fetch('/api/share/' + TOKEN + '/verify', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: pw}) });
    const data = await res.json();
    if (data.valid) {
      SHARE_PASSWORD = pw;
      await loadAndRender();
    } else {
      err.style.display = 'block';
      err.textContent = data.expired ? '分享已过期' : '密码错误，请重试';
      btn.disabled = false;
      btn.textContent = '🔓 验证并访问';
    }
  } catch (e) {
    err.style.display = 'block';
    err.textContent = '验证失败，请重试';
    btn.disabled = false;
    btn.textContent = '🔓 验证并访问';
  }
}

function renderFiles(shareData) {
  const { type, name, files } = shareData;
  const token = TOKEN;
  const expiryInfo = shareData.expiresAt
    ? (new Date(shareData.expiresAt) < new Date()
      ? '<span style="color:#fbbf24;">已过期</span>'
      : '将在 ' + new Date(shareData.expiresAt).toLocaleString() + ' 过期')
    : '永不过期';
  let bodyHtml = '';
  if (type === 'file' && files.length === 1) {
    bodyHtml = '<div style="text-align:center;">'
      + '<div style="font-size:64px;padding:24px;">' + fileEmoji(files[0].name) + '</div>'
      + '<div style="color:var(--text-secondary);margin-bottom:8px;">' + fmtSize(files[0].size) + '</div>'
      + '<a href="/dl/' + token + shareQuery() + '" class="big-download">⬇ 下载文件</a>'
      + '</div>';
  } else {
    bodyHtml = (type === 'folder' && files.length > 1
      ? '<div style="margin-bottom:16px;text-align:right;"><span style="font-size:13px;color:var(--text-secondary);">共 ' + files.length + ' 个文件 — 请逐个下载</span></div>'
      : '');
    bodyHtml += '<table class="file-table"><thead><tr><th>文件名</th><th>大小</th><th></th></tr></thead><tbody>';
    for (const f of files) {
      const dlUrl = type === 'file'
        ? '/dl/' + token + shareQuery()
        : '/dl/' + token + '/' + encodeURIComponent(f.name) + shareQuery();
      bodyHtml += '<tr><td><span class="file-icon">' + fileEmoji(f.name) + '</span><span class="file-name">' + esc(f.name) + '</span></td><td class="size-col">' + fmtSize(f.size) + '</td><td class="action-col"><a href="' + dlUrl + '" class="btn-download" download>⬇ 下载</a></td></tr>';
    }
    bodyHtml += '</tbody></table>';
  }
  document.getElementById('cardContent').innerHTML =
    '<div class="card-header">'
    + '<span class="share-icon">' + (type === 'folder' ? '📂' : '📄') + '</span>'
    + '<h2>' + esc(name) + '</h2>'
    + '<div class="share-meta">' + (type === 'folder' ? '共享文件夹' : '共享文件') + ' · ' + files.length + ' 个文件 · ' + expiryInfo + '</div>'
    + '</div>'
    + '<div class="card-body">' + bodyHtml + '</div>';
}

async function loadAndRender() {
  renderLoading();
  try {
    const res = await fetch('/api/share/' + TOKEN + shareQuery());
    if (res.status === 404) {
      const data = await res.json();
      renderNotFound(data.error);
      return;
    }
    const data = await res.json();
    if (data.error) {
      renderNotFound(data.error);
      return;
    }
    if (data.expired) {
      renderExpired(data.name);
      return;
    }
    if (data.hasPassword) {
      if (data.passwordRequired) {
        const urlParams = new URLSearchParams(window.location.search);
        const pwFromUrl = urlParams.get('pw');
        if (pwFromUrl) {
          const vRes = await fetch('/api/share/' + TOKEN + '/verify', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: pwFromUrl}) });
          const vData = await vRes.json();
          if (vData.valid) {
            SHARE_PASSWORD = pwFromUrl;
            if (window.history && window.history.replaceState) {
              window.history.replaceState({}, '', '/s/' + TOKEN);
            }
            await loadAndRender();
            return;
          } else {
            renderPasswordForm(data.name);
            return;
          }
        } else {
          renderPasswordForm(data.name);
          return;
        }
      }
    }
    renderFiles(data);
  } catch (e) {
    renderNotFound('加载失败');
  }
}

loadAndRender();
</script>
</body>
</html>`;
}
