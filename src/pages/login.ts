/** HTML template for the admin login page. */

import { escapeHtml } from "../encoding";
import { safeNextPath } from "../auth";
import type { Env } from "../types";

export function loginPageHTML(env: Env, next = "/", error = ""): string {
  const safeNext = escapeHtml(safeNextPath(next));
  const safeError = escapeHtml(error);
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - CloudShare</title>
<style>
  :root { --ink:#17211b; --muted:#647067; --line:#d9e1d8; --paper:#fffdf6; --field:#f7f3e8; --accent:#2f6f4e; --accent2:#d97706; --danger:#b91c1c; }
  * { box-sizing:border-box; }
  body { min-height:100vh; margin:0; display:grid; place-items:center; font-family: ui-serif, Georgia, "Times New Roman", serif; color:var(--ink); background:radial-gradient(circle at 20% 15%, #f8e9bc 0 18%, transparent 19%), radial-gradient(circle at 80% 10%, #cfe8d8 0 16%, transparent 17%), linear-gradient(135deg,#eef5e9,#fbf3dc 55%,#efe2c2); }
  .login-card { width:min(420px, calc(100vw - 32px)); padding:34px; background:rgba(255,253,246,.9); border:1px solid rgba(47,111,78,.18); border-radius:28px; box-shadow:0 28px 80px rgba(45,55,72,.18); backdrop-filter:blur(16px); }
  .brand { display:flex; align-items:center; gap:12px; margin-bottom:28px; }
  .mark { width:48px; height:48px; border-radius:16px; display:grid; place-items:center; color:white; font-size:24px; background:linear-gradient(135deg,var(--accent),#8a9f45); box-shadow:0 12px 28px rgba(47,111,78,.28); }
  h1 { margin:0; font-size:28px; letter-spacing:-.03em; }
  p { margin:6px 0 0; color:var(--muted); font-size:14px; line-height:1.6; }
  label { display:block; margin:22px 0 8px; font-size:13px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; color:#365143; }
  input { width:100%; border:1px solid var(--line); border-radius:16px; padding:15px 16px; background:var(--field); color:var(--ink); font:inherit; outline:none; }
  input:focus { border-color:var(--accent); box-shadow:0 0 0 4px rgba(47,111,78,.12); background:white; }
  button { width:100%; margin-top:18px; border:0; border-radius:16px; padding:15px 16px; cursor:pointer; color:white; font:700 15px ui-sans-serif, system-ui, sans-serif; background:linear-gradient(135deg,var(--accent),#7f8f2d); box-shadow:0 14px 32px rgba(47,111,78,.24); }
  .error { margin:0 0 16px; padding:12px 14px; border-radius:14px; background:#fee2e2; color:var(--danger); font:600 13px ui-sans-serif, system-ui, sans-serif; }
  .hint { margin-top:16px; text-align:center; font:12px ui-sans-serif, system-ui, sans-serif; color:var(--muted); }
</style>
</head>
<body>
  <main class="login-card">
    <div class="brand">
      <div class="mark">☁</div>
      <div>
        <h1>CloudShare</h1>
        <p>输入管理员密码后继续访问。</p>
      </div>
    </div>
    ${safeError ? `<div class="error">${safeError}</div>` : ""}
    <form method="POST" action="/api/login">
      <input type="hidden" name="next" value="${safeNext}">
      <label for="credential">管理员凭据</label>
      <input id="credential" name="credential" type="password" autocomplete="current-password" autofocus required placeholder="ADMIN_PASSWORD">
      <button type="submit">进入管理后台</button>
    </form>
    <div class="hint">登录状态保存在 HttpOnly Cookie 中，有效期 7 天。</div>
  </main>
</body>
</html>`;
}

/** Minimal CSS+JS used by every page that shows a toast / uses a dialog. */
export const SHARED_JS = `function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML.replace(/'/g,'&#39;');}
function toast(m,t){const c=document.getElementById('toastContainer');const e=document.createElement('div');e.className='toast '+t;e.textContent=m;c.appendChild(e);setTimeout(()=>e.remove(),3000);}
function copyToClipboard(t){if(navigator.clipboard){navigator.clipboard.writeText(t)}else{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');document.body.removeChild(a)}}
function showDialog(o){return new Promise(r=>{const ov=document.getElementById('genericDialog');const done=v=>{ov.style.display='none';ov.onclick=null;r(v)};ov.onclick=e=>{if(e.target===ov)done({value:null,input:null,cancelled:true})};document.getElementById('dialogTitle').textContent=o.title||'';const ce=document.getElementById('dialogContent');if(o.type==='text'||o.type==='number'){ce.innerHTML='<input type="'+o.type+'" class="dialog-input" id="dialogInput" placeholder="'+esc(o.placeholder||'')+'" value="'+esc(o.value||'')+'" autofocus onkeydown="if(event.key===\\'Enter\\')document.getElementById(\\'dialogBtn0\\').click()">'}else{ce.innerHTML='<p class="dialog-text">'+esc(o.content||'')+'</p>'}const ae=document.getElementById('dialogActions');ae.innerHTML='';(o.buttons||[{text:'确定',cls:'primary',value:true}]).forEach((b,i)=>{const btn=document.createElement('button');btn.id='dialogBtn'+i;btn.className='btn btn-'+(b.cls||'primary');btn.textContent=b.text;btn.onclick=()=>{const inp=document.getElementById('dialogInput');done({value:b.value,input:inp?inp.value:null})};ae.appendChild(btn)});ov.style.display='flex';setTimeout(()=>{const inp=document.getElementById('dialogInput');if(inp)inp.focus()},100)})}`;
