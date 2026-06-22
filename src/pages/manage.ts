/** HTML template for the share-management standalone page (/manage). */

import { SHARED_JS } from "./login";

export function managePageHTML(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>分享管理 - CloudShare</title>
<style>
  :root {
    --bg: #f0f2f5; --surface: #fff; --primary: #3b82f6; --primary-hover: #2563eb;
    --danger: #ef4444; --text: #1e293b; --text-secondary: #64748b; --border: #e2e8f0;
    --radius: 12px; --radius-sm: 8px;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
  .topbar { background:var(--surface); border-bottom:1px solid var(--border); padding:16px 32px; display:flex; align-items:center; justify-content:space-between; }
  .topbar h1 { font-size:20px; display:flex; align-items:center; gap:8px; }
  .topbar a { color:var(--primary); text-decoration:none; font-size:14px; }
  .container { max-width:1100px; margin:24px auto; padding:0 24px; }
  .shares-table { width:100%; border-collapse:collapse; background:var(--surface); border-radius:var(--radius); overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.06); }
  .shares-table th { text-align:left; padding:12px 16px; background:#f8fafc; border-bottom:2px solid var(--border); font-size:12px; text-transform:uppercase; color:var(--text-secondary); letter-spacing:0.5px; }
  .shares-table td { padding:14px 16px; border-bottom:1px solid var(--border); font-size:14px; }
  .shares-table tr:hover td { background:#f8fafc; }
  .badge { display:inline-block; padding:2px 10px; border-radius:10px; font-size:11px; font-weight:500; }
  .badge-active { background:#dcfce7; color:#166534; }
  .badge-expired { background:#fef2f2; color:#991b1b; }
  .badge-file { background:#eff6ff; color:#1d4ed8; }
  .badge-folder { background:#fefce8; color:#854d0e; }
  .btn-icon { width:36px; height:36px; border:none; background:transparent; border-radius:8px; cursor:pointer; font-size:17px; display:inline-flex; align-items:center; justify-content:center; transition:background 0.15s; margin:0 1px; }
  .btn-icon:hover { background:#f1f5f9; }
  .btn-icon.danger:hover { background:#fef2f2; }
  .btn { padding:8px 16px; border:none; border-radius:var(--radius-sm); cursor:pointer; font-size:13px; font-weight:500; }
  .btn-outline { background:#fff; color:var(--text); border:1px solid var(--border); }
  .btn-outline:hover { background:var(--bg); }
  .btn-primary { background:var(--primary); color:#fff; }
  .btn-primary:hover { background:var(--primary-hover); }
  .btn-danger { background:var(--danger); color:#fff; }
  .empty-state { text-align:center; padding:60px; color:var(--text-secondary); }
  .toast-container { position:fixed; bottom:24px; right:24px; z-index:200; }
  .toast { padding:12px 20px; background:#1e293b; color:#f1f5f9; border-radius:var(--radius-sm); font-size:13px; margin-top:8px; }
  .toast.success { border-left:3px solid #22c55e; }
  .toast.error { border-left:3px solid #ef4444; }
  .modal-overlay { position:fixed; top:0;left:0;right:0;bottom:0; background:rgba(0,0,0,0.5); display:flex; align-items:center; justify-content:center; z-index:100; }
  .modal { background:var(--surface); border-radius:var(--radius); padding:28px; max-width:440px; width:90vw; }
  .modal h3 { margin-bottom:12px; }
  .modal-actions { display:flex; gap:8px; margin-top:16px; justify-content:flex-end; }
  .dialog-input { width:100%; padding:10px 14px; border:2px solid var(--border); border-radius:var(--radius-sm); font-size:14px; outline:none; margin:8px 0; }
  .dialog-input:focus { border-color:var(--primary); }
  .dialog-text { font-size:14px; line-height:1.5; }
  @media (max-width:768px) { .topbar { padding:12px 16px; } .container { padding:0 12px; margin-top:12px; } .shares-table { font-size:12px; } .shares-table th,.shares-table td { padding:8px 10px; } }
</style>
</head>
<body>
<div class="topbar">
  <h1><span>☁</span> CloudShare <span style="font-size:14px;color:var(--text-secondary);font-weight:400;">分享管理</span></h1>
  <div style="display:flex;gap:8px;align-items:center;">
    <a href="/" class="btn btn-outline" style="text-decoration:none;">文件管理</a>
    <a href="/api/logout" class="btn btn-outline" style="text-decoration:none;">退出登录</a>
  </div>
</div>
<div class="container">
  <div id="sharesTable"></div>
</div>
<div class="toast-container" id="toastContainer"></div>
<div class="modal-overlay" id="genericDialog" style="display:none;">
  <div class="modal"><h3 id="dialogTitle"></h3><div id="dialogContent" style="margin:12px 0;"></div><div class="modal-actions" id="dialogActions"></div></div>
</div>
<script>
${SHARED_JS}
async function loadShares(){
  try{
    const res=await fetch('/api/shares');
    const data=await res.json();
    const shares=data.shares||[];
    const el=document.getElementById('sharesTable');
    if(!shares.length){el.innerHTML='<div class="empty-state"><div style="font-size:48px;">📭</div><p style="margin-top:12px;">暂无分享链接</p></div>';return}
    let h='<table class="shares-table"><thead><tr><th>名称</th><th>类型</th><th>过期时间</th><th>密码</th><th>状态</th><th>操作</th></tr></thead><tbody>';
    for(const s of shares){
      const expired=s.expiresAt&&new Date(s.expiresAt)<new Date();
      h+='<tr><td><strong>'+esc(s.name)+'</strong></td>'
        +'<td><span class="badge '+(s.type==='folder'?'badge-folder':'badge-file')+'">'+(s.type==='folder'?'📂 文件夹':'📄 文件')+'</span></td>'
        +'<td>'+(s.expiresAt?new Date(s.expiresAt).toLocaleString():'<span style="color:var(--text-secondary);">永不过期</span>')+'</td>'
        +'<td>'+(s.hasPassword?'🔒 已设':'<span style="color:var(--text-secondary);">—</span>')+'</td>'
        +'<td>'+(expired?'<span class="badge badge-expired">已过期</span>':'<span class="badge badge-active">有效</span>')+'</td>'
        +'<td style="white-space:nowrap;">'
        +'<button class="btn-icon" onclick="copyUrl(\\''+s.token+'\\')" title="复制链接">🔗</button>'
        +(s.hasPassword?'<button class="btn-icon" onclick="copyUrlWithPw(\\''+s.token+'\\')" title="复制带密码链接">🔐</button>':'')
        +'<button class="btn-icon" onclick="extendShare(\\''+s.token+'\\')" title="续期">🔄</button>'
        +'<button class="btn-icon" onclick="changePw(\\''+s.token+'\\')" title="修改密码">🔑</button>'
        +'<button class="btn-icon danger" onclick="cancelSh(\\''+s.token+'\\')" title="取消分享">❌</button>'
        +'</td></tr>';
    }
    h+='</tbody></table>';
    el.innerHTML=h;
  }catch(e){toast('加载失败','error')}
}

function copyUrl(token){copyToClipboard(location.origin+'/s/'+token);toast('链接已复制','success')}
async function copyUrlWithPw(token){
  const r=await showDialog({title:'🔐 输入密码',type:'text',placeholder:'输入此分享的密码',content:'输入密码后生成带密码的链接',buttons:[{text:'取消',cls:'outline',value:null},{text:'复制',cls:'primary',value:'ok'}]});
  if(r&&r.value==='ok'&&r.input){copyToClipboard(location.origin+'/s/'+token+'?pw='+encodeURIComponent(r.input));toast('带密码链接已复制','success')}
}
async function extendShare(token){
  const r=await showDialog({title:'🔄 续期',type:'number',placeholder:'天数 (0=永不过期)',value:'30',buttons:[{text:'取消',cls:'outline',value:null},{text:'续期',cls:'primary',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  const days=r.input;const ei=days&&parseInt(days)>0?parseInt(days)*86400:null;
  const res=await fetch('/api/share/'+token,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'extend',expiresIn:ei})});
  const d=await res.json();
  if(d.success){toast('续期成功','success');loadShares()}else toast(d.error,'error')
}
async function changePw(token){
  const r=await showDialog({title:'🔑 修改密码',type:'text',placeholder:'新密码 (留空=移除)',buttons:[{text:'取消',cls:'outline',value:null},{text:'保存',cls:'primary',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  const res=await fetch('/api/share/'+token,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'password',password:r.input||null})});
  const d=await res.json();
  if(d.success){toast(r.input?'密码已设置':'密码已移除','success');loadShares()}else toast(d.error,'error')
}
async function cancelSh(token){
  const r=await showDialog({title:'❌ 取消分享',content:'确定取消此分享？',buttons:[{text:'保留',cls:'outline',value:null},{text:'确认取消',cls:'danger',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  await fetch('/api/share/'+token,{method:'DELETE'});
  toast('已取消','success');loadShares()
}
loadShares();
</script>
</body>
</html>`;
}
