/**
 * Admin file-management page (/).
 *
 * Front-end security notes:
 *   - File/folder names are escaped with esc() for HTML text content and
 *     jsAttrString() for inline event handler arguments. jsAttrString
 *     combines JSON.stringify (valid JS literal) with HTML entity
 *     encoding (safe inside an attribute value).
 *   - The server rejects file/folder names containing <, >, ", |, ?, *,
 *     \, / or control characters, so XSS payloads cannot reach this
 *     page in the first place. The escaping here is defense in depth.
 */

import { jsAttrString } from "../encoding";

export function mainPageHTML(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudShare - 文件分享管理</title>
<style>
  :root { --bg: #f0f2f5; --surface: #fff; --primary: #3b82f6; --primary-hover: #2563eb; --danger: #ef4444; --danger-hover: #dc2626; --success: #22c55e; --text: #1e293b; --text-secondary: #64748b; --border: #e2e8f0; --radius: 12px; --radius-sm: 8px; --shadow-lg: 0 10px 25px rgba(0,0,0,0.1); --transition: 0.2s ease; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); display:flex; flex-direction:column; height:100vh; overflow:hidden; }
  .topbar { background:var(--surface); border-bottom:1px solid var(--border); padding:14px 32px; display:flex; align-items:center; justify-content:space-between; flex-shrink:0; }
  .breadcrumb { display:flex; align-items:center; gap:4px; font-size:15px; flex-wrap:wrap; }
  .breadcrumb a { color:var(--primary); text-decoration:none; padding:2px 6px; border-radius:4px; transition:background var(--transition); white-space:nowrap; }
  .breadcrumb a:hover { background:#eff6ff; }
  .breadcrumb .sep { color:var(--text-secondary); user-select:none; }
  .breadcrumb .current { font-weight:600; color:var(--text); padding:2px 6px; }
  .topbar-actions { display:flex; gap:8px; }
  .upload-progress { margin:0 32px; padding:12px 16px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); display:none; flex-shrink:0; }
  .upload-progress.show { display:block; }
  .progress-bar { height:6px; background:var(--border); border-radius:3px; overflow:hidden; margin-top:6px; }
  .progress-fill { height:100%; background:var(--primary); border-radius:3px; transition:width 0.3s ease; width:0%; }
  .file-grid-wrap { flex:1; overflow-y:auto; padding:24px 32px; }
  .file-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(180px, 1fr)); gap:12px; align-content:start; }
  .file-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:16px; cursor:default; transition:all var(--transition); display:flex; flex-direction:column; gap:8px; position:relative; }
  .file-card:hover { box-shadow:var(--shadow-lg); border-color:#94a3b8; }
  .file-card .file-icon { font-size:36px; text-align:center; }
  .file-card .file-name { font-size:13px; font-weight:500; text-align:center; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .file-card .file-meta { font-size:11px; color:var(--text-secondary); text-align:center; }
  .file-card .card-actions { display:flex; gap:4px; justify-content:center; }
  .add-card { background:var(--surface); border:2px dashed #cbd5e1; border-radius:var(--radius); padding:16px; cursor:pointer; transition:all var(--transition); display:flex; flex-direction:column; align-items:center; justify-content:center; gap:6px; min-height:160px; position:relative; }
  .add-card:hover { border-color:var(--primary); background:#f8faff; }
  .add-card .add-icon { font-size:40px; color:var(--primary); }
  .add-card .add-text { font-size:13px; color:var(--text-secondary); }
  .add-popup { display:none; position:absolute; top:100%; left:0; margin-top:4px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); box-shadow:var(--shadow-lg); z-index:50; min-width:180px; overflow:hidden; }
  .add-popup.show { display:block; }
  .add-popup-item { display:flex; align-items:center; gap:10px; padding:12px 16px; cursor:pointer; font-size:14px; transition:background var(--transition); border:none; background:none; width:100%; text-align:left; }
  .add-popup-item:hover { background:var(--bg); }
  .add-popup-item .popup-icon { font-size:20px; }
  .btn-icon { width:32px; height:32px; border:none; background:transparent; border-radius:6px; cursor:pointer; font-size:16px; display:inline-flex; align-items:center; justify-content:center; transition:background var(--transition); }
  .btn-icon:hover { background:var(--bg); }
  .btn-icon.danger:hover { background:#fef2f2; color:var(--danger); }
  .btn { padding:8px 16px; border:none; border-radius:var(--radius-sm); cursor:pointer; font-size:13px; font-weight:500; transition:all var(--transition); display:inline-flex; align-items:center; gap:6px; }
  .btn-primary { background:var(--primary); color:#fff; }
  .btn-primary:hover { background:var(--primary-hover); }
  .btn-danger { background:var(--danger); color:#fff; }
  .btn-danger:hover { background:var(--danger-hover); }
  .btn-outline { background:#fff; color:var(--text); border:1px solid var(--border); }
  .btn-outline:hover { background:var(--bg); }
  .btn-sm { padding:6px 10px; font-size:12px; }
  .modal-overlay { position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.5); display:flex; align-items:center; justify-content:center; z-index:100; animation:fadeIn 0.15s ease; }
  .modal { background:var(--surface); border-radius:var(--radius); padding:28px; width:480px; max-width:90vw; box-shadow:var(--shadow-lg); animation:slideUp 0.2s ease; }
  .modal h3 { font-size:18px; margin-bottom:12px; }
  .modal .share-url { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:var(--radius-sm); font-size:13px; background:var(--bg); margin:12px 0; font-family:monospace; }
  .modal .modal-actions { display:flex; gap:8px; margin-top:16px; justify-content:flex-end; }
  @keyframes fadeIn { from{opacity:0} to{opacity:1} }
  @keyframes slideUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
  .dialog-input { width:100%; padding:10px 14px; border:2px solid var(--border); border-radius:var(--radius-sm); font-size:14px; outline:none; margin:8px 0; }
  .dialog-input:focus { border-color:var(--primary); }
  .dialog-text { font-size:14px; line-height:1.5; }
  .toast-container { position:fixed; bottom:24px; right:24px; display:flex; flex-direction:column; gap:8px; z-index:200; }
  .toast { padding:12px 20px; background:#1e293b; color:#f1f5f9; border-radius:var(--radius-sm); font-size:13px; box-shadow:var(--shadow-lg); animation:slideUp 0.2s ease; }
  .toast.success { border-left:3px solid var(--success); }
  .toast.error { border-left:3px solid var(--danger); }
  .form-group { margin-bottom:14px; }
  .form-label { display:block; font-size:13px; font-weight:500; margin-bottom:4px; }
  .form-hint { font-weight:400; color:var(--text-secondary); font-size:12px; }
  .form-input { width:100%; padding:8px 12px; border:1px solid var(--border); border-radius:6px; font-size:13px; font-family:inherit; outline:none; }
  .form-input:focus { border-color:var(--primary); box-shadow:0 0 0 2px rgba(59,130,246,0.1); }
  .input-row { display:flex; gap:6px; }
  .input-row .form-input { flex:1; }
  select.form-input { cursor:pointer; background:#fff; }
  .share-info-row { display:flex; gap:8px; padding:4px 0; font-size:13px; }
  .info-label { color:var(--text-secondary); min-width:50px; }
  .share-badge { position:absolute; top:8px; right:8px; background:var(--success); color:#fff; font-size:10px; padding:2px 8px; border-radius:10px; font-weight:600; pointer-events:none; }
  .empty-state { grid-column:1/-1; text-align:center; padding:60px 20px; color:var(--text-secondary); }
  .file-card.selected { border-color:var(--primary); background:#eff6ff; }
  .empty-state .empty-icon { font-size:56px; margin-bottom:12px; }
  @media (max-width:768px) { .topbar { padding:12px 16px; } .file-grid-wrap { padding:16px; } .file-grid { grid-template-columns:repeat(auto-fill, minmax(140px, 1fr)); } }
</style>
</head>
<body>
<div class="topbar">
  <div class="breadcrumb" id="breadcrumb"></div>
  <div class="topbar-actions">
    <a href="/manage" class="btn btn-outline" style="text-decoration:none;">🔗 管理分享</a>
    <a href="/api/logout" class="btn btn-outline" style="text-decoration:none;">退出登录</a>
  </div>
</div>
<div class="upload-progress" id="uploadProgress">
  <div style="display:flex;align-items:center;justify-content:space-between;">
    <span id="uploadStatus" style="font-size:13px;">准备上传...</span>
    <button class="btn btn-sm btn-outline" id="btnCancelUpload" style="display:none;color:var(--danger);" onclick="cancelUpload()">✕ 取消</button>
  </div>
  <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
</div>
<div class="file-grid-wrap" id="fileGridWrap">
  <div class="file-grid" id="fileGrid">
    <div class="add-card" id="addCard" onclick="toggleAddPopup(event)">
      <div class="add-icon">＋</div>
      <div class="add-text">新建或上传</div>
      <div class="add-popup" id="addPopup">
        <button class="add-popup-item" onclick="event.stopPropagation();createFolder()"><span class="popup-icon">📁</span> 新建文件夹</button>
        <button class="add-popup-item" onclick="event.stopPropagation();triggerUpload()"><span class="popup-icon">📤</span> 上传文件</button>
      </div>
    </div>
  </div>
</div>
<input type="file" id="fileInput" multiple style="display:none;">
<div class="toast-container" id="toastContainer"></div>
<div class="modal-overlay" id="shareModal" style="display:none;">
  <div class="modal">
    <h3 id="shareModalTitle">🔗 分享</h3>
    <div id="shareTargetName" style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;"></div>
    <input type="text" id="shareUrlInput" class="share-url" readonly style="display:none;">
    <div id="shareCreateForm">
      <div class="form-group">
        <label class="form-label">密码 <span class="form-hint">(可选)</span></label>
        <div class="input-row">
          <input type="text" id="sharePassword" class="form-input" placeholder="留空表示无密码">
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">有效期</label>
        <select id="shareExpiry" class="form-input" onchange="onExpiryChange()">
          <option value="3600">1 小时</option>
          <option value="86400" selected>24 小时</option>
          <option value="604800">7 天</option>
          <option value="2592000">30 天</option>
          <option value="">永久</option>
          <option value="custom">自定义...</option>
        </select>
        <div id="customExpiryWrap" style="display:none;margin-top:8px;">
          <input type="number" id="shareExpiryCustom" class="form-input" placeholder="天数" min="1">
        </div>
      </div>
    </div>
    <div id="shareInfoPanel" style="display:none;">
      <div class="share-info-row"><span class="info-label">状态:</span><span id="shareInfoStatus"></span></div>
      <div class="share-info-row"><span class="info-label">密码:</span><span id="shareInfoPassword"></span></div>
      <div class="share-info-row"><span class="info-label">过期:</span><span id="shareInfoExpiry"></span></div>
      <div id="shareNewPasswordGroup" class="form-group" style="margin-top:14px;">
        <label class="form-label">设置新密码 <span class="form-hint">(留空 = 不修改)</span></label>
        <input type="text" id="shareNewPassword" class="form-input" placeholder="新密码">
      </div>
      <div id="shareExtendGroup" class="form-group">
        <label class="form-label">续期</label>
        <select id="shareExtendExpiry" class="form-input">
          <option value="3600">1 小时</option>
          <option value="86400">24 小时</option>
          <option value="604800">7 天</option>
          <option value="2592000">30 天</option>
          <option value="">永不过期</option>
          <option value="custom">自定义...</option>
        </select>
        <div id="customExtendWrap" style="display:none;margin-top:8px;">
          <input type="number" id="shareExtendCustom" class="form-input" placeholder="天数" min="1">
        </div>
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-outline" onclick="closeShareModal()">关闭</button>
      <button class="btn btn-outline" id="btnCopyShareWithPw" style="display:none;" onclick="copyActiveShareUrlWithPw()">复制带密码链接</button>
      <button class="btn btn-outline" id="btnCopyShare" style="display:none;" onclick="copyShareUrl()">复制链接</button>
      <button class="btn btn-primary" id="btnCreateShare" onclick="createShareLink()">创建分享</button>
      <button class="btn btn-primary" id="btnUpdateShare" style="display:none;" onclick="updateShareSettings()">保存修改</button>
      <button class="btn btn-danger" id="btnCancelShare" style="display:none;" onclick="cancelShare()">取消分享</button>
    </div>
  </div>
</div>
<div class="modal-overlay" id="genericDialog" style="display:none;">
  <div class="modal"><h3 id="dialogTitle"></h3><div id="dialogContent" style="margin:12px 0;"></div><div class="modal-actions" id="dialogActions"></div></div>
</div>
<script>
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML.replace(/'/g,'&#39;');}
function jsAttrString(v){return JSON.stringify(String(v==null?'':v)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function toast(m,t){const c=document.getElementById('toastContainer');const e=document.createElement('div');e.className='toast '+t;e.textContent=m;c.appendChild(e);setTimeout(()=>e.remove(),3000);}
function copyToClipboard(t){if(navigator.clipboard){navigator.clipboard.writeText(t)}else{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');document.body.removeChild(a)}}
function showDialog(o){return new Promise(r=>{const ov=document.getElementById('genericDialog');const done=v=>{ov.style.display='none';ov.onclick=null;r(v)};ov.onclick=e=>{if(e.target===ov)done({value:null,input:null,cancelled:true})};document.getElementById('dialogTitle').textContent=o.title||'';const ce=document.getElementById('dialogContent');if(o.type==='text'||o.type==='number'){ce.innerHTML='<input type="'+o.type+'" class="dialog-input" id="dialogInput" placeholder="'+esc(o.placeholder||'')+'" value="'+esc(o.value||'')+'" autofocus onkeydown="if(event.key===\\'Enter\\')document.getElementById(\\'dialogBtn0\\').click()">'}else{ce.innerHTML='<p class="dialog-text">'+esc(o.content||'')+'</p>'}const ae=document.getElementById('dialogActions');ae.innerHTML='';(o.buttons||[{text:'确定',cls:'primary',value:true}]).forEach((b,i)=>{const btn=document.createElement('button');btn.id='dialogBtn'+i;btn.className='btn btn-'+(b.cls||'primary');btn.textContent=b.text;btn.onclick=()=>{const inp=document.getElementById('dialogInput');done({value:b.value,input:inp?inp.value:null})};ae.appendChild(btn)});ov.style.display='flex';setTimeout(()=>{const inp=document.getElementById('dialogInput');if(inp)inp.focus()},100)})}

let currentFolder = '';
let folderPath = [];
let fileList = [];
let folderList = [];

function setupDragDrop(){
  const wrap=document.getElementById('fileGridWrap');
  wrap.addEventListener('dragover',e=>{e.preventDefault();wrap.style.background='#f0f7ff'});
  wrap.addEventListener('dragleave',()=>{wrap.style.background=''});
  wrap.addEventListener('drop',e=>{e.preventDefault();wrap.style.background='';if(e.dataTransfer.files.length)uploadFiles(e.dataTransfer.files)});
}

function triggerUpload(){document.getElementById('fileInput').click()}
function toggleAddPopup(e){e.stopPropagation();document.getElementById('addPopup').classList.toggle('show')}
document.addEventListener('click',()=>document.getElementById('addPopup').classList.remove('show'));
document.getElementById('fileInput').addEventListener('change',e=>{if(e.target.files.length)uploadFiles(e.target.files)});

const LARGE_FILE_THRESHOLD = 40 * 1024 * 1024;
const CHUNK_SIZE = 8 * 1024 * 1024;
const MAX_CONCURRENT = 2;
const HASH_CHUNK_SIZE = 4 * 1024 * 1024;
let uploadAbortController = null;

class Sha256Stream {
  constructor(){this.buf=new Uint8Array(0);this.pending=new Uint8Array(0);this.pos=0;this.parts=[]}
  write(chunk){this.parts.push(new Uint8Array(chunk))}
  async finalize(){
    const all=new Uint8Array(this.parts.reduce((s,p)=>s+p.length,0));
    let off=0;for(const p of this.parts){all.set(p,off);off+=p.length}
    const hash=await crypto.subtle.digest('SHA-256',all);
    const arr=new Uint8Array(hash);
    return Array.from(arr).map(b=>b.toString(16).padStart(2,'0')).join('');
  }
}

async function computeSHA256(file,onProgress,signal){
  const stream=new Sha256Stream();
  let pos=0;
  while(pos<file.size){
    if(signal.aborted)throw new DOMException('Aborted','AbortError');
    const end=Math.min(pos+HASH_CHUNK_SIZE,file.size);
    const slice=file.slice(pos,end);
    const buf=await slice.arrayBuffer();
    stream.write(buf);
    pos=end;
    if(onProgress)onProgress(pos/file.size);
    await new Promise(r=>setTimeout(r,0));
  }
  return await stream.finalize();
}

function uploadOverallPercent(uploaded,total){return Math.round(uploaded*100/total)}

async function createDedupPointer(folder,file,sha256,signal){
  const res=await fetch('/api/upload/dedup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({folder,filename:file.name,sha256,size:file.size,contentType:file.type||'application/octet-stream'}),signal});
  const data=await res.json();
  if(!res.ok)throw new Error(data.error||'去重检查失败');
  if(!data.exists)return null;
  return data.file;
}

function getMimeTypeFromName(name){
  const ext=(name||'').split('.').pop()?.toLowerCase();
  const map={txt:'text/plain',html:'text/html',css:'text/css',js:'text/javascript',json:'application/json',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',webp:'image/webp',svg:'image/svg+xml',pdf:'application/pdf',zip:'application/zip',mp3:'audio/mpeg',wav:'audio/wav',mp4:'video/mp4'};
  return map[ext]||'application/octet-stream';
}

function cancelUpload(){
  if(uploadAbortController){uploadAbortController.abort();uploadAbortController=null}
  const progress=document.getElementById('uploadProgress');
  const status=document.getElementById('uploadStatus');
  status.textContent='⚠ 上传已取消';
  document.getElementById('btnCancelUpload').style.display='none';
  setTimeout(()=>{progress.classList.remove('show');document.getElementById('progressFill').style.width='0%'},1500);
}

async function uploadFiles(files){
  if(!files.length)return;
  const folder=currentFolder||'';
  const progress=document.getElementById('uploadProgress');
  const fill=document.getElementById('progressFill');
  const status=document.getElementById('uploadStatus');
  const cancelBtn=document.getElementById('btnCancelUpload');
  progress.classList.add('show');
  fill.style.width='2%';
  fill.style.transition='width 0.3s ease';
  cancelBtn.style.display='inline-flex';
  uploadAbortController=new AbortController();
  const signal=uploadAbortController.signal;
  let totalUploaded=0;
  const totalSize=Array.from(files).reduce((s,f)=>s+f.size,0);
  const results=[];
  for(const file of files){
    if(signal.aborted)break;
    try{
      status.textContent='计算文件指纹: '+file.name;
      const hash=await computeSHA256(file,(ratio)=>{fill.style.width=Math.max(2,Math.round(2+ratio*8))+'%'},signal);
      if(signal.aborted)break;
      const existingFile=await createDedupPointer(folder,file,hash,signal);
      if(existingFile){
        results.push(existingFile);
        totalUploaded+=file.size;
        const pct=uploadOverallPercent(totalUploaded,totalSize);
        fill.style.width=pct+'%';
        status.textContent='已秒传: '+file.name;
        continue;
      }
      if(file.size<=LARGE_FILE_THRESHOLD){
        status.textContent='上传中: '+file.name;
        fill.style.width='15%';
        const formData=new FormData();
        formData.append('folder',folder);
        formData.append('files',file);
        formData.append('sha256',hash);
        const res=await fetch('/api/upload',{method:'POST',body:formData,signal});
        const data=await res.json();
        if(data.success){
          results.push(...data.files);
          totalUploaded+=file.size;
          fill.style.width=uploadOverallPercent(totalUploaded,totalSize)+'%';
        } else throw new Error(data.error);
      } else {
        status.textContent='分片上传中: '+file.name+' (0%)';
        const result=await uploadChunked(file,folder,(chunkUploaded)=>{
          totalUploaded+=chunkUploaded;
          const pct=uploadOverallPercent(totalUploaded,totalSize);
          fill.style.width=pct+'%';
          status.textContent='分片上传中: '+file.name+' ('+pct+'%)';
        },signal,hash);
        results.push(result);
      }
    } catch(e){
      if(signal.aborted)break;
      status.textContent='❌ 上传失败: '+e.message;
      toast('上传失败: '+e.message,'error');
      cancelBtn.style.display='none';
      setTimeout(()=>{progress.classList.remove('show');fill.style.width='0%'},2000);
      return;
    }
  }
  if(signal.aborted)return;
  uploadAbortController=null;
  fill.style.width='100%';
  status.textContent='✅ 上传完成: '+results.length+' 个文件';
  cancelBtn.style.display='none';
  toast('上传成功','success');
  document.getElementById('fileInput').value='';
  loadFiles();
  setTimeout(()=>{progress.classList.remove('show');fill.style.width='0%'},2000);
}

function uploadChunkWithProgress(uploadId,key,partNumber,chunk,signal,onProgress){
  return new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();
    let uploaded=0;
    const cleanup=()=>signal?.removeEventListener('abort',abort);
    const abort=()=>xhr.abort();
    if(signal?.aborted){reject(new DOMException('Upload aborted','AbortError'));return}
    signal?.addEventListener('abort',abort,{once:true});
    xhr.upload.onprogress=(event)=>{if(!event.lengthComputable)return;const delta=event.loaded-uploaded;uploaded=event.loaded;if(delta>0&&onProgress)onProgress(delta)};
    xhr.onload=()=>{cleanup();try{const data=JSON.parse(xhr.responseText||'{}');if(xhr.status>=200&&xhr.status<300&&data.etag){if(uploaded<chunk.size&&onProgress)onProgress(chunk.size-uploaded);resolve(data)}else{reject(new Error(data.error||'分片上传失败: part '+partNumber))}}catch(e){reject(e)}};
    xhr.onerror=()=>{cleanup();reject(new Error('网络错误: part '+partNumber))};
    xhr.onabort=()=>{cleanup();reject(new DOMException('Upload aborted','AbortError'))};
    xhr.open('POST','/api/upload/part?uploadId='+encodeURIComponent(uploadId)+'&key='+encodeURIComponent(key)+'&partNumber='+partNumber);
    xhr.setRequestHeader('Content-Type','application/octet-stream');
    xhr.send(chunk);
  });
}

async function uploadChunked(file,folder,onProgress,signal,sha256){
  const totalChunks=Math.ceil(file.size/CHUNK_SIZE);
  const initRes=await fetch('/api/upload/init',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({folder,filename:file.name,contentType:file.type,sha256}),signal});
  const initData=await initRes.json();
  if(initRes.ok&&initData.exists){
    const existingFile=await createDedupPointer(folder,file,sha256,signal);
    if(!existingFile)throw new Error('Dedup pointer creation failed');
    if(onProgress)onProgress(file.size);
    return existingFile;
  }
  if(!initRes.ok||!initData.uploadId)throw new Error(initData.error||'初始化分片上传失败');
  const {uploadId,key,targetKey}=initData;
  const parts=[];
  let nextPart=1;
  const partAbortController=new AbortController();
  if(signal.aborted){partAbortController.abort()}else{signal.addEventListener('abort',()=>partAbortController.abort(),{once:true})};
  const uploadPart=async(partNumber)=>{
    if(partAbortController.signal.aborted)throw new DOMException('Upload aborted','AbortError');
    const start=(partNumber-1)*CHUNK_SIZE;
    const end=Math.min(start+CHUNK_SIZE,file.size);
    const chunk=file.slice(start,end);
    const data=await uploadChunkWithProgress(uploadId,key,partNumber,chunk,partAbortController.signal,onProgress);
    parts.push({partNumber:data.partNumber,etag:data.etag});
  };
  const abortMultipart=async()=>{
    const abortRes=await fetch('/api/upload/abort',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({uploadId,key})});
    if(!abortRes.ok){const data=await abortRes.json();throw new Error(data.error||'取消分片上传失败')}
  };
  try{
    const workers=Array.from({length:Math.min(MAX_CONCURRENT,totalChunks)},async()=>{while(!partAbortController.signal.aborted){const partNumber=nextPart++;if(partNumber>totalChunks)return;await uploadPart(partNumber)}});
    await Promise.all(workers);
    if(signal.aborted)throw new DOMException('Upload aborted','AbortError');
    parts.sort((a,b)=>a.partNumber-b.partNumber);
    document.getElementById('uploadStatus').textContent='合并分片中: '+file.name;
    const contentType=file.type||getMimeTypeFromName(file.name);
    const completeRes=await fetch('/api/upload/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uploadId,key,targetKey,parts,sha256,size:file.size,contentType}),signal});
    const completeData=await completeRes.json();
    if(!completeRes.ok||!completeData.success)throw new Error(completeData.error||'合并分片失败');
    return {name:file.name,folder,size:file.size,key:targetKey,refCount:1};
  } catch(e){
    try{await abortMultipart()}catch(_){}
    throw e;
  }
}

function renderBreadcrumb(){
  const el=document.getElementById('breadcrumb');
  let html='<a href="javascript:void(0)" onclick="navigateTo([])">🏠 根目录</a>';
  let accumulated=[];
  for(const seg of folderPath){
    accumulated.push(seg);
    html+='<span class="sep">/</span>';
    if(accumulated.length===folderPath.length){
      html+='<span class="current">📂 '+esc(seg)+'</span>';
    } else {
      html+='<a href="javascript:void(0)" onclick="navigateTo('+JSON.stringify([...accumulated]).replace(/"/g,'&quot;')+')">📂 '+esc(seg)+'</a>';
    }
  }
  el.innerHTML=html;
}

function navigateTo(pathArr){
  folderPath=[...pathArr];
  currentFolder=folderPath.join('/');
  history.pushState(null,'','/'+currentFolder);
  renderBreadcrumb();
  loadFiles();
}

async function createFolder(){
  document.getElementById('addPopup').classList.remove('show');
  const r=await showDialog({title:'📁 新建文件夹',type:'text',placeholder:'文件夹名',content:'输入新文件夹名称',buttons:[{text:'取消',cls:'outline',value:null},{text:'创建',cls:'primary',value:'ok'}]});
  if(!r||r.value!=='ok'||!r.input)return;
  try{
    const res=await fetch('/api/folders',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:r.input,currentFolder:currentFolder})});
    const data=await res.json();
    if(data.success){toast('文件夹已创建','success');loadFiles()}else toast(data.error,'error');
  } catch(e){toast('创建失败','error')}
}

async function deleteFolder(name){
  const r=await showDialog({title:'🗑 删除文件夹',content:'确定删除文件夹 '+esc(name)+' 及其所有文件？此操作不可撤销 !',buttons:[{text:'取消',cls:'outline',value:null},{text:'确认删除',cls:'danger',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  try{
    const path=encodePath(currentFolder?currentFolder+'/'+name:name);
    const res=await fetch('/api/folders/'+path,{method:'DELETE'});
    const data=await res.json();
    if(data.success){toast('文件夹已删除','success');loadFiles()}else toast(data.error,'error');
  } catch(e){toast('删除失败','error')}
}

async function loadFiles(){
  try{
    const path=currentFolder?'/api/files/'+encodePath(currentFolder):'/api/files';
    const res=await fetch(path);
    const data=await res.json();
    if(!res.ok)throw new Error(data.error||'加载失败');
    fileList=data.files||[];
    folderList=data.folders||[];
    renderFileList();
  } catch(e){
    fileList=[];folderList=[];
    renderFileList();
    toast('加载文件失败: '+e.message,'error');
  }
}

function renderFileList(){
  const grid=document.getElementById('fileGrid');
  let html='<div class="add-card" id="addCard" onclick="toggleAddPopup(event)">'
    +'<div class="add-icon">＋</div>'
    +'<div class="add-text">新建或上传</div>'
    +'<div class="add-popup" id="addPopup">'
    +'<button class="add-popup-item" onclick="event.stopPropagation();createFolder()"><span class="popup-icon">📁</span> 新建文件夹</button>'
    +'<button class="add-popup-item" onclick="event.stopPropagation();triggerUpload()"><span class="popup-icon">📤</span> 上传文件</button>'
    +'</div></div>';
  if(!fileList.length&&!folderList.length){
    html+='<div class="empty-state"><div class="empty-icon">📭</div><div class="empty-text" style="font-size:15px;">此文件夹为空，点击 ＋ 新建文件夹或上传文件</div></div>';
  }
  for(const f of folderList){
    const sname=jsAttrString(f.name);
    html+='<div class="file-card" style="cursor:pointer;" onclick="navigateToFolder('+sname+')">'
      +'<div class="file-icon">📂</div>'
      +'<div class="file-name" title="'+esc(f.name)+'">'+esc(f.name)+'</div>'
      +'<div class="file-meta">文件夹</div>'
      +'<div class="card-actions">'
      +'<button class="btn-icon" title="分享文件夹" onclick="event.stopPropagation();shareFolder('+sname+')">🔗</button>'
      +'<button class="btn-icon danger" title="删除文件夹" onclick="event.stopPropagation();deleteFolder('+sname+')">🗑</button>'
      +'</div></div>';
  }
  for(const f of fileList){
    const sname=jsAttrString(f.name);
    const sfolder=jsAttrString(f.folder||currentFolder);
    const shared=shareMap.get(f.key);
    html+='<div class="file-card">'
      +(shared?'<span class="share-badge">已分享</span>':'')
      +'<div class="file-icon">'+fileIcon(f.name)+'</div>'
      +'<div class="file-name" title="'+esc(f.name)+'">'+esc(f.name)+'</div>'
      +'<div class="file-meta">'+formatSize(f.size)+'</div>'
      +'<div class="card-actions">'
      +'<button class="btn-icon" title="分享" onclick="event.stopPropagation();shareFile('+sname+','+sfolder+')">🔗</button>'
      +'<button class="btn-icon" title="下载" onclick="event.stopPropagation();downloadFile('+sfolder+','+sname+')">⬇</button>'
      +'<button class="btn-icon danger" title="删除" onclick="event.stopPropagation();deleteFile('+sfolder+','+sname+')">🗑</button>'
      +'</div></div>';
  }
  grid.innerHTML=html;
}

function navigateToFolder(name){
  folderPath.push(name);
  currentFolder=folderPath.join('/');
  history.pushState(null,'','/'+currentFolder);
  renderBreadcrumb();
  loadFiles();
}

window.addEventListener('popstate',()=>{
  const path=location.pathname.slice(1);
  folderPath=path?path.split('/'):[];
  currentFolder=path||'';
  renderBreadcrumb();
  loadFiles();
});

(function initFromUrl(){
  const path=location.pathname.slice(1);
  if(path){folderPath=path.split('/');currentFolder=path}
})();

function downloadFile(folder,name){
  const path=folder?encodePath(folder)+'/'+encodeURIComponent(name):encodeURIComponent(name);
  window.location.href='/api/admin-download/'+path;
}

async function deleteFile(folder,name){
  const r=await showDialog({title:'🗑 删除文件',content:'确定删除 '+esc(name)+'？',buttons:[{text:'取消',cls:'outline',value:null},{text:'确认删除',cls:'danger',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  try{
    const path=folder?encodePath(folder)+'/'+encodeURIComponent(name):encodeURIComponent(name);
    const res=await fetch('/api/files/'+path,{method:'DELETE'});
    const data=await res.json();
    if(data.success){toast('文件已删除','success');loadFiles()}else toast(data.error,'error');
  } catch(e){toast('删除失败','error')}
}

let activeShareToken=null;
let activeShareType=null;
let activeSharePath=null;
let activeShareName=null;
let activeSharePassword=null;
let shareMap=new Map();

async function loadAllShares(){
  try{
    const res=await fetch('/api/shares');
    const data=await res.json();
    if(!res.ok)throw new Error(data.error||'加载分享失败');
    shareMap.clear();
    for(const s of (data.shares||[])){shareMap.set(s.path,s)}
    if(fileList.length)renderFileList();
  } catch(e){
    toast('加载分享状态失败: '+e.message,'error');
    throw e;
  }
}

function shareFile(name,folder){
  const key=folder?encodePath(folder)+'/'+encodeURIComponent(name):encodeURIComponent(name);
  const existing=shareMap.get(key);
  activeShareType='file';
  activeSharePath=key;
  activeShareName=name;
  if(existing){showShareDialog(name,existing.token,existing);return}
  showShareDialogNew(name);
}

function shareFolder(name){
  const fullPath=currentFolder?currentFolder+'/'+name:name;
  const key=encodePath(fullPath);
  const existing=shareMap.get(key);
  activeShareType='folder';
  activeSharePath=key;
  activeShareName=name;
  if(existing){showShareDialog(name,existing.token,existing);return}
  showShareDialogNew(name);
}

function showShareDialogNew(name){
  activeShareToken=null;
  document.getElementById('shareModalTitle').textContent='🔗 创建分享';
  document.getElementById('shareTargetName').textContent=name;
  document.getElementById('shareUrlInput').value='';
  document.getElementById('shareUrlInput').style.display='none';
  document.getElementById('shareCreateForm').style.display='block';
  document.getElementById('shareInfoPanel').style.display='none';
  document.getElementById('shareNewPasswordGroup').style.display='none';
  document.getElementById('shareExtendGroup').style.display='none';
  document.getElementById('btnCreateShare').style.display='inline-flex';
  document.getElementById('btnUpdateShare').style.display='none';
  document.getElementById('btnCancelShare').style.display='none';
  document.getElementById('btnCopyShareWithPw').style.display='none';
  document.getElementById('sharePassword').value='';
  document.getElementById('shareExpiry').value='';
  document.getElementById('shareModal').style.display='flex';
}

function showShareDialog(name,token,shareData){
  activeShareToken=token;
  document.getElementById('shareModalTitle').textContent='🔗 分享详情';
  document.getElementById('shareTargetName').textContent=name;
  document.getElementById('shareUrlInput').value=location.origin+'/s/'+token;
  document.getElementById('shareUrlInput').style.display='block';
  document.getElementById('shareCreateForm').style.display='none';
  document.getElementById('shareInfoPanel').style.display='block';
  document.getElementById('shareNewPasswordGroup').style.display='block';
  document.getElementById('shareExtendGroup').style.display='block';
  document.getElementById('btnCreateShare').style.display='none';
  document.getElementById('btnUpdateShare').style.display='inline-flex';
  document.getElementById('btnCancelShare').style.display='inline-flex';
  document.getElementById('btnCopyShareWithPw').style.display=shareData.hasPassword?'inline-flex':'none';
  document.getElementById('shareNewPassword').value='';
  const expired=shareData.expiresAt&&new Date(shareData.expiresAt)<new Date();
  document.getElementById('shareInfoStatus').textContent=expired?'已过期':'有效';
  document.getElementById('shareInfoPassword').textContent=shareData.hasPassword?'已设置':'未设置';
  document.getElementById('shareInfoExpiry').textContent=shareData.expiresAt?new Date(shareData.expiresAt).toLocaleString():'永不过期';
  document.getElementById('shareModal').style.display='flex';
}

function closeShareModal(){
  document.getElementById('shareModal').style.display='none';
  activeShareToken=null;
  activeShareType=null;
  activeSharePath=null;
  activeShareName=null;
  activeSharePassword=null;
}

function copyShareUrl(){
  const input=document.getElementById('shareUrlInput');
  if(!input.value){toast('请先创建分享','error');return}
  copyToClipboard(input.value);
  toast('链接已复制到剪贴板','success');
}

async function copyActiveShareUrlWithPw(){
  if(!activeShareToken)return;
  let pw=activeSharePassword;
  if(!pw){
    const result=await showDialog({title:'🔐 输入分享密码',type:'text',placeholder:'输入此分享的密码',content:'密码不会从服务端明文返回；输入后生成带密码的访问链接。',buttons:[{text:'取消',cls:'outline',value:null},{text:'复制',cls:'primary',value:'ok'}]});
    if(!result||result.value!=='ok'||!result.input)return;
    pw=result.input;
    activeSharePassword=pw;
  }
  const url=location.origin+'/s/'+activeShareToken+'?pw='+encodeURIComponent(pw);
  copyToClipboard(url);
  toast('带密码链接已复制（访问时无需输入密码）','success');
}

function togglePasswordVisible(id){
  const el=document.getElementById(id);
  el.type=el.type==='password'?'text':'password';
}

function onExpiryChange(){
  const val=document.getElementById('shareExpiry').value;
  document.getElementById('customExpiryWrap').style.display=val==='custom'?'block':'none';
}

function getExpiresIn(){
  const select=document.getElementById('shareExpiry');
  if(select.value==='custom'){
    const days=parseInt(document.getElementById('shareExpiryCustom').value)||0;
    return days>0?days*86400:null;
  }
  return select.value?parseInt(select.value):null;
}

function getExtendExpiresIn(){
  const select=document.getElementById('shareExtendExpiry');
  if(select.value==='custom'){
    const days=parseInt(document.getElementById('shareExtendCustom').value)||0;
    return days>0?days*86400:null;
  }
  return select.value?parseInt(select.value):null;
}

async function createShareLink(){
  const password=document.getElementById('sharePassword').value.trim()||null;
  const expiresIn=getExpiresIn();
  let body={type:activeShareType,path:activeSharePath,name:activeShareName};
  if(password)body.password=password;
  if(expiresIn)body.expiresIn=expiresIn;
  try{
    const res=await fetch('/api/share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const data=await res.json();
    if(data.success){
      document.getElementById('shareUrlInput').value=data.url;
      document.getElementById('shareUrlInput').style.display='block';
      document.getElementById('btnCreateShare').style.display='none';
      document.getElementById('btnCopyShare').style.display='inline-flex';
      document.getElementById('btnCopyShareWithPw').style.display='inline-flex';
      document.getElementById('shareCreateForm').style.display='none';
      document.getElementById('shareInfoPanel').style.display='block';
      document.getElementById('shareNewPasswordGroup').style.display='none';
      document.getElementById('shareExtendGroup').style.display='none';
      document.getElementById('btnUpdateShare').style.display='none';
      document.getElementById('btnCancelShare').style.display='inline-flex';
      document.getElementById('shareModalTitle').textContent='🔗 分享详情';
      document.getElementById('shareInfoStatus').textContent='有效';
      document.getElementById('shareInfoPassword').textContent=password?'已设置':'未设置';
      document.getElementById('shareInfoExpiry').textContent=expiresIn?new Date(Date.now()+expiresIn*1000).toLocaleString():'永不过期';
      activeShareToken=data.share.token;
      activeSharePassword=password;
      toast('分享已创建','success');
      await loadAllShares();
    } else toast(data.error,'error');
  } catch(e){toast('创建失败','error')}
}

async function updateShareSettings(){
  if(!activeShareToken)return;
  const newPassword=document.getElementById('shareNewPassword').value;
  const expiresIn=getExtendExpiresIn();
  try{
    if(newPassword){
      const res=await fetch('/api/share/'+activeShareToken,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'password',password:newPassword})});
      const data=await res.json();
      if(!data.success){toast(data.error,'error');return}
      toast('密码已更新','success');
    }
    if(document.getElementById('shareExtendExpiry').value!==''||expiresIn!==null){
      const res=await fetch('/api/share/'+activeShareToken,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'extend',expiresIn})});
      const data=await res.json();
      if(!data.success){toast(data.error,'error');return}
      toast('已续期','success');
    }
    await loadAllShares();
    closeShareModal();
  } catch(e){toast('更新失败','error')}
}

async function cancelShare(){
  if(!activeShareToken)return;
  const r=await showDialog({title:'❌ 取消分享',content:'确定取消此分享 ？分享链接将立即失效 !',buttons:[{text:'保留',cls:'outline',value:null},{text:'确认取消',cls:'danger',value:'ok'}]});
  if(!r||r.value!=='ok')return;
  try{
    await fetch('/api/share/'+activeShareToken,{method:'DELETE'});
    toast('分享已取消','success');
    closeShareModal();
    shareMap.clear();
    await loadAllShares();
    renderFileList();
  } catch(e){toast('取消失败','error')}
}

function fileIcon(name){
  const ext=(name||'').split('.').pop()?.toLowerCase();
  const m={jpg:'🖼',jpeg:'🖼',png:'🖼',gif:'🖼',webp:'🖼',svg:'🖼',pdf:'📕',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',ppt:'📽',pptx:'📽',zip:'📦',rar:'📦','7z':'📦',mp3:'🎵',wav:'🎵',mp4:'🎬',avi:'🎬',js:'💛',ts:'💙',py:'🐍',html:'🌐',css:'🎨',json:'📋',txt:'📄',md:'📝'};
  return m[ext]||'📎';
}

function encodePath(path){
  return (path||'').split('/').filter(Boolean).map(encodeURIComponent).join('/');
}

function escapeHtml(str){
  const div=document.createElement('div');
  div.textContent=str;
  return div.innerHTML.replace(/'/g,'&#39;');
}

function formatSize(bytes){
  if(!bytes||bytes===0)return '0 B';
  const u=['B','KB','MB','GB','TB'];
  const i=Math.floor(Math.log(bytes)/Math.log(1024));
  return (bytes/Math.pow(1024,i)).toFixed(i>0?1:0)+' '+u[i];
}

(async function init(){
  setupDragDrop();
  renderBreadcrumb();
  await loadFiles();
  try{await loadAllShares()}catch(_){}
})();
</script>
</body>
</html>`;
}
