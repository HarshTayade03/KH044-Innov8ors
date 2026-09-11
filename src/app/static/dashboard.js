'use strict';
const API='/api/v1', state={findings:[],issues:[],clusters:[],priorities:[],view:'findings',busy:false};
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=v=>esc(String(v??'').slice(0,12));

async function request(path,options={}){
  const response=await fetch(path,options); let body;
  try{body=await response.json()}catch{body={detail:await response.text()}}
  if(!response.ok)throw new Error(body.detail||`${response.status} ${response.statusText}`);
  return body;
}
function message(text,error=false){$('#notice').textContent=text;$('#notice').classList.toggle('error',error)}
function busy(on){state.busy=on;$$('button').forEach(b=>{if(!b.classList.contains('tab'))b.disabled=on});$('#runBtn').innerHTML=on?'<span class="spinner"></span> Working…':'Run core workflow'}
function step(name,status,text){const e=$(`[data-step="${name}"]`);e.classList.remove('active','done','fail');if(status)e.classList.add(status);e.querySelector('span').textContent=text}
function pill(value){return `<span class="pill ${esc(value)}">${esc(value||'Unknown')}</span>`}

async function refresh(){
  const calls=await Promise.allSettled([
    request(`${API}/findings?limit=500`),request(`${API}/canonical-issues?limit=500`),
    request(`${API}/clusters?limit=500`),request(`${API}/priorities?limit=500`)
  ]);
  calls.forEach((result,index)=>{
    const key=['findings','issues','clusters','priorities'][index];
    state[key]=result.status==='fulfilled'?(result.value[key]||result.value.canonical_issues||[]):[];
  });
  $('#mFindings').textContent=state.findings.length; $('#mIssues').textContent=state.issues.length;
  $('#mClusters').textContent=state.clusters.length; $('#mPriorities').textContent=state.priorities.length;
  render();
}
function filtered(items){const q=$('#search').value.toLowerCase().trim();return q?items.filter(x=>JSON.stringify(x).toLowerCase().includes(q)):items}
function empty(label){return `<div class="empty">No ${label} yet.</div>`}
function render(){const wrap=$('#tableWrap');({findings:renderFindings,issues:renderIssues,clusters:renderClusters}[state.view])(wrap)}
function renderFindings(w){
  const rows=filtered(state.findings); if(!rows.length){w.innerHTML=empty('findings');return}
  w.innerHTML=`<table><thead><tr><th>Finding</th><th>Scanner</th><th>Severity</th><th>Location</th><th>Quality</th><th></th></tr></thead><tbody>${rows.map(f=>`<tr><td class="title-cell"><b>${esc(f.vulnerability.title)}</b><span class="mono">${short(f.finding_id)} · ${esc(f.vulnerability.cwe_primary||'No CWE')}</span></td><td>${esc(f.source_scanner)}</td><td>${pill(f.vulnerability.severity)}</td><td>${esc(f.location.host||f.asset.asset_name)}<div class="mono">${esc(f.location.path||f.location.url||'—')} ${f.location.parameter?'· '+esc(f.location.parameter):''}</div></td><td>${Math.round((f.quality.completeness_score||0)*100)}%</td><td><button class="btn ghost" data-finding="${esc(f.finding_id)}">Inspect</button></td></tr>`).join('')}</tbody></table>`;
}
function priorityFor(id){return state.priorities.find(p=>p.canonical_issue_id===id)}
function renderIssues(w){
  const rows=filtered(state.issues);if(!rows.length){w.innerHTML=empty('active issues; run deduplication first');return}
  w.innerHTML=`<table><thead><tr><th>Canonical issue</th><th>Reports</th><th>Method</th><th>Priority</th><th></th></tr></thead><tbody>${rows.map(i=>{const p=priorityFor(i.canonical_issue_id);return `<tr><td class="title-cell"><b>${esc(i.title)}</b><span class="mono">${short(i.canonical_issue_id)}</span></td><td>${i.source_finding_ids.length} · ${esc(i.source_scanners.join(', '))}</td><td>${esc(i.merge_method)}</td><td>${p?`${pill(p.remediation_tier)} <b>${p.risk_score}</b>`:'Not scored'}</td><td class="actions"><button class="btn ghost" data-issue="${esc(i.canonical_issue_id)}">Inspect</button><button class="btn primary" data-prioritize="${esc(i.canonical_issue_id)}">Score</button></td></tr>`}).join('')}</tbody></table>`;
}
function renderClusters(w){
  const rows=filtered(state.clusters);if(!rows.length){w.innerHTML=empty('clusters');return}
  w.innerHTML=`<table><thead><tr><th>Cluster</th><th>Method</th><th>Status</th><th>Members</th><th>Similarity</th><th>Review action</th></tr></thead><tbody>${rows.map(c=>`<tr><td class="mono">${short(c.cluster_id)}</td><td>${esc(c.cluster_method)}</td><td>${pill(c.status)}</td><td>${c.members.length}</td><td>${c.similarity_score==null?'—':Math.round(c.similarity_score*100)+'%'}</td><td class="actions"><button class="btn ghost" data-cluster="${esc(c.cluster_id)}">Inspect</button><button class="btn primary" data-merge="${esc(c.cluster_id)}">Merge</button><button class="btn danger" data-split="${esc(c.cluster_id)}">Keep separate</button></td></tr>`).join('')}</tbody></table>`;
}
async function inspectFinding(id){
  try{
    const [finding,views,embeddings]=await Promise.all([request(`${API}/findings/${id}`),request(`${API}/findings/${id}/views`),request(`${API}/findings/${id}/embeddings`).catch(()=>null)]);
    $('#modalTitle').textContent=finding.vulnerability.title;
    $('#modalBody').innerHTML=`<div class="views">${['description','location','reproduction','impact'].map(k=>`<section class="view"><h4>${esc(k)} ${pill(views[k].status)}</h4><p>${esc(views[k].text||'No extracted text')}</p></section>`).join('')}</div><h2>Embedding status</h2>${embeddings?`<dl class="kv"><dt>Backend</dt><dd>${esc(embeddings.embedding_model)} ${esc(embeddings.model_version||'')}</dd><dt>Dimension</dt><dd>${embeddings.embedding_dimension}</dd><dt>Missing views</dt><dd>${esc(embeddings.missing_views.join(', ')||'None')}</dd></dl>`:'<p class="note">No embeddings stored. Run the core workflow.</p>'}`;
    $('#detailDialog').showModal();
  }catch(error){message(error.message,true)}
}
function inspectIssue(id){
  const issue=state.issues.find(x=>x.canonical_issue_id===id),priority=priorityFor(id);
  $('#modalTitle').textContent=issue.title;
  $('#modalBody').innerHTML=`<dl class="kv"><dt>Issue ID</dt><dd class="mono">${esc(issue.canonical_issue_id)}</dd><dt>Source findings</dt><dd>${issue.source_finding_ids.map(short).join(', ')}</dd><dt>Scanners</dt><dd>${esc(issue.source_scanners.join(', '))}</dd><dt>Merge reason</dt><dd>${esc(issue.merge_reason.join(' · '))}</dd></dl>${priority?`<h2>Risk ${priority.risk_score} · ${pill(priority.remediation_tier)}</h2><div class="contrib">${Object.entries(priority.factors.contributions||{}).map(([k,v])=>`<div><span class="note">${esc(k)}</span><br><b>${Number(v).toFixed(2)} pts</b></div>`).join('')}</div><ul>${priority.explanation.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:'<p class="note">This issue has not been prioritized.</p>'}`;
  $('#detailDialog').showModal();
}
function inspectCluster(id){
  const c=state.clusters.find(x=>x.cluster_id===id);$('#modalTitle').textContent='Cluster details';
  $('#modalBody').innerHTML=`<dl class="kv"><dt>Cluster ID</dt><dd class="mono">${esc(c.cluster_id)}</dd><dt>Method</dt><dd>${esc(c.cluster_method)}</dd><dt>Status</dt><dd>${esc(c.status)}</dd><dt>Reason</dt><dd>${esc(c.merge_reason.join(' · '))}</dd><dt>Members</dt><dd>${c.members.map(m=>short(m.finding_id)).join(', ')}</dd><dt>Run at</dt><dd>${esc(c.run_at)}</dd></dl>`;
  $('#detailDialog').showModal();
}
async function runWorkflow(){
  if(state.busy)return;if(!state.findings.length){message('Import at least one finding before running the workflow.',true);return}
  busy(true);['views','embeddings','dedup','risk'].forEach(k=>step(k,'','Waiting'));const failures=[];
  try{
    for(const [name,path] of [['views','extract-views'],['embeddings','generate-embeddings']]){
      step(name,'active',name==='views'?'Extracting…':'Generating…');const before=failures.length;
      for(let i=0;i<state.findings.length;i++){try{await request(`${API}/findings/${state.findings[i].finding_id}/${path}`,{method:'POST'})}catch(e){failures.push(`${name}: ${e.message}`)}step(name,'active',`${i+1}/${state.findings.length}`)}
      step(name,failures.length>before?'fail':'done',failures.length>before?'Completed with errors':'Complete');
    }
    step('dedup','active','Clustering…');const d=await request(`${API}/deduplication/run`,{method:'POST'});step('dedup','done',`${d.total_canonical_issues} issues · ${d.semantic_status}`);await refresh();
    step('risk','active','Scoring…');const before=failures.length;
    for(let i=0;i<state.issues.length;i++){try{await request(`${API}/canonical-issues/${state.issues[i].canonical_issue_id}/prioritize`,{method:'POST'})}catch(e){failures.push(`risk: ${e.message}`)}step('risk','active',`${i+1}/${state.issues.length}`)}
    step('risk',failures.length>before?'fail':'done',failures.length>before?'Completed with errors':'Complete');await refresh();
    message(failures.length?`Workflow finished with ${failures.length} error(s):\n${failures.slice(0,5).join('\n')}`:`Workflow complete: ${state.findings.length} findings → ${state.issues.length} active issues → ${state.priorities.length} scores.`,!!failures.length);
  }catch(e){message(`Workflow stopped: ${e.message}`,true)}finally{busy(false)}
}
async function submit(form,operation){
  if(state.busy)return;busy(true);
  try{const result=await operation();message(`Import complete: ${result.normalized??1} normalized, ${result.normalized_with_warnings??0} with warnings, ${result.rejected??0} rejected.`);await refresh()}
  catch(e){message(`Import failed: ${e.message}`,true)}finally{busy(false)}
}
$$('[data-tab]').forEach(b=>b.onclick=()=>{$$('[data-tab]').forEach(x=>x.classList.toggle('active',x===b));$$('[data-panel]').forEach(x=>x.classList.toggle('hidden',x.dataset.panel!==b.dataset.tab))});
$$('[data-view]').forEach(b=>b.onclick=()=>{$$('[data-view]').forEach(x=>x.classList.toggle('active',x===b));state.view=b.dataset.view;render()});
$('#sampleBtn').onclick=()=>{$('#jsonInput').value=JSON.stringify([{name:'SQL Injection in login',host:'https://app.example.test',path:'/login',parameter:'username',severity:'High',cwe_ids:['CWE-89'],cve_ids:['CVE-2024-1001'],request:'POST /login username=demo&password=secret',response:'HTTP/1.1 500 Database error'}],null,2)};
$('#jsonForm').onsubmit=e=>{e.preventDefault();submit(e.currentTarget,()=>{let findings;try{findings=JSON.parse($('#jsonInput').value)}catch{throw new Error('JSON is not valid')}if(!Array.isArray(findings))throw new Error('JSON input must be an array');return request(`${API}/findings`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source_scanner:$('#jsonScanner').value,findings})})})};
$('#fileForm').onsubmit=e=>{e.preventDefault();submit(e.currentTarget,()=>{const data=new FormData();data.append('source_scanner',$('#fileScanner').value);data.append('file',$('#fileInput').files[0]);return request(`${API}/findings/upload`,{method:'POST',body:data})})};
$('#manualForm').onsubmit=e=>{e.preventDefault();submit(e.currentTarget,()=>{const d=Object.fromEntries(new FormData(e.currentTarget));const payload={title:d.title,asset_name:d.asset_name,severity:d.severity,url:d.url||null,parameter:d.parameter||null,cwe_ids:d.cwe?[d.cwe]:[]};return request(`${API}/findings/manual`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})})};
$('#tableWrap').onclick=async e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.finding)return inspectFinding(b.dataset.finding);if(b.dataset.issue)return inspectIssue(b.dataset.issue);if(b.dataset.cluster)return inspectCluster(b.dataset.cluster);if(b.dataset.prioritize){busy(true);try{await request(`${API}/canonical-issues/${b.dataset.prioritize}/prioritize`,{method:'POST'});message('Priority calculated.');await refresh()}catch(x){message(x.message,true)}finally{busy(false)}}if(b.dataset.merge||b.dataset.split){const merge=!!b.dataset.merge,id=b.dataset.merge||b.dataset.split;busy(true);try{await request(`${API}/clusters/${id}/${merge?'merge':'split'}`,{method:'POST'});message(merge?'Cluster merged.':'Cluster kept separate.');await refresh()}catch(x){message(x.message,true)}finally{busy(false)}}};
$('#search').oninput=render;$('#refreshBtn').onclick=refresh;$('#runBtn').onclick=runWorkflow;$('#closeModal').onclick=()=>$('#detailDialog').close();
(async()=>{try{const h=await request('/health');$('#healthDot').classList.add('ok');$('#healthText').textContent=`Backend online · ${h.tables_initialized} tables · ${h.threat_intelligence_mode} feeds`;await refresh()}catch(e){$('#healthText').textContent='Backend unavailable';message(e.message,true)}})();
