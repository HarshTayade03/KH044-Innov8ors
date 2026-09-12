'use strict';
const API='/api/v1',state={datasets:[],findings:[],issues:[],clusters:[],priorities:[],cases:[],audit:[],feeds:[],view:'findings',busy:false,sortKey:'priority',sortDir:'desc'};
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=v=>esc(String(v||'').slice(0,12)), tag=v=>`<span class="tag ${esc(v)}">${esc(v||'Unknown')}</span>`;
async function request(path,options={}){const r=await fetch(path,options),b=await r.json().catch(()=>({}));if(!r.ok)throw new Error(b.detail||`${r.status} ${r.statusText}`);return b}
function busy(on){state.busy=on;$$('button').forEach(b=>b.disabled=on);$('#runBtn').textContent=on?'Processing workspace…':'Process current workspace'}
function notice(t,e=false){$('#notice').textContent=t;$('#notice').classList.toggle('error',e)}
function step(k,s,t){const e=$(`[data-step="${k}"]`);if(!e)return;e.classList.remove('active','done','fail');if(s)e.classList.add(s);e.querySelector('strong').textContent=t}
async function metrics(){const m=await request(`${API}/dashboard/metrics`);for(const [id,key] of [['mFindings','findings'],['mIssues','active_issues'],['mClusters','clusters'],['mPriorities','priorities'],['mValidations','validations']])$(`#${id}`).textContent=m[key]}
async function refresh(){const all=await Promise.all([request(`${API}/findings?limit=500`),request(`${API}/canonical-issues?limit=500`),request(`${API}/clusters?limit=500`),request(`${API}/priorities?limit=500`),request(`${API}/cases?limit=500`),request(`${API}/audit-events?limit=500`),request(`${API}/threat-intelligence/feeds`),request(`${API}/sandbox/docker/status`).catch(()=>null),metrics()]);state.findings=all[0].findings||[];state.issues=all[1].canonical_issues||[];state.clusters=all[2].clusters||[];state.priorities=all[3].priorities||[];state.cases=Array.isArray(all[4])?all[4]:[];state.audit=all[5].events||[];state.feeds=all[6].feeds||[];state.dockerStatus=all[7];$('#workspaceFindings').textContent=state.findings.length;$('#workspaceIssues').textContent=state.issues.length;$('#workspaceCases').textContent=state.cases.filter(c=>c.status==='pending_review').length;$('#feedStatus').innerHTML=state.feeds.map(f=>`<article class="feed-card"><div><b>${esc(f.name)}</b><small>${esc(f.provider)}</small></div><span class="feed-pill ${f.available?'feed-ok':'feed-off'}">${f.available?'Available':'Disabled'}</span><p>${esc(f.mode)} · ${esc(f.note)}</p></article>`).join('');render()}
async function catalog(){const d=await request(`${API}/demo/datasets`);state.datasets=d.datasets;$('#datasetGrid').innerHTML=d.datasets.map(x=>`<button class="dataset-item" data-dataset="${esc(x.id)}"><i>${esc(x.scanner)} · ${esc(x.filename.split('.').pop())}</i><b>${esc(x.category)}</b><strong>${x.count} findings →</strong></button>`).join('')}
function showDataset(id){const dataset=state.datasets.find(x=>x.id===id);if(!dataset)return;$('#datasetTitle').textContent=dataset.category;$('#datasetBody').innerHTML=`<div class="dataset-hero"><span class="dataset-count">${dataset.count}</span><div><p class="eyebrow">${esc(dataset.origin||'Prepared scanner export')}</p><h4>${esc(dataset.filename)}</h4><p>Review this fixed fixture before adding its normalized findings to the local workspace.</p></div></div><dl class="dataset-facts"><div><dt>Scanner</dt><dd>${esc(dataset.scanner)}</dd></div><div><dt>Format</dt><dd>${esc(dataset.filename.split('.').pop().toUpperCase())}</dd></div><div><dt>Finding family</dt><dd>${esc(dataset.category)}</dd></div><div><dt>Expected records</dt><dd>${dataset.count}</dd></div></dl><p class="dataset-note">${dataset.origin==='included workflow resource'?'This sample is included in the repository as a mixed scanner workflow resource.':'This export is repository-owned synthetic data.'} Loading it changes local SQLite state, but does not contact a real target.</p>`;$('#loadDataset').dataset.id=id;$('#datasetDialog').showModal()}
async function load(ids){if(state.busy)return;$('#datasetDialog')?.close();busy(true);let total=0,existing=0;try{for(const id of ids){$('#loadStatus').textContent=`Loading ${id}…`;const r=await request(`${API}/demo/datasets/${id}/load`,{method:'POST'});total+=r.normalized+r.normalized_with_warnings;existing+=r.already_loaded||0}await refresh();const summary=`${total} new findings loaded; ${existing} already loaded.`;$('#loadStatus').textContent=summary;notice(summary)}catch(e){$('#loadStatus').textContent=`Load stopped: ${e.message}`;notice(e.message,true)}finally{busy(false)}}
async function importExport(event){event.preventDefault();const file=$('#uploadFile').files[0];if(!file)return;busy(true);try{const data=new FormData();data.append('file',file);data.append('source_scanner',$('#uploadScanner').value);const result=await request(`${API}/findings/upload`,{method:'POST',body:data});await refresh();notice(`Imported ${result.normalized} findings from ${file.name}. ${result.rejected||0} rejected.`)}catch(e){notice(`Import failed: ${e.message}`,true)}finally{busy(false)}}
async function addManual(event){event.preventDefault();busy(true);try{const data=Object.fromEntries(new FormData(event.currentTarget));const result=await request(`${API}/findings/manual`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:data.title,asset_name:data.asset_name,severity:data.severity,cwe_ids:data.cwe_ids?[data.cwe_ids]:[],cve_ids:data.cve_ids?[data.cve_ids]:[],url:data.url||null,notes:data.notes||null})});event.currentTarget.reset();await refresh();notice(`Added finding ${result.finding_id}. It is ready for view extraction and triage.`)}catch(e){notice(`Could not add finding: ${e.message}`,true)}finally{busy(false)}}
const filtered=a=>{const q=$('#search').value.toLowerCase().trim();return q?a.filter(x=>JSON.stringify(x).toLowerCase().includes(q)):a};
const empty=t=>`<div class="empty">${t}</div>`, priority=id=>state.priorities.find(p=>p.canonical_issue_id===id);

const SEV_MAP={Critical:5,Immediate:5,High:4,Accelerated:4,Medium:3,Standard:3,Low:2,Informational:1,Unknown:0};
function getVal(item,key){
  if(key==='priority'||key==='risk'||key==='severity'){
    const p=priority(item.canonical_issue_id||item.finding_id);
    if(p&&p.risk_score!=null)return p.risk_score;
    const s=item.vulnerability?.severity||item.severity||'Unknown';
    return SEV_MAP[s]||0;
  }
  if(key==='title'||key==='finding'||key==='issue'||key==='case')return (item.title||item.vulnerability?.title||item.case_id||'').toLowerCase();
  if(key==='scanner')return (item.source_scanner||item.source_scanners?.join(',')||'').toLowerCase();
  if(key==='endpoint')return (item.location?.host||item.asset?.asset_name||'').toLowerCase();
  if(key==='quality')return item.quality?.completeness_score||0;
  if(key==='sources'||key==='members')return (item.source_finding_ids||item.members||[]).length;
  if(key==='method')return (item.merge_method||item.cluster_method||'').toLowerCase();
  if(key==='status')return (item.status||'').toLowerCase();
  if(key==='updated'||key==='when')return new Date(item.last_updated_at||item.occurred_at||0).getTime();
  if(key==='confidence')return item.similarity_score||0;
  return String(item[key]||'').toLowerCase();
}

function sorted(arr){
  const k=state.sortKey, d=state.sortDir==='asc'?1:-1;
  if(!k)return arr;
  return [...arr].sort((a,b)=>{
    const va=getVal(a,k), vb=getVal(b,k);
    if(typeof va==='number'&&typeof vb==='number')return (va-vb)*d;
    return String(va).localeCompare(String(vb))*d;
  });
}

function thSort(key,label){
  const active=state.sortKey===key, dir=state.sortDir;
  let icon=`<svg class="sort-svg neutral" width="9" height="11" viewBox="0 0 9 11" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4.5 0.5L8 4H1L4.5 0.5Z" fill="currentColor" opacity="0.35"/><path d="M4.5 10.5L1 7H8L4.5 10.5Z" fill="currentColor" opacity="0.35"/></svg>`;
  if(active&&dir==='asc'){
    icon=`<svg class="sort-svg active" width="9" height="11" viewBox="0 0 9 11" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4.5 0.5L8 4H1L4.5 0.5Z" fill="#292524"/><path d="M4.5 10.5L1 7H8L4.5 10.5Z" fill="#292524" opacity="0.2"/></svg>`;
  }else if(active&&dir==='desc'){
    icon=`<svg class="sort-svg active" width="9" height="11" viewBox="0 0 9 11" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4.5 0.5L8 4H1L4.5 0.5Z" fill="#292524" opacity="0.2"/><path d="M4.5 10.5L1 7H8L4.5 10.5Z" fill="#292524"/></svg>`;
  }
  return `<th class="sortable-th ${active?'active-sort':''}" data-sort="${key}"><span class="th-content"><span>${label}</span>${icon}</span></th>`;
}

function render(){
  const w=$('#tableWrap');
  if(state.view==='findings'){
    const rows=sorted(filtered(state.findings));
    w.innerHTML=rows.length?`<table><thead><tr>${thSort('title','Finding')}${thSort('scanner','Scanner')}${thSort('severity','Severity')}${thSort('endpoint','Endpoint')}${thSort('quality','Quality')}<th></th></tr></thead><tbody>${rows.map(f=>`<tr><td class="title-cell"><b>${esc(f.vulnerability.title)}</b><small class="mono">${short(f.finding_id)} · ${esc(f.vulnerability.cwe_primary||'No CWE')}</small></td><td>${esc(f.source_scanner)}</td><td>${tag(f.vulnerability.severity)}</td><td>${esc(f.location.host||f.asset.asset_name)}<small class="mono">${esc(f.location.path||'—')}</small></td><td>${Math.round(f.quality.completeness_score*100)}%</td><td><button class="inspect" data-finding="${f.finding_id}">Inspect</button></td></tr>`).join('')}</tbody></table>`:empty('Load a prepared dataset to see normalized findings.');
  }else if(state.view==='issues'){
    const rows=sorted(filtered(state.issues));
    w.innerHTML=rows.length?`<table><thead><tr>${thSort('title','Canonical issue')}${thSort('sources','Sources')}${thSort('method','Method')}${thSort('priority','Risk')}<th>Actions</th></tr></thead><tbody>${rows.map(i=>{const p=priority(i.canonical_issue_id);return`<tr><td class="title-cell"><b>${esc(i.title)}</b><small class="mono">${short(i.canonical_issue_id)}</small></td><td>${i.source_finding_ids.length} reports · ${esc(i.source_scanners.join(', '))}</td><td>${esc(i.merge_method)}</td><td>${p?`${tag(p.remediation_tier)} <b>${p.risk_score}</b>`:'Awaiting score'}</td><td class="actions"><button class="inspect" data-issue="${i.canonical_issue_id}">Inspect</button><button class="patch-btn" data-patch="${i.canonical_issue_id}">✨ AI Patch</button><button class="case" data-case-issue="${i.canonical_issue_id}">Create case</button><button class="validate" data-validate="${i.canonical_issue_id}">Validate</button></td></tr>`}).join('')}</tbody></table>`:empty('Run the pipeline to create canonical issues.');
  }else if(state.view==='cases'){
    const rows=sorted(filtered(state.cases));
    w.innerHTML=rows.length?`<table><thead><tr>${thSort('title','Case')}${thSort('status','Status')}${thSort('issue','Issue')}${thSort('updated','Updated')}<th>Actions</th></tr></thead><tbody>${rows.map(c=>`<tr><td class="title-cell"><b>${esc(c.title)}</b><small class="mono">${short(c.case_id)}</small></td><td>${tag(c.status)}</td><td class="mono">${short(c.canonical_issue_id)}</td><td>${esc(new Date(c.last_updated_at).toLocaleString())}</td><td class="actions"><button class="inspect" data-case="${c.case_id}">Inspect</button><button class="export-ticket-btn" data-ticket="${c.case_id}">✨ Ticket Export</button>${['pending_review','more_evidence_requested'].includes(c.status)?`<button class="case-approve" data-approve="${c.case_id}">Approve</button><button class="case-evidence" data-evidence="${c.case_id}">Request evidence</button><button class="resolve" data-case-resolve="${c.case_id}">Resolve</button>`:''}</td></tr>`).join('')}</tbody></table>`:empty('Create a case from an active canonical issue to begin review.');
  }else if(state.view==='clusters'){
    const rows=sorted(filtered(state.clusters));
    w.innerHTML=rows.length?`<table><thead><tr>${thSort('cluster','Cluster')}${thSort('method','Method')}${thSort('status','Status')}${thSort('members','Members')}${thSort('confidence','Confidence')}<th></th></tr></thead><tbody>${rows.map(c=>`<tr><td class="mono">${short(c.cluster_id)}</td><td>${esc(c.cluster_method)}</td><td>${tag(c.status)}</td><td>${c.members.length}</td><td>${c.similarity_score==null?'—':Math.round(c.similarity_score*100)+'%'}</td><td><button class="inspect" data-cluster="${c.cluster_id}">Inspect</button></td></tr>`).join('')}</tbody></table>`:empty('Run deduplication to see cluster evidence.');
  }else if(state.view==='integrations'){
    w.innerHTML=`<div class="integration-grid">
      <div class="integration-card">
        <h4>🤖 Free Groq LLM Configurator</h4>
        <p>Enable free live Groq LLM engine for real-time AI Patch Generation and LLM Risk Synthesis.</p>
        <div class="form-group"><label>Groq API Key (gsk_...)</label><input id="groqApiKeyInput" placeholder="gsk_mBSwu2..." type="password"></div>
        <button id="btnSaveGroqKey" class="primary">Enable Groq LLM Engine</button>
      </div>
      <div class="integration-card">
        <h4>🐳 Ephemeral Docker Sandbox</h4>
        <p>Execute isolated security probes inside Docker containers with 64MB RAM and network restrictions.</p>
        <div class="form-group"><label>Sandbox Status</label><div class="mono" style="font-size:12px;padding:6px 0">${state.dockerStatus?.docker_available?'Daemon Active ✅ · Policy Enforced':'CLI Mode / Standalone Isolated Probe'}</div></div>
        <button id="btnTestDockerSandbox" class="primary">Run Docker Probe Test</button>
      </div>
      <div class="integration-card">
        <h4>🚨 Live Outbound Webhook Dispatcher</h4>
        <p>Dispatch real formatted alert webhooks directly to your Slack, Discord, or HTTP endpoint.</p>
        <div class="form-group"><label>Target Webhook URL (Slack / Discord / HTTP)</label><input id="outboundUrl" value="https://httpbin.org/post"></div>
        <button id="btnDispatchWebhook" class="primary">Dispatch Real Webhook Alert</button>
      </div>
      <div class="integration-card">
        <h4>⚡ Continuous Inbound Webhook Intake</h4>
        <p>Stream findings directly into VulnTriager from GitHub Actions, CI/CD, or external security scanners.</p>
        <div class="form-group"><label>Inbound Webhook Endpoint</label><input readonly value="${window.location.origin}${API}/integrations/webhook/ingest"></div>
        <button id="btnSimulateWebhook" class="primary">Simulate Inbound Webhook</button>
      </div>
      <div class="integration-card">
        <h4>📋 Ticket Markdown Exporter</h4>
        <p>Generate formatted ticket payloads for Jira or GitHub Issues from active cases.</p>
        <div class="form-group"><label>Select Case</label><select id="exportCaseSelect">${state.cases.length?state.cases.map(c=>`<option value="${c.case_id}">${esc(c.title)} (${short(c.case_id)})</option>`).join(''):'<option value="">No active cases</option>'}</select></div>
        <div class="form-group"><label>Format</label><select id="exportFormatSelect"><option value="jira">Jira Markup</option><option value="github">GitHub Markdown</option></select></div>
        <button id="btnExportTicketPayload" class="primary" ${state.cases.length?'':'disabled'}>Generate Ticket Payload</button>
      </div>
    </div>`;
    $('#btnSaveGroqKey')?.addEventListener('click', saveGroqApiKey);
    $('#btnTestDockerSandbox')?.addEventListener('click', testDockerSandboxCard);
    $('#btnSimulateWebhook')?.addEventListener('click', simulateInboundWebhook);
    $('#btnDispatchWebhook')?.addEventListener('click', testOutboundWebhook);
    $('#btnExportTicketPayload')?.addEventListener('click', () => {
      const cId = $('#exportCaseSelect').value;
      const fmt = $('#exportFormatSelect').value;
      if(cId) exportTicketModal(cId, fmt);
    });
  }else{
    const rows=sorted(filtered(state.audit));
    w.innerHTML=rows.length?`<table><thead><tr>${thSort('when','When')}${thSort('action','Action')}${thSort('entity','Entity')}${thSort('actor','Actor')}${thSort('details','Details')}</tr></thead><tbody>${rows.map(a=>`<tr><td class="mono">${esc(new Date(a.occurred_at).toLocaleString())}</td><td><b>${esc(a.action)}</b></td><td>${esc(a.entity_type)}<small class="mono">${short(a.entity_id)}</small></td><td>${esc(a.actor)}</td><td class="mono">${esc(JSON.stringify(a.details))}</td></tr>`).join('')}</tbody></table>`:empty('No audit events have been recorded yet.');
  }
}

async function saveGroqApiKey(){
  const key = $('#groqApiKeyInput').value.trim();
  if(!key) return notice('Please enter a Groq API key (gsk_...).', true);
  busy(true);
  try{
    const res = await request(`${API}/settings/llm-key?api_key=${encodeURIComponent(key)}&provider=groq`, {method:'POST'});
    notice(`Groq LLM Engine activated! Provider: ${res.provider} (Model: ${res.model}).`);
  }catch(e){
    notice(`Could not update Groq API key: ${e.message}`, true);
  }finally{
    busy(false);
  }
}

async function generatePatch(id){
  busy(true);
  try{
    const patch = await request(`${API}/canonical-issues/${id}/remediation-patch`, {method:'POST'});
    open(`✨ AI Security Patch Fix: ${esc(patch.title)}`, `
      <div class="validation-banner">
        <b>Engine Provider: ${esc(patch.provider_used)}</b> · Confidence: ${(patch.confidence*100).toFixed(0)}% · Syntax Valid: <b>${patch.validation.is_valid_syntax ? 'YES ✅' : 'NO ❌'}</b>
      </div>
      <p><b>Human Explanation:</b> ${esc(patch.summary)}</p>
      <div class="diff-container">
        <p style="margin:0 0 8px;font-weight:600;color:var(--muted)">Git Unified Diff Patch:</p>
        <pre class="diff-code">${esc(patch.git_diff)}</pre>
      </div>
      <div class="code-compare">
        <div class="vulnerable">
          <h5>Original Vulnerable Code</h5>
          <pre>${esc(patch.vulnerable_code_snippet)}</pre>
        </div>
        <div class="fixed">
          <h5>Recommended Fixed Code</h5>
          <pre>${esc(patch.fixed_code_snippet)}</pre>
        </div>
      </div>
    `);
    notice(`Generated AI patch proposal for canonical issue ${short(id)}.`);
  }catch(e){
    notice(`Patch generation failed: ${e.message}`, true);
  }finally{
    busy(false);
  }
}

async function runDockerProbe(id){
  busy(true);
  try{
    const status = await request(`${API}/sandbox/docker/status`);
    const probe = await request(`${API}/sandbox/docker/execute/${id}`, {method:'POST'});
    open(`🐳 Docker Ephemeral Sandbox Execution`, `
      <div class="validation-banner">
        <b>Status: ${esc(probe.execution_status.toUpperCase())}</b> · Docker Host: ${status.docker_available ? 'Available ✅' : 'Not Running / Disabled'}
      </div>
      <dl class="kv">
        <dt>Execution Duration</dt><dd>${probe.execution_time_ms} ms</dd>
        <dt>Isolation Mode</dt><dd>network_mode=none · 64MB RAM limit</dd>
        <dt>Evidence SHA-256</dt><dd class="mono">${esc(probe.sha256_digest)}</dd>
        <dt>Limitations</dt><dd>${esc(probe.limitations)}</dd>
      </dl>
      <div class="evidence" style="margin-top:16px">
        <b>Stdout / Execution Summary</b>
        <pre>${esc(probe.stdout_summary || probe.stderr_summary || 'No output recorded.')}</pre>
      </div>
    `);
    notice(`Docker probe completed (${probe.execution_status}). Evidence digest recorded.`);
  }catch(e){
    notice(`Docker probe failed: ${e.message}`, true);
  }finally{
    busy(false);
  }
}

async function exportTicketModal(caseId, format='jira'){
  busy(true);
  try{
    const ticket = await request(`${API}/cases/${caseId}/export-ticket?format_type=${format}`, {method:'POST'});
    open(`📋 Export ${format.toUpperCase()} Ticket Payload`, `
      <div class="validation-banner">
        <b>Ticket Title:</b> ${esc(ticket.ticket_title)} <br>
        <b>Priority Level:</b> ${esc(ticket.priority_level)} · <b>Labels:</b> ${ticket.labels.map(l=>tag(l)).join(' ')}
      </div>
      <p style="font-weight:600;margin-bottom:6px">Copy & Paste Ticket Body (${format.toUpperCase()}):</p>
      <div class="ticket-preview">${esc(ticket.ticket_body_markdown)}</div>
    `);
    notice(`Exported case ticket in ${format} format.`);
  }catch(e){
    notice(`Ticket export failed: ${e.message}`, true);
  }finally{
    busy(false);
  }
}

async function testOutboundWebhook(){
  const target_url = $('#outboundUrl').value;
  if(!target_url) return notice('Please enter a target webhook URL.', true);
  busy(true);
  try{
    const res = await request(`${API}/integrations/test-webhook`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({target_url, event_type:'high_risk_alert', payload:{title:'SQLi Alert Test', risk_score:92.5, cwe_primary:'CWE-89', remediation_tier:'Immediate', summary:'Critical SQL injection finding requires analyst review.'}})
    });
    notice(`Webhook delivery result: ${res.message} (HTTP ${res.status_code})`, !res.success);
  }catch(e){
    notice(`Webhook dispatch error: ${e.message}`, true);
  }finally{
    busy(false);
  }
}

async function simulateInboundWebhook(){
  busy(true);
  try{
    const payload = {
      source_name: "github_actions_sarif",
      repository: "security-demo/payment-service",
      findings: [
        {
          ruleId: "CWE-89",
          message: { text: "Inbound Webhook SARIF: Dynamic SQL string concatenation detected in query" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "src/db/auth.py" } } }]
        }
      ]
    };
    const res = await request(`${API}/integrations/webhook/ingest`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    await refresh();
    notice(`Inbound Webhook Accepted! ${res.findings_processed} finding ingested into batch ${short(res.batch_id)}.`);
  }catch(e){
    notice(`Inbound webhook failed: ${e.message}`, true);
  }finally{
    busy(false);
  }
}

async function processViews(){if(!state.findings.length)throw new Error('Import findings before extracting views.');const errors=[];for(const [key,path] of [['views','extract-views'],['embeddings','generate-embeddings']]){step(key,'active','Working');for(const finding of state.findings)try{await request(`${API}/findings/${finding.finding_id}/${path}`,{method:'POST'})}catch(e){errors.push(e.message)}step(key,errors.length?'fail':'done',`${state.findings.length} processed`)}if(errors.length)throw new Error(`${errors.length} finding operations failed.`)}
async function extractOnly(){if(state.busy)return;busy(true);try{await processViews();await refresh();notice(`Views and representations generated for ${state.findings.length} findings.`)}catch(e){notice(e.message,true)}finally{busy(false)}}
async function dedupOnly(){if(state.busy)return;busy(true);try{if(!state.findings.length)throw new Error('Import findings before finding duplicates.');const d=await request(`${API}/deduplication/run`,{method:'POST'});step('dedup','done',`${d.total_canonical_issues} issues`);await refresh();notice(`Duplicate detection complete · ${d.total_canonical_issues} canonical issues published.`)}catch(e){notice(e.message,true)}finally{busy(false)}}
async function prioritizeOnly(){if(state.busy)return;busy(true);try{if(!state.issues.length)throw new Error('Run duplicate detection before scoring issues.');step('risk','active','Scoring');for(const issue of state.issues)await request(`${API}/canonical-issues/${issue.canonical_issue_id}/prioritize`,{method:'POST'});step('risk','done',`${state.issues.length} scored`);await refresh();notice(`Risk scoring complete · ${state.issues.length} issues now have explainable scores.`)}catch(e){step('risk','fail','Needs attention');notice(e.message,true)}finally{busy(false)}}
async function resolveIssue(id){const reason=window.prompt('Resolution reason (required):');if(!reason?.trim())return;const actor=window.prompt('Analyst ID:', 'analyst');if(!actor?.trim())return;busy(true);try{await request(`${API}/canonical-issues/${id}/resolve`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor,reason})});await refresh();notice('Issue marked solved and removed from the active queue. Evidence and audit history remain available.')}catch(e){notice(`Could not resolve issue: ${e.message}`,true)}finally{busy(false)}}
async function createCase(id){busy(true);try{await request(`${API}/canonical-issues/${id}/generate-case`,{method:'POST'});await refresh();state.view='cases';$$('[data-view]').forEach(x=>x.classList.toggle('active',x.dataset.view==='cases'));render();notice('Case assembled from the canonical issue and ready for analyst review.')}catch(e){notice(e.message,true)}finally{busy(false)}}
async function reviewCase(id,action){const reason=window.prompt(`Reason for ${action.replace('-',' ')}:`);if(!reason?.trim())return;const actor=window.prompt('Analyst ID:','analyst');if(!actor?.trim())return;busy(true);try{const path=action==='approve'?'approve':action==='request-evidence'?'request-evidence':null;const target=path?`${API}/cases/${id}/${path}`:`${API}/canonical-issues/${state.cases.find(c=>c.case_id===id).canonical_issue_id}/resolve`;await request(target,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({actor,reason})});await refresh();notice(`Case ${action.replace('-',' ')} recorded with an audit event.`)}catch(e){notice(e.message,true)}finally{busy(false)}}
function exportView(){const rows=state.view==='findings'?state.findings:state.view==='issues'?state.issues:state.view==='cases'?state.cases:state.view==='clusters'?state.clusters:state.audit;if(!rows.length)return notice('There is no data in this view to export.',true);const csv=rows.map(row=>JSON.stringify(row)).join('\n');const blob=new Blob([csv],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`triage-${state.view}.json`;a.click();URL.revokeObjectURL(a.href);notice(`Exported ${rows.length} ${state.view}.`)}
async function run(){if(!state.findings.length)return notice('Import findings or choose an included fixture first.',true);busy(true);const errors=[];try{await processViews();step('dedup','active','Clustering');const d=await request(`${API}/deduplication/run`,{method:'POST'});step('dedup','done',`${d.total_canonical_issues} issues`);await refresh();step('risk','active','Scoring');for(const i of state.issues)try{await request(`${API}/canonical-issues/${i.canonical_issue_id}/prioritize`,{method:'POST'})}catch(e){errors.push(e.message)}step('risk',errors.length?'fail':'done',`${state.issues.length} scored`);await refresh();notice(`Pipeline complete · ${state.findings.length} findings → ${state.issues.length} canonical issues → ${state.priorities.length} risk scores${errors.length?` · ${errors.length} warnings`:''}`,!!errors.length)}catch(e){notice(`Pipeline stopped: ${e.message}`,true)}finally{busy(false)}}
async function inspectFinding(id){const [f,v,e]=await Promise.all([request(`${API}/findings/${id}`),request(`${API}/findings/${id}/views`),request(`${API}/findings/${id}/embeddings`).catch(()=>null)]);open(f.vulnerability.title,`<div class="views">${['description','location','reproduction','impact'].map(k=>`<section class="view"><h4>${k} ${tag(v[k].status)}</h4><p>${esc(v[k].text||'No extracted text')}</p></section>`).join('')}</div><p class="mono">Embedding backend: ${esc(e?.embedding_model||'not generated')} · dimension ${e?.embedding_dimension||'—'}</p>`)}
function inspectIssue(id){
  const i=state.issues.find(x=>x.canonical_issue_id===id),p=priority(id);
  const synth = p?.factors?.llm_context || p?.llm_context;
  open(i.title,`
    <div style="display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap">
      <button class="patch-btn" data-patch="${i.canonical_issue_id}">✨ AI Patch Fix</button>
      <button class="docker-btn" data-docker="${i.canonical_issue_id}">🐳 Run Docker Probe</button>
      <button class="case" data-case-issue="${i.canonical_issue_id}">Create Case</button>
      <button class="resolve" data-resolve="${i.canonical_issue_id}">Mark Solved</button>
    </div>
    <dl class="kv">
      <dt>Issue identity</dt><dd class="mono">${esc(id)}</dd>
      <dt>Source reports</dt><dd>${i.source_finding_ids.length} across ${esc(i.source_scanners.join(', '))}</dd>
      <dt>Merge basis</dt><dd>${esc(i.merge_reason.join(' · '))}</dd>
    </dl>
    ${synth?`
      <div class="ai-synthesis-box">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <b style="color:var(--ink)">🤖 AI Contextual Synthesis</b>
          <span class="tag">${esc(synth.provider_used || 'groq')} (${esc(synth.model_used || 'openai/gpt-oss-20b')})</span>
        </div>
        <p style="margin:4px 0"><b>Exploitability:</b> ${esc(synth.exploitability_assessment)}</p>
        <p style="margin:4px 0"><b>Business Impact:</b> ${esc(synth.business_impact_analysis)}</p>
        <p style="margin:4px 0"><b>Remediation Guidance:</b> ${esc(synth.remediation_guidance)}</p>
        ${synth.evidence_basis?.length?`<p style="margin:6px 0 0"><small class="mono"><b>Evidence Basis:</b> ${esc(synth.evidence_basis.join(' · '))}</small></p>`:''}
      </div>
    `:''}
    ${p?`<div class="validation-banner">Latest validation: <b>${esc(p.factors.validation_status)}</b></div><div class="risk-number">${p.risk_score}</div><p>${tag(p.remediation_tier)}</p><div class="contrib">${Object.entries(p.factors.contributions||{}).map(([k,v])=>`<div><span class="mono">${esc(k)}</span><br><b>${Number(v).toFixed(2)} pts</b></div>`).join('')}</div>`:'<p>Run prioritization to calculate a risk score.</p>'}
  `);
}

async function testDockerSandboxCard(){
  if(!state.issues.length) return notice('Import findings and run pipeline first to test Docker sandbox on an issue.', true);
  runDockerProbe(state.issues[0].canonical_issue_id);
}
function inspectCluster(id){const c=state.clusters.find(x=>x.cluster_id===id);open('Cluster evidence',`<dl class="kv"><dt>Identity</dt><dd class="mono">${esc(id)}</dd><dt>Method</dt><dd>${esc(c.cluster_method)}</dd><dt>Status</dt><dd>${esc(c.status)}</dd><dt>Members</dt><dd>${c.members.map(m=>short(m.finding_id)).join(', ')}</dd><dt>Reasons</dt><dd>${esc(c.merge_reason.join(' · '))}</dd></dl>`)}
async function validate(id){busy(true);try{const v=await request(`${API}/canonical-issues/${id}/validate`,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}),e=await request(`${API}/validations/${v.validation_id}/evidence`);await request(`${API}/canonical-issues/${id}/prioritize`,{method:'POST'});await refresh();open('Controlled validation',`<div class="validation-banner"><b>${esc(v.status)}</b> · ${esc(v.scenario.toUpperCase())} offline fixture</div><p>${esc(v.execution_summary)}</p><p>${esc(v.limitations.join(' '))}</p><section class="evidence"><b>Redacted, integrity-checked artifact</b><pre>${esc(e.artifacts[0].content)}</pre><span class="mono">SHA-256 ${esc(e.artifacts[0].content_hash)}</span></section>`);notice('Offline validation stored and risk score recalculated.')}catch(e){notice(e.message,true)}finally{busy(false)}}
function open(title,body){$('#modalTitle').textContent=title;$('#modalBody').innerHTML=body;$('#detailDialog').showModal()}

$('#datasetGrid').onclick=e=>{const b=e.target.closest('[data-dataset]');if(b)showDataset(b.dataset.dataset)};
$('#loadDataset').onclick=()=>load([$('#loadDataset').dataset.id]);
$('#closeDataset').onclick=()=>$('#datasetDialog').close();
$('#loadAll').onclick=()=>load(state.datasets.map(x=>x.id));
$('#uploadForm').onsubmit=importExport;
$('#manualForm').onsubmit=addManual;
$$('[data-intake]').forEach(b=>b.onclick=()=>{$$('[data-intake]').forEach(x=>x.classList.toggle('active',x===b));$('#uploadForm').classList.toggle('hidden',b.dataset.intake!=='upload');$('#manualForm').classList.toggle('hidden',b.dataset.intake!=='manual')});
$('#runBtn').onclick=run;
$('#extractBtn').onclick=extractOnly;
$('#dedupBtn').onclick=dedupOnly;
$('#prioritizeBtn').onclick=prioritizeOnly;
$('#exportBtn').onclick=exportView;
$('#search').oninput=render;
$$('[data-view]').forEach(b=>b.onclick=()=>{$$('[data-view]').forEach(x=>x.classList.toggle('active',x===b));state.view=b.dataset.view;render()});

$('#tableWrap').onclick=e=>{
  const b=e.target.closest('button');
  if(!b)return;
  if(b.dataset.finding)inspectFinding(b.dataset.finding).catch(x=>notice(x.message,true));
  if(b.dataset.issue)inspectIssue(b.dataset.issue);
  if(b.dataset.patch)generatePatch(b.dataset.patch);
  if(b.dataset.docker)runDockerProbe(b.dataset.docker);
  if(b.dataset.ticket)exportTicketModal(b.dataset.ticket);
  if(b.dataset.cluster)inspectCluster(b.dataset.cluster);
  if(b.dataset.validate)validate(b.dataset.validate);
  if(b.dataset.resolve)resolveIssue(b.dataset.resolve);
  if(b.dataset.caseIssue)createCase(b.dataset.caseIssue);
  if(b.dataset.case)request(`${API}/cases/${b.dataset.case}`).then(x=>open(x.case.title,`<pre>${esc(JSON.stringify(x,null,2))}</pre>`));
  if(b.dataset.approve)reviewCase(b.dataset.approve,'approve');
  if(b.dataset.evidence)reviewCase(b.dataset.evidence,'request-evidence');
  if(b.dataset.caseResolve)reviewCase(b.dataset.caseResolve,'resolve')
};

document.addEventListener('click', e => {
  const th = e.target.closest('th.sortable-th');
  if (th && th.dataset.sort) {
    const k = th.dataset.sort;
    if (state.sortKey === k) {
      state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      state.sortKey = k;
      state.sortDir = (k === 'priority' || k === 'severity' || k === 'quality' || k === 'confidence' || k === 'sources') ? 'desc' : 'asc';
    }
    render();
  }
});

$('#closeModal').onclick=()=>$('#detailDialog').close();

(async()=>{try{const h=await request('/health');$('#healthDot').classList.add('ok');$('#healthText').textContent=`Backend online · ${h.tables_initialized} tables`;await Promise.all([catalog(),refresh()])}catch(e){$('#healthText').textContent='Backend unavailable';notice(e.message,true)}})();
