'use strict';
// Phase B composes the existing demo controls; P7 backend files belong to Copilot.
const workspace = { filters: {}, health: null, stale: [], opener: null };
const baseRender = render;
const viewLabels = {findings:'Findings',issues:'Canonical issues',clusters:'Clusters',priorities:'Priorities',validation:'Validation',cases:'Cases',system:'System'};

request = async function(path, options = {}) {
  const response = await fetch(path, options);
  const raw = await response.text();
  let body;
  try { body = JSON.parse(raw); } catch { body = null; }
  if (!response.ok) {
    const detail = body?.detail;
    const explanation = Array.isArray(detail) ? detail.map(x => `${(x.loc || []).join('.')}: ${x.msg}`).join('; ') : typeof detail === 'string' ? detail : `HTTP ${response.status}`;
    const error = new Error(`${options.method || 'GET'} ${path}: ${explanation}`);
    error.status = response.status;
    throw error;
  }
  if (body === null) throw new Error(`Invalid JSON response from ${path}`);
  return body;
};

async function allPages(path, key) {
  const records = [];
  for (let offset = 0; ; offset += 500) {
    const page = await request(`${API}${path}?limit=500&offset=${offset}`);
    if (!Array.isArray(page[key])) throw new Error(`Missing ${key} in ${path} response`);
    records.push(...page[key]);
    if (page[key].length < 500) return records;
  }
}

refresh = async function() {
  const collections = [['findings','/findings','findings'],['issues','/canonical-issues','canonical_issues'],['clusters','/clusters','clusters'],['priorities','/priorities','priorities'],['cases','/cases','cases']];
  const results = await Promise.allSettled(collections.map(([,path,key]) => allPages(path,key)));
  workspace.stale = [];
  results.forEach((result,index) => {
    const name = collections[index][0];
    if (result.status === 'fulfilled') state[name] = result.value;
    else workspace.stale.push(`${name}: ${result.reason.message}`);
  });
  try { await metrics(); } catch (error) { workspace.stale.push(`metrics: ${error.message}`); }
  render();
  if(typeof renderCases === 'function') renderCases();
  if (workspace.stale.length) notice(`Some data could not refresh. Previously loaded records retained.\n${workspace.stale.join('\n')}`,true);
};

busy = function(on) {
  state.busy = on;
  $$('button').forEach(button => {
    if (button.id !== 'closeModal' && !button.closest('.feature-nav') && !button.dataset.view) button.disabled = on;
  });
  $('#runBtn').textContent = on ? 'Working…' : 'Run core pipeline';
  $('#pipeline').setAttribute('aria-busy', String(on));
};

function currentFilter() { return workspace.filters[state.view] || {query:'',value:''}; }
function filterValue(item) {
  if (state.view === 'findings') return item.vulnerability.severity;
  if (state.view === 'clusters') return item.cluster_method;
  return item.remediation_tier || priority(item.canonical_issue_id)?.remediation_tier || '';
}
filtered = function(items) {
  const f = currentFilter();
  return items.filter(item => (!f.value || filterValue(item) === f.value) && (!f.query || JSON.stringify(item).toLowerCase().includes(f.query.toLowerCase())));
};

function selectView(view) {
  if(view === 'cases') { $('#cases').scrollIntoView({block:'start'}); return; }
  state.view = view;
  const f = currentFilter();
  $('#search').value = f.query;
  const values = view === 'findings' ? ['Critical','High','Medium','Low','Informational','Unknown'] : view === 'clusters' ? ['fingerprint','semantic','manual'] : ['Immediate','Accelerated','Standard'];
  $('#featureFilter').innerHTML = '<option value="">All</option>' + values.map(v => `<option>${esc(v)}</option>`).join('');
  $('#featureFilter').value = f.value;
  const noFilter = ['system','cases'].includes(view);
  $('#featureFilter').hidden = noFilter;
  $('#search').hidden = noFilter;
  $$('[data-view]').forEach(b => { b.classList.toggle('active',b.dataset.view===view); b.setAttribute('aria-pressed',String(b.dataset.view===view)); });
  $$('[data-module]').forEach(b => b.setAttribute('aria-pressed',String(b.dataset.module===view)));
  render();
  $('#evidence').scrollIntoView({block:'start'});
}

render = function() {
  const rows = state.view === 'priorities' || state.view === 'validation' ? filtered(state.priorities) : [];
  if (state.view === 'priorities') {
    $('#tableWrap').innerHTML = rows.length ? `<table><thead><tr><th>Issue</th><th>Tier</th><th>Risk score</th><th>Threat source</th><th>Action</th></tr></thead><tbody>${[...rows].sort((a,b)=>b.risk_score-a.risk_score).map(p=>`<tr><td>${esc(state.issues.find(i=>i.canonical_issue_id===p.canonical_issue_id)?.title || p.canonical_issue_id)}</td><td>${tag(p.remediation_tier)}</td><td>${esc(p.risk_score)} / 100</td><td>${esc(p.factors.threat_source || 'unknown')}</td><td><button class="inspect" data-issue="${esc(p.canonical_issue_id)}">Explain score</button></td></tr>`).join('')}</tbody></table>` : empty('No matching scores. Run the pipeline or clear the filters.');
  } else if (state.view === 'validation') {
    $('#tableWrap').innerHTML = `<p class="workspace-warning">Latest validation referenced by each priority score. This is not the complete run history. Offline simulation does not prove exploitability.</p>` + (rows.length ? `<table><thead><tr><th>Issue</th><th>Latest result</th><th>Action</th></tr></thead><tbody>${rows.map(p=>`<tr><td>${esc(state.issues.find(i=>i.canonical_issue_id===p.canonical_issue_id)?.title || p.canonical_issue_id)}</td><td>${tag(p.factors.validation_status)}</td><td class="actions">${p.factors.validation_id?`<button data-evidence="${esc(p.factors.validation_id)}">View evidence</button>`:''}<button data-validate="${esc(p.canonical_issue_id)}">Simulate validation</button></td></tr>`).join('')}</tbody></table>` : empty('Prioritize canonical issues to select a validation target.'));
  } else if (state.view === 'system') {
    const h = workspace.health;
    $('#tableWrap').innerHTML = `<div class="system-grid">${[['API',h?'Connected':'Not checked'],['SQLite',h?`${h.tables_initialized} tables initialized`:'Unknown'],['Threat intelligence',h?.threat_intelligence_mode || 'Unknown'],['Validation',h?.validation_status || 'Unknown'],['Model downloads',h?.model_download_allowed?'Allowed':'Disabled'],['Case queue',workspace.stale.some(x=>x.startsWith('cases:'))?'Unavailable':'Connected']].map(([key,value])=>`<section><h3>${esc(key)}</h3><p>${esc(value)}</p></section>`).join('')}</div><div class="workspace-detail"><button class="workspace-action" data-check-health>Check services again</button></div>`;
  } else if (state.view === 'cases') {
    $('#tableWrap').innerHTML = `<div class="empty"><h3>Case review integration</h3><p>Use the Human review queue below to assemble cases and record decisions.</p><p>The existing issue, risk and validation views remain available.</p></div>`;
  } else baseRender();
  $('#viewSummary').textContent = `${viewLabels[state.view]}${workspace.stale.length?' · Some data could not refresh; showing the last loaded records.':''}`;
};

open = function(title,body) {
  const dialog = $('#detailDialog');
  if (!dialog.open) workspace.opener = document.activeElement;
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = body;
  $('#closeModal').disabled = false;
  if (!dialog.open) dialog.showModal();
};

inspectFinding = async function(id) {
  const f = await request(`${API}/findings/${id}`);
  const details = await Promise.allSettled([request(`${API}/findings/${id}/views`),request(`${API}/findings/${id}/embeddings`)]);
  const views = details[0].status==='fulfilled'?details[0].value:null;
  const embeddings = details[1].status==='fulfilled'?details[1].value:null;
  open(f.vulnerability.title, `<dl class="kv"><dt>Scanner</dt><dd>${esc(f.source_scanner)}</dd><dt>Source file</dt><dd>${esc(f.provenance.source_file)}</dd><dt>Parser</dt><dd>${esc(f.provenance.parser_name)}</dd><dt>Raw record hash</dt><dd class="mono">${esc(f.provenance.raw_record_hash)}</dd><dt>Quality</dt><dd>${Math.round(f.quality.completeness_score*100)}%</dd></dl><ul>${f.quality.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul><div class="views">${['description','location','reproduction','impact'].map(k=>`<section class="view"><h4>${k} ${tag(views?.[k]?.status || 'unavailable')}</h4><p>${esc(views?.[k]?.text || 'No view available. Retry extraction.')}</p>${views?`<details><summary>Extraction provenance</summary><p>Confidence: ${esc(views[k].confidence)}</p><p>${esc((views[k].source_fields||[]).join(', '))}</p></details>`:''}</section>`).join('')}</div><h4>Embedding provenance</h4>${embeddings?`<dl class="kv"><dt>Backend</dt><dd>${esc(embeddings.embedding_model)}</dd><dt>Version</dt><dd>${esc(embeddings.model_version)}</dd><dt>Dimension</dt><dd>${esc(embeddings.embedding_dimension)}</dd></dl><p>Hashing fallback represents lexical similarity, not learned semantic evidence.</p>`:`<p>${details[1].reason?.status===404?'Embeddings have not been generated.':esc(details[1].reason?.message || 'Embedding status unavailable.')}</p>`}<div class="source-links"><button class="workspace-action" data-extract="${esc(id)}">Extract views</button><button class="workspace-action" data-embed="${esc(id)}">Generate embeddings</button></div>`);
};

inspectIssue = function(id) {
  const i=state.issues.find(x=>x.canonical_issue_id===id),p=priority(id);
  if (!i) return notice('Issue no longer available. Refresh the workspace.',true);
  open(i.title,`<dl class="kv"><dt>Issue ID</dt><dd class="mono">${esc(id)}</dd><dt>Merge basis</dt><dd>${esc(i.merge_reason.join(' · '))}</dd><dt>Source scanners</dt><dd>${esc(i.source_scanners.join(', '))}</dd></dl><div class="source-links">${i.source_finding_ids.map(fid=>`<button class="workspace-action" data-open-finding="${esc(fid)}">Finding ${short(fid)}</button>`).join('')}</div>${p?`<div class="risk-number">${esc(p.risk_score)} <small>/100</small></div>${tag(p.remediation_tier)}<div class="contrib">${Object.entries(p.factors.contributions || {}).map(([key,value])=>`<div>${esc(key)}<br><b>${Number(value).toFixed(2)} points</b><div class="risk-bar"><span style="width:${Math.max(0,Math.min(100,Number(value)))}%"></span></div></div>`).join('')}</div><ul>${p.explanation.map(x=>`<li>${esc(x)}</li>`).join('')}</ul><details><summary>Threat feed provenance</summary><pre>${esc(JSON.stringify(p.factors.threat_intelligence || [],null,2))}</pre></details>`:'<p>No priority calculated yet.</p>'}<button class="workspace-action" data-score="${esc(id)}">Recalculate priority</button>`);
};

async function showEvidence(id) {
  const [run,evidence]=await Promise.all([request(`${API}/validations/${id}`),request(`${API}/validations/${id}/evidence`)]);
  const artifacts=await Promise.all(evidence.artifacts.map(async artifact=>{
    let result='Verification unavailable';
    if(globalThis.crypto?.subtle){
      const bytes=new TextEncoder().encode(artifact.content);
      const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),v=>v.toString(16).padStart(2,'0')).join('');
      result=hash===artifact.content_hash && bytes.length===artifact.content_size?'Hash and size verified':'INTEGRITY MISMATCH';
    }
    return `<section class="evidence"><h4>${esc(artifact.artifact_type)} · ${esc(result)}</h4><pre>${esc(artifact.content)}</pre><p class="mono">SHA-256 ${esc(artifact.content_hash)}</p></section>`;
  }));
  open('Validation evidence',`<p class="workspace-warning">Offline simulation does not prove exploitability.</p>${tag(run.status)}<p>${esc(run.execution_summary)}</p><p>${esc(run.limitations.join(' '))}</p>${artifacts.join('') || '<p>No retained artifacts.</p>'}`);
}

async function checkHealth() {
  try {workspace.health=await request('/health');$('#healthDot').classList.add('ok');$('#healthText').textContent='Backend online';}
  catch(error){workspace.health=null;$('#healthDot').classList.remove('ok');$('#healthText').textContent='Backend unavailable';notice(error.message,true);}
  if(state.view==='system')render();
}

validate = async function(id) {
  if(state.busy)return;
  busy(true);
  try {
    const result=await request(`${API}/canonical-issues/${id}/validate`,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    let scoreError=null;
    try {await request(`${API}/canonical-issues/${id}/prioritize`,{method:'POST'});}catch(error){scoreError=error;}
    await refresh();
    await showEvidence(result.validation_id);
    notice(scoreError?`Validation saved as ${result.validation_id}. Score refresh failed: ${scoreError.message}`:'Validation evidence saved and priority recalculated.',!!scoreError);
  } catch(error) {notice(error.message,true);} finally {busy(false);}
};

run = async function() {
  if(state.busy)return;
  if(!state.findings.length)return notice('Load a prepared dataset first.',true);
  busy(true);
  const errors=[];
  let activeStage='views';
  ['views','embeddings','dedup','risk'].forEach(key=>step(key,'','Waiting'));
  try {
    for(const [key,path] of [['views','extract-views'],['embeddings','generate-embeddings']]) {
      activeStage=key;let failed=0;
      const findings=[...state.findings];
      for(let index=0;index<findings.length;index++) {
        step(key,'active',`${index+1} / ${findings.length}`);
        try {await request(`${API}/findings/${findings[index].finding_id}/${path}`,{method:'POST'});}
        catch(error){failed++;errors.push(error.message);}
      }
      step(key,failed?'fail':'done',`${findings.length-failed} completed, ${failed} failed`);
      if(failed)throw new Error(`${key} has failed records. Retry the pipeline to rebuild complete inputs.`);
    }
    activeStage='dedup';step('dedup','active','Grouping findings');
    const result=await request(`${API}/deduplication/run`,{method:'POST'});
    step('dedup','done',`${result.total_canonical_issues} issues · ${result.semantic_status}`);
    await refresh();
    if(workspace.stale.some(x=>x.startsWith('issues:')))throw new Error('Could not refresh the current issue list; retry before scoring.');
    activeStage='risk';let failed=0;
    for(let index=0;index<state.issues.length;index++) {
      step('risk','active',`${index+1} / ${state.issues.length}`);
      try {await request(`${API}/canonical-issues/${state.issues[index].canonical_issue_id}/prioritize`,{method:'POST'});}
      catch(error){failed++;errors.push(error.message);}
    }
    step('risk',failed?'fail':'done',`${state.issues.length-failed} completed, ${failed} failed`);
    await refresh();
    notice(errors.length?`Pipeline finished with errors:\n${errors.slice(0,5).join('\n')}`:'Core pipeline complete. Inspect priorities or explicitly simulate validation.',!!errors.length);
  } catch(error) {
    step(activeStage,'fail','Needs retry');
    notice(`${error.message}\n${errors.slice(0,3).join('\n')}`,true);
  } finally {busy(false);}
};

const featureNav=document.createElement('nav');
featureNav.className='feature-nav';featureNav.setAttribute('aria-label','Feature workspace');
featureNav.innerHTML=`<button data-section="corpus">Corpus</button><button data-section="pipeline">Pipeline</button>${Object.entries(viewLabels).map(([key,label])=>`<button data-module="${key}" aria-pressed="false">${label}</button>`).join('')}`;
$('#corpus').before(featureNav);
const filterControl=document.createElement('select');filterControl.id='featureFilter';filterControl.className='workspace-filter';filterControl.setAttribute('aria-label','Filter feature records');
$('.controls').append(filterControl);
const summary=document.createElement('div');summary.id='viewSummary';summary.className='workspace-summary';summary.setAttribute('role','status');$('#tableWrap').before(summary);
$('#search').setAttribute('aria-label','Search feature records');$('#notice').setAttribute('role','status');$('#notice').setAttribute('aria-live','polite');
featureNav.onclick=e=>{const b=e.target.closest('button');if(b?.dataset.module)selectView(b.dataset.module);if(b?.dataset.section)$(`#${b.dataset.section}`).scrollIntoView({block:'start'});};
$$('[data-view]').forEach(b=>b.onclick=()=>selectView(b.dataset.view));
function changeFilter(){workspace.filters[state.view]={query:$('#search').value,value:filterControl.value};render();}
$('#search').oninput=changeFilter;filterControl.onchange=changeFilter;
$('#detailDialog').addEventListener('close',()=>{if(workspace.opener?.isConnected)workspace.opener.focus();});
document.addEventListener('click',async event=>{
  const b=event.target.closest('button');if(!b)return;
  try{
    if(b.hasAttribute('data-check-health'))return await checkHealth();
    if(b.dataset.evidence)return await showEvidence(b.dataset.evidence);
    if(b.dataset.openFinding)return await inspectFinding(b.dataset.openFinding);
    const id=b.dataset.extract||b.dataset.embed||b.dataset.score;
    if(!id || state.busy)return;
    busy(true);
    try{
      const path=b.dataset.score?`/canonical-issues/${id}/prioritize`:`/findings/${id}/${b.dataset.extract?'extract-views':'generate-embeddings'}`;
      await request(API+path,{method:'POST'});
      await refresh();
      if(b.dataset.score)inspectIssue(id);else await inspectFinding(id);
      notice('Module operation completed.');
    }finally{busy(false)}
  }catch(error){notice(error.message,true)}
});
// Initial filter setup without scrolling away from the hero.
filterControl.innerHTML='<option value="">All severities</option>'+['Critical','High','Medium','Low','Informational','Unknown'].map(x=>`<option>${x}</option>`).join('');
checkHealth();
$('#runBtn').onclick=run;
