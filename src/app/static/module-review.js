'use strict';
// UI contracts in docs/MODULE_SPECS/C_module_review.md. Backend ownership remains with Copilot.
const moduleReview = {historyIssue:'', histories:{}, historyErrors:{}, loading:new Set()};
const renderBeforeReview = render;

render = function() {
  if(state.view !== 'validation') return renderBeforeReview();
  $('#search').hidden = true;
  $('#featureFilter').hidden = true;
  const id=moduleReview.historyIssue, rows=moduleReview.histories[id];
  $('#viewSummary').textContent='Validation history by issue';
  $('#tableWrap').innerHTML=`<div class="workspace-detail">
    <p class="workspace-warning">Offline simulation does not prove exploitability. History includes every retained run for the selected issue.</p>
    <form id="historyForm" class="source-links"><label for="historyIssue">Canonical issue</label>
      <input id="historyIssue" name="issue" list="historyIssues" required placeholder="Select or paste an issue ID" value="${esc(id)}">
      <datalist id="historyIssues">${state.issues.map(i=>`<option value="${esc(i.canonical_issue_id)}">${esc(i.title)}</option>`).join('')}</datalist>
      <button type="submit">Load history</button></form>
    <p>Paste a retained issue ID to inspect history after regrouping.</p>
    <p role="status">${moduleReview.loading.has(id)?'Loading history…':esc(moduleReview.historyErrors[id]||'')}</p>
    ${rows?`<p>${rows.length} retained run(s)</p>`:''}
    ${rows?.length?`<div class="table-wrap"><table><thead><tr><th>Time</th><th>Scenario</th><th>Result</th><th>Mode</th><th>Evidence</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.executed_at)}</td><td>${esc(r.scenario)}</td><td>${tag(r.status)}</td><td>${esc(r.sandbox_mode)}</td><td><button data-evidence="${esc(r.validation_id)}">Inspect artifacts</button></td></tr>`).join('')}</tbody></table></div>`:empty(rows?'No validation runs for this issue. Simulate validation from Canonical issues.':'Select an issue to load its history.')}
    </div>`;
};

async function loadIssueHistory(id) {
  id=id.trim();if(!id || moduleReview.loading.has(id))return;
  moduleReview.historyIssue=id;moduleReview.loading.add(id);delete moduleReview.historyErrors[id];
  if(state.view==='validation')render();
  try{moduleReview.histories[id]=await allPages(`/canonical-issues/${encodeURIComponent(id)}/validations`,'validations');}
  catch(error){moduleReview.historyErrors[id]=`${error.message}. Previously loaded history retained.`;}
  finally{moduleReview.loading.delete(id);if(state.view==='validation')render();}
}

inspectCluster = function(id) {
  const c=state.clusters.find(item=>item.cluster_id===id);
  if(!c)return notice('Cluster is unavailable. Refresh the workspace.',true);
  const members=c.members.map(member=>({id:member.finding_id,f:state.findings.find(f=>f.finding_id===member.finding_id)}));
  open('Compare cluster members',`<dl class="kv"><dt>Cluster</dt><dd>${esc(id)}</dd><dt>Method</dt><dd>${esc(c.cluster_method)}</dd><dt>Status</dt><dd>${tag(c.status)}</dd><dt>Merge reasons</dt><dd>${esc(c.merge_reason.join('; '))}</dd></dl>
    <div class="table-wrap"><table><thead><tr><th>Source</th><th>Finding / CWE</th><th>Host / path</th><th>Parameter / package</th><th>Details</th></tr></thead><tbody>${members.map(({id,f})=>`<tr><td>${esc(f?.source_scanner||'Unavailable')}</td><td>${esc(f?.vulnerability.title||id)}<br>${esc(f?.vulnerability.cwe_primary)}</td><td>${esc(f?.location.host)}<br>${esc(f?.location.path)}</td><td>${esc(f?.location.parameter)}<br>${esc(f?.location.package)}</td><td><button data-open-finding="${esc(id)}">Inspect source</button></td></tr>`).join('')}</tbody></table></div>
    <p class="workspace-warning">Confirm merge keeps compatible members together. Split separates all members into individual issues. Membership changes invalidate affected priority scores and mark dependent cases stale. Original findings and historical evidence are retained.</p>
    <p>Backend compatibility checks apply to every decision. Recalculate priorities after regrouping.</p>
    <div id="clusterError" role="alert"></div><div class="source-links"><button data-cluster-review="merge" data-review-id="${esc(id)}">Confirm merge</button><button data-cluster-review="split" data-review-id="${esc(id)}">Split into individual issues</button></div>`);
};

async function reviewCluster(id,action) {
  if(state.busy || !['merge','split'].includes(action))return;
  busy(true);
  try{
    await request(`${API}/clusters/${encodeURIComponent(id)}/${action}`,{method:'POST'});
    await refresh();
    if($('#detailDialog').open)$('#detailDialog').close();
    notice(`Cluster ${action} recorded. Review current canonical issues and recalculate affected priorities.`);
  }catch(error){const target=$('#clusterError');if(target)target.textContent=error.message;notice(error.message,true);}
  finally{busy(false);}
}

document.addEventListener('submit',event=>{
  if(event.target.id!=='historyForm')return;
  event.preventDefault();loadIssueHistory($('#historyIssue').value);
});
document.addEventListener('click',event=>{
  const b=event.target.closest('[data-cluster-review]');
  if(b)reviewCluster(b.dataset.reviewId,b.dataset.clusterReview);
});
