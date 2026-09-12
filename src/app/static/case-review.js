'use strict';
const caseReview = {current:null};
const reviewLabels={approve:'Approve',reject:'Reject',request_evidence:'Request evidence',override_priority:'Override priority'};

function showCaseDetail(c,selected='approve') {
  caseReview.current=c;
  const data=c.case_data||{},terminal=['approved','rejected'].includes(c.status);
  const editable=!c.stale&&!terminal;
  open(c.title,`<p>${tag(c.status)} ${c.stale?tag('Stale'):''}</p><p>${esc(c.summary)}</p>
    <dl class="kv"><dt>Case ID</dt><dd>${esc(c.case_id)}</dd><dt>Canonical issue</dt><dd>${esc(c.canonical_issue_id)}</dd>
    <dt>Priority</dt><dd>${data.priority?`${esc(data.priority.remediation_tier)} · ${esc(data.priority.risk_score??'Not scored')}`:'Not prioritized'}</dd>
    <dt>Validation</dt><dd>${data.validation?'Offline simulation; not proof of exploitability':'No validation in this snapshot'}</dd></dl>
    <div class="source-links">${(data.findings||[]).map(item=>`<button data-open-finding="${esc(item.finding.finding_id)}">${esc(item.finding.source_scanner)} · ${short(item.finding.finding_id)}</button>`).join('')}</div>
    <details><summary>Review history (${c.reviews?.length||0})</summary>${c.reviews?.length?`<ol>${c.reviews.map(r=>`<li><b>${esc(r.action)}</b> · ${esc(r.actor_id)} · ${esc(r.reviewed_at)}<p>${esc(r.reason)}</p>${r.comment?`<p>${esc(r.comment)}</p>`:''}</li>`).join('')}</ol>`:'<p>No decisions recorded.</p>'}</details>
    <details><summary>Audit timeline (${c.audit_events?.length||0})</summary>${c.audit_events?.length?`<ol>${c.audit_events.map(e=>`<li><b>${esc(e.action)}</b> · ${esc(e.actor)} · ${esc(e.occurred_at)}<pre>${esc(JSON.stringify(e.details,null,2))}</pre></li>`).join('')}</ol>`:'<p>No audit events available.</p>'}</details>
    <div id="caseReviewError" role="alert"></div>
    ${c.stale?`<p class="workspace-warning">This snapshot is stale. Regenerate it before review. Retired issues cannot be regenerated.</p><button data-rebuild-case="${esc(c.canonical_issue_id)}">Regenerate case</button>`:''}
    ${editable?`<form id="caseDecisionForm" class="case-decision-form">
      <h4>Record an analyst decision</h4><label for="caseAction">Decision</label><select id="caseAction" name="action">${Object.entries(reviewLabels).map(([key,label])=>`<option value="${key}" ${key===selected?'selected':''}>${label}</option>`).join('')}</select>
      <label for="caseActor">Analyst identity</label><input id="caseActor" name="actor_id" required maxlength="120" autocomplete="username">
      <label for="caseReason">Reason</label><textarea id="caseReason" name="reason" required maxlength="4000" rows="3"></textarea>
      <label for="caseComment">Additional comment (optional)</label><textarea id="caseComment" name="comment" maxlength="4000" rows="2"></textarea>
      <div id="caseTierField" ${selected==='override_priority'?'':'hidden'}><label for="caseTier">New remediation tier</label><select id="caseTier" name="new_tier"><option>Immediate</option><option>Accelerated</option><option>Standard</option></select></div>
      <button type="submit" class="primary">Record decision</button></form>`:terminal?'<p>This case has a final decision. Its review and audit history remain available.</p>':''}`);
}

inspectCase=async function(id){
  try{showCaseDetail(await request(`${API}/cases/${encodeURIComponent(id)}`));}
  catch(error){notice(error.message,true);}
};
// Existing queue buttons select a form action; they never submit a decision directly.
reviewCase=async function(id,kind){
  if(state.busy)return;
  try{showCaseDetail(await request(`${API}/cases/${encodeURIComponent(id)}`),kind);}
  catch(error){notice(error.message,true);}
};

async function submitCaseDecision(id,fields){
  if(state.busy)return;
  const errorTarget=$('#caseReviewError');
  const action=fields.action;
  const body={actor_id:fields.actor_id.trim(),reason:fields.reason.trim(),comment:fields.comment.trim()||null};
  if(!reviewLabels[action]||!body.actor_id||!body.reason){errorTarget.textContent='Choose a decision and provide an analyst identity and a nonblank reason.';return;}
  if(action==='override_priority')body.new_tier=fields.new_tier;
  busy(true);errorTarget.textContent='';
  try{
    const result=await request(`${API}/cases/${encodeURIComponent(id)}/${action.replaceAll('_','-')}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    await refresh();showCaseDetail(result);notice('Analyst decision saved with review and audit history.');
  }catch(error){errorTarget.textContent=error.message;}
  finally{busy(false);}
}

document.addEventListener('change',event=>{if(event.target.id==='caseAction')$('#caseTierField').hidden=event.target.value!=='override_priority';});
document.addEventListener('submit',event=>{
  if(event.target.id!=='caseDecisionForm')return;
  event.preventDefault();
  const form=event.target;
  submitCaseDecision(caseReview.current.case_id,Object.fromEntries(new FormData(form)));
});
document.addEventListener('click',async event=>{
  const b=event.target.closest('[data-rebuild-case]');if(!b||state.busy)return;
  busy(true);
  try{const c=await request(`${API}/canonical-issues/${encodeURIComponent(b.dataset.rebuildCase)}/generate-case`,{method:'POST'});await refresh();await inspectCase(c.case_id);}
  catch(error){$('#caseReviewError').textContent=error.message;}
  finally{busy(false);}
});
