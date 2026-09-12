// Behavior checks for the browser-independent request/state layer. No packages required.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync('src/app/static/workspace.js','utf8').split('const featureNav=')[0];
function context(fetch){
  const ctx=vm.createContext({fetch,console,TextEncoder,crypto:require('node:crypto').webcrypto});
  vm.runInContext(`const API='/api/v1';const state={findings:[],issues:[],clusters:[],priorities:[],view:'findings'};
    const esc=x=>String(x??'');const elements={};const $=s=>elements[s]||=({textContent:'',classList:{},setAttribute(){}});const $$=()=>[];
    const tag=x=>x;const short=x=>x;const priority=()=>null;const empty=x=>x;
    let filtered,request;function render(){} function refresh(){} function metrics(){} function busy(){}
    function inspectFinding(){} function inspectIssue(){} function open(){} function validate(){} function run(){}
    function notice(){} function step(){}`,ctx);
  vm.runInContext(source,ctx);
  return ctx;
}
const response=(body,status=200)=>({ok:status===200,status,text:async()=>JSON.stringify(body),json:async()=>body});
test('pagination retrieves records beyond 500 without trusting page-local total',async()=>{
  let calls=0;const ctx=context(async()=>response({total:500,findings:++calls===1?Array.from({length:500},(_,id)=>({id})):[{id:500}]}));
  const records=await vm.runInContext("allPages('/findings','findings')",ctx);
  assert.equal(records.length,501);assert.equal(calls,2);
});
test('structured API errors retain method, path and field explanation',async()=>{
  const ctx=context(async()=>response({detail:[{loc:['body','reason'],msg:'Required'}]},422));
  await assert.rejects(vm.runInContext("request('/cases',{method:'POST'})",ctx),/POST \/cases: body.reason: Required/);
});
test('failed collection refresh keeps earlier records',async()=>{
  const ctx=context(async path=>path.includes('/findings?')?response({detail:'Down'},503):response({canonical_issues:[],clusters:[],priorities:[],cases:[]}));
  vm.runInContext("state.findings=[{finding_id:'keep'}];render=()=>{};",ctx);
  await vm.runInContext('refresh()',ctx);
  assert.equal(vm.runInContext('state.findings[0].finding_id',ctx),'keep');
  assert.equal(vm.runInContext('workspace.stale.length',ctx),1);
});
test('filters are scoped to each module',()=>{
  const ctx=context();
  vm.runInContext("workspace.filters.findings={query:'login',value:'High'}",ctx);
  assert.equal(vm.runInContext("filtered([{title:'login',vulnerability:{severity:'High'}},{title:'other',vulnerability:{severity:'High'}}]).length",ctx),1);
  vm.runInContext("state.view='clusters'",ctx);
  assert.equal(vm.runInContext("filtered([{cluster_method:'manual'}]).length",ctx),1);
});

test('all frontend scripts initialize together and refresh the case queue',async()=>{
  const elements=new Map();
  const element=()=>({textContent:'',innerHTML:'',value:'',dataset:{},classList:{add(){},remove(){},toggle(){}},setAttribute(){},addEventListener(){},append(){},before(){},querySelector(){return element()},closest(){return null}});
  const document={querySelector(selector){if(!elements.has(selector))elements.set(selector,element());return elements.get(selector)},querySelectorAll(){return []},createElement:element,addEventListener(){}};
  const ctx=vm.createContext({document,console,TextEncoder,crypto:require('node:crypto').webcrypto,fetch:async path=>response(
    path==='/health'?{tables_initialized:14}:path.includes('/demo/datasets')?{datasets:[]}:
    path.includes('/cases?')?{cases:[{case_id:'case-1',canonical_issue_id:'issue-1',status:'pending_review',title:'Review me'}]}:
    {findings:[],canonical_issues:[],clusters:[],priorities:[]})});
  vm.runInContext(fs.readFileSync('src/app/static/dashboard.js','utf8'),ctx);
  vm.runInContext(fs.readFileSync('src/app/static/workspace.js','utf8'),ctx);
  vm.runInContext(fs.readFileSync('src/app/static/module-review.js','utf8'),ctx);
  vm.runInContext(fs.readFileSync('src/app/static/case-review.js','utf8'),ctx);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(typeof elements.get('#generateCases').onclick,'function');
  assert.equal(vm.runInContext('state.cases.length',ctx),1);
  assert.match(elements.get('#caseWrap').innerHTML,/Review me/);
  assert.match(elements.get('#healthText').textContent,/Backend online/);
});

function reviewContext(fetch){
  const ctx=context(fetch);
  vm.runInContext("const document={addEventListener(){}};function inspectCluster(){}",ctx);
  vm.runInContext(fs.readFileSync('src/app/static/module-review.js','utf8'),ctx);
  return ctx;
}

test('history uses the selected issue, all pages, and retains runs on failure',async()=>{
  let fail=false;const paths=[];
  const ctx=reviewContext(async path=>{paths.push(path);return fail?response({detail:'Offline'},503):response({validations:[{validation_id:'old-run'}]});});
  await vm.runInContext("loadIssueHistory('retired-issue')",ctx);
  assert.match(paths[0],/canonical-issues\/retired-issue\/validations\?limit=500/);
  fail=true;
  await vm.runInContext("loadIssueHistory('retired-issue')",ctx);
  assert.equal(vm.runInContext("moduleReview.histories['retired-issue'][0].validation_id",ctx),'old-run');
  assert.match(vm.runInContext("moduleReview.historyErrors['retired-issue']",ctx),/Offline/);
  assert.equal(vm.runInContext('moduleReview.loading.size',ctx),0);
});

test('cluster conflicts retain the dialog and release busy state',async()=>{
  const calls=[];
  const ctx=reviewContext(async(path,options)=>{calls.push([path,options.method]);return response({detail:'Incompatible members'},409);});
  vm.runInContext("busy=on=>{state.busy=on};",ctx);
  await vm.runInContext("reviewCluster('cluster-1','merge')",ctx);
  assert.deepEqual(calls,[['/api/v1/clusters/cluster-1/merge','POST']]);
  assert.equal(vm.runInContext('state.busy',ctx),false);
  assert.match(vm.runInContext("$('#clusterError').textContent",ctx),/Incompatible members/);
  vm.runInContext('state.busy=true',ctx);
  await vm.runInContext("reviewCluster('cluster-1','split')",ctx);
  assert.equal(calls.length,1);
});

function caseContext(fetch){
  const ctx=reviewContext(fetch);
  vm.runInContext('function inspectCase(){} function reviewCase(){};let rendered="";open=(title,html)=>{rendered=html};busy=on=>{state.busy=on};refresh=async()=>{};',ctx);
  vm.runInContext(fs.readFileSync('src/app/static/case-review.js','utf8'),ctx);
  return ctx;
}

test('case decisions require nonblank identity and reason before submitting',async()=>{
  let calls=0;const ctx=caseContext(async()=>{calls++;return response({})});
  await vm.runInContext("submitCaseDecision('case-1',{action:'approve',actor_id:' ',reason:'why',comment:''})",ctx);
  assert.equal(calls,0);
  assert.match(vm.runInContext("$('#caseReviewError').textContent",ctx),/nonblank reason/);
});

test('case override sends typed payload and conflicts preserve the form',async()=>{
  const calls=[];const ctx=caseContext(async(path,options)=>{calls.push([path,JSON.parse(options.body)]);return response({detail:'Case is stale'},409)});
  vm.runInContext("rendered='entered form content'",ctx);
  await vm.runInContext("submitCaseDecision('case-1',{action:'override_priority',actor_id:' analyst ',reason:' impact ',comment:'',new_tier:'Accelerated'})",ctx);
  assert.deepEqual(calls,[['/api/v1/cases/case-1/override-priority',{actor_id:'analyst',reason:'impact',comment:null,new_tier:'Accelerated'}]]);
  assert.equal(vm.runInContext('rendered',ctx),'entered form content');
  assert.match(vm.runInContext("$('#caseReviewError').textContent",ctx),/Case is stale/);
  assert.equal(vm.runInContext('state.busy',ctx),false);
});

test('terminal and stale case details suppress decision forms',()=>{
  const ctx=caseContext();
  vm.runInContext("showCaseDetail({case_id:'case-1',status:'approved'})",ctx);
  assert.doesNotMatch(vm.runInContext('rendered',ctx),/caseDecisionForm/);
  vm.runInContext("showCaseDetail({case_id:'case-1',status:'pending_review',stale:true})",ctx);
  assert.doesNotMatch(vm.runInContext('rendered',ctx),/caseDecisionForm/);
  assert.match(vm.runInContext('rendered',ctx),/Regenerate case/);
});

test('cluster success refreshes dependent collections',async()=>{
  const ctx=reviewContext(async()=>response({status:'split'}));
  vm.runInContext("let refreshed=0;refresh=async()=>{refreshed++};busy=on=>{state.busy=on}",ctx);
  await vm.runInContext("reviewCluster('cluster-1','split')",ctx);
  assert.equal(vm.runInContext('refreshed',ctx),1);
  assert.equal(vm.runInContext('state.busy',ctx),false);
});
