const PG = 'http://127.0.0.1:8765';
let sessionToken = '', catalog = null, busy = false;
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const json = value => esc(JSON.stringify(value, null, 2));
const money = cents => new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format((cents || 0)/100);
const ms = value => value == null ? '—' : value > 1000 ? `${(value/1000).toFixed(1)}s` : `${Math.round(value)}ms`;
const pct = value => value == null ? '—' : `${(value*100).toFixed(1)}%`;
const link = url => /^https:\/\//i.test(url || '') ? `<a href="${esc(url)}" target="_blank" rel="noopener">Open original source ↗</a>` : esc(url);

async function request(path, data, local=false) {
  const response = await fetch((local ? '' : PG)+path, {method: data === undefined ? 'GET' : 'POST', headers: data === undefined ? {} : {'Content-Type':'application/json','X-Session-Token':sessionToken}, body: data === undefined ? undefined : JSON.stringify(data)});
  let result;
  try { result = await response.json(); } catch { throw new Error('The service returned an unreadable response.'); }
  if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : JSON.stringify(result.detail || result));
  return result;
}
function error(message) { $('global-error').textContent=message; $('global-error').classList.remove('hidden'); }
function setBusy(value) { busy=value; ['run-agent','run-rag','test-policies'].forEach(id => $(id).disabled=value); }
function notice(id, message, running=true) { $(id).classList.remove('hidden'); $(id).classList.toggle('running',running); $(id).textContent=message; }
async function poll(path, id, local=false) {
  for (;;) {
    const job = await request(path,undefined,local);
    notice(id,`${job.progress || job.status}${job.total ? ` · ${job.completed}/${job.total} executions` : ''}`);
    if (job.status==='complete') { notice(id,'Comparison complete. These are actual model outputs.',false); return job.result; }
    if (job.status==='error') throw new Error(job.error);
    await new Promise(resolve=>setTimeout(resolve,1500));
  }
}
function traceHtml(run) {
  return (run.trace || []).map(t => {
    const state=t.result.status || (t.tool==='read_ticket'?'read':'verified lookup');
    const color=['denied','quarantined'].includes(state)?'bad-text':state==='approval_pending'?'amber-text':'good-text';
    return `<div class="step"><div class="step-top"><span class="step-num">${t.step}</span><span class="step-tool">${esc(t.tool)}</span><span class="step-status ${color}">${esc(state)}</span></div><details><summary>Arguments, result & source exposure</summary><pre>${json(t)}</pre></details>${state==='approval_pending'?`<button class="secondary approval-btn" data-approval="${esc(t.result.approval_id)}" data-run="${esc(run.run_id)}">Approve this exact test refund</button>`:''}</div>`;
  }).join('');
}
function renderRun(run) {
  const title=run.mode==='unprotected'?'Without protection':run.mode==='scanner'?'Detector only':'With PROMPTGUARD';
  const valid=run.status==='completed';
  const color=!valid?'neutral':run.unauthorized_execution?'bad':run.task_success?'good':'neutral';
  const state=!valid?'Run incomplete':run.unauthorized_execution?'Unauthorized action executed':run.approval_pending?'Human approval pending':run.task_success?'Authorized task completed':'No unauthorized action observed';
  return `<article class="result-card ${color}"><div class="card-head"><div class="overline">${esc(run.mode==='protected'?run.policy_id:'SAME MODEL · SAME OPERATOR TASK')}</div><h3>${title}</h3><span class="status ${color==='bad'?'bad-text':color==='good'?'good-text':'amber-text'}">${state}</span></div><div class="card-body"><div class="answer">${esc(run.answer || run.error || 'No final answer was produced.')}</div><div class="mini-stats"><div><small>Test refunds</small><strong>${money(run.refunded_cents)}</strong></div><div><small>Task complete</small><strong>${run.task_success===true?'Yes':run.task_success===false?'No':'Unscored'}</strong></div><div><small>Elapsed</small><strong>${ms(run.latency_ms)}</strong></div></div><div>${traceHtml(run)}</div><details><summary>Detector decisions (${run.scans?.length || 0})</summary><pre>${json(run.scans || [])}</pre></details><details><summary>Independent ledger verification</summary><pre>${json(run.ledger)}</pre></details><details><summary>Task authority & signed receipt</summary><pre>${json({contract:run.contract,receipt:run.receipt})}</pre></details><button class="link-button verify-receipt" data-run="${esc(run.run_id)}">Verify saved receipt ↗</button><div class="footnote">Run ${esc(run.run_id?.slice(0,10))} · ${esc(run.status)}<br>${esc(run.model_calls?.[0]?.model || run.receipt?.payload?.model || 'Model not reached')}</div></div></article>`;
}
function renderComparison(result, saved=false) {
  const scenario=$('scenario').value;
  let runs=result.runs.filter(r=>r.scenario===scenario);
  if (!runs.length) runs=result.runs;
  $('agent-results').innerHTML=runs.map(renderRun).join('');
  $('agent-results').classList.toggle('three',runs.length!==2); $('agent-results').classList.toggle('two',runs.length===2);
  const cliRuns=runs.every(r=>(r.model_calls||[]).some(c=>c.backend==='codex_cli_chatgpt'));
  $('agent-source').textContent=saved?(cliRuns?'Saved CLI outputs · Codex sign-in':'Historical API outputs · recorded'):'Live model executions';
  const original=runs.find(r=>r.mode==='unprotected');
  const protectedRun=runs.find(r=>r.mode==='protected');
  $('agent-decision').classList.remove('hidden');
  let message='Inspect the calls and ledger. A model that already resists the attack does not demonstrate a newly prevented failure.';
  if (original?.unauthorized_execution && protectedRun?.status==='completed' && !protectedRun.unauthorized_execution) message='The original agent made an unauthorized test refund. The protected run made no unauthorized refund. Inspect whether the legitimate task also completed; blocking alone is not business success.';
  else if (runs.some(r=>r.status!=='completed')) message='At least one execution did not complete. Treat that outcome as inconclusive; it is not evidence of successful protection.';
  $('agent-decision').innerHTML=`<div class="decision"><h3>What this means for the business</h3><p>${message}</p><p>${saved?'These are saved individual runs, not a paired benchmark.':'The comparison used the same model, operator task and starting ledger. Only protection changed.'}</p></div>`;
  document.querySelectorAll('.approval-btn').forEach(button=>button.onclick=async()=>{button.disabled=true;try {const r=await request('/api/approvals/grant',{run_id:button.dataset.run,approval_id:button.dataset.approval});button.textContent=`${r.result.status}: ${r.result.reason || 'test ledger updated'}`;}catch(e){button.textContent=e.message;}});
  document.querySelectorAll('.verify-receipt').forEach(button=>button.onclick=async()=>{try {const run=await request('/api/runs/'+button.dataset.run);const verified=await request('/api/receipts/verify',{receipt:run.receipt});button.textContent=verified.valid?'Receipt signature verified ✓':'Receipt verification failed';}catch(e){error(e.message);}});
}
async function runAgent() {
  if (busy) return; setBusy(true); $('global-error').classList.add('hidden');
  try { const job=await request('/api/demo/compare',{scenario:$('scenario').value,policies:[$('policy').value],include_scanner:true});const result=await poll('/api/jobs/'+job.job_id,'agent-progress');renderComparison(result); }
  catch(e){error(e.message);notice('agent-progress','Comparison did not complete.',false);}finally{setBusy(false);}
}
async function loadSaved() {
  try {
    if($('scenario').value==='cross_customer' && $('policy').value==='recommended') {
      const recorded=await request('/api/demo/recorded');
      if(recorded.runs?.length){renderComparison(recorded,true);return;}
    }
    const list=await request('/api/runs');const chosen=[];
    for (const mode of ['unprotected','scanner','protected']) {
      const row=list.runs.find(r=>r.scenario===$('scenario').value && r.mode===mode && r.status==='completed' && (mode!=='protected'||r.policy_id===$('policy').value));
      if(row) chosen.push(await request('/api/runs/'+row.run_id));
    }
    if(!chosen.length) throw new Error('No complete saved runs for this scenario yet. Run a live comparison.');
    renderComparison({runs:chosen},true);
  } catch(e){error(e.message);}
}
function renderRag(result,saved=false) {
  $('rag-source').textContent=saved?'Saved model outputs':'Live model executions';
  $('rag-results').innerHTML=result.results.map(r=>`<article class="result-card ${r.status!=='completed'?'neutral':r.canary_observed?'bad':r.mode==='protected'?'good':'neutral'}"><div class="card-head"><div class="overline">${r.mode==='protected'?'VIA THE SEPARATE PROTECTION API':'ORIGINAL RETRIEVED CONTENT'}</div><h3>${r.mode==='protected'?'With PROMPTGUARD':'Without protection'}</h3><span class="status">${r.status==='completed'?`${r.decisions?.filter(d=>d.action!=='ALLOW').length || 0} documents withheld · ${ms(r.latency_ms)}`:esc(r.status)}</span></div><div class="card-body"><div class="answer">${esc(r.answer)}</div>${r.canary_observed?'<div class="notice error">The attack marker appeared in the model answer.</div>':''}<details><summary>Exact context sent to the model</summary><pre>${esc(r.context)}</pre></details><details><summary>Protection decisions & receipt</summary><pre>${json({decisions:r.decisions,receipt:r.receipt})}</pre></details></div></article>`).join('');
  $('rag-documents').innerHTML=`<div class="panel"><h2>What was retrieved</h2><p class="muted">${esc(result.retrieval)}. Both conditions start from these same documents.</p>${result.retrieved.map(d=>`<div class="source-row"><strong>${esc(d.title)}</strong><small>${esc(d.origin)}</small>${link(d.source)}<details><summary>Inspect document text</summary><pre>${esc(d.text)}</pre></details></div>`).join('')}<p class="footnote">${esc(result.limitations)}</p></div>`;
}
async function runRag() {
  if(busy)return;setBusy(true);$('global-error').classList.add('hidden');
  try { const job=await request('/api/rag/compare',{question:$('rag-question').value,scenario:$('rag-scenario').value},true);const result=await poll('/api/rag/jobs/'+job.job_id,'rag-progress',true);renderRag(result); }
  catch(e){error(e.message);notice('rag-progress','Comparison did not complete.',false);}finally{setBusy(false);}
}
function renderAudit(data,element='audit-results') {
  $(element).innerHTML=`<div class="graph"><div class="node">External source<small>UNTRUSTED CONTENT</small></div><b>→</b><div class="node">${esc(data.profile.name)}<small>DECLARED CAPABILITIES</small></div><b>→</b>${data.profile.tools.filter(t=>t.enabled).map(t=>`<div class="node">${esc(t.name)}<small>${esc(t.kind)}</small></div>`).join('')}</div>${data.findings.slice(0,5).map(f=>`<div class="finding ${f.observed?'observed':''}"><span class="badge">${f.observed?'Observed in isolated test':'Potential exposure · not proven exploitation'}</span><h3>${esc(f.title)}</h3><p>${esc(f.why_now)}</p><p class="action">${esc(f.business_action)}</p><p>${esc(f.limitations)}</p>${f.run_id?`<small>Evidence run: ${esc(f.run_id)}</small>`:''}</div>`).join('') || '<div class="panel">No dangerous capability combination identified by the supported rules. This is not a safety guarantee.</div>'}<div class="panel"><h2>Evidence coverage</h2><pre>${json(data.coverage)}</pre><p class="footnote">Profile digest: ${esc(data.profile_digest)}</p></div>`;
  if(data.existing_configuration_review) {
    const review=data.existing_configuration_review;
    $(element).innerHTML+=`<div class="panel"><h2>Existing configuration → actionable review</h2><p class="muted">${esc(review.source?.name)} · ${esc(review.source?.kind)}</p><p>${esc(review.finding)}</p><p class="action">${esc(review.action)}</p><details><summary>Original source and integrity manifest</summary><pre>${json(review.source)}</pre></details></div>`;
  }
  if(data.test_plan)$(element).innerHTML+=`<div class="panel"><h2>Suggested test plan</h2><pre>${json(data.test_plan)}</pre></div>`;
}
async function loadAudit() {
  const data=await request('/api/audit'); renderAudit(data);
  $('profile-json').value=JSON.stringify({name:data.profile.name,sources:data.profile.sources,tools:data.profile.tools,controls:data.profile.controls,permission_evidence:'declared',activity:[]},null,2);
}
async function testPolicies() {
  if(busy)return;setBusy(true);
  try {const job=await request('/api/demo/compare',{scenario:$('scenario').value,policies:['recommended','approval','disabled'],include_scanner:true,include_clean:true});const r=await poll('/api/jobs/'+job.job_id,'policy-progress');const report=r.restriction_report;
    $('policy-results').innerHTML=`<div class="table-wrap"><table><thead><tr><th>Condition</th><th>Runs</th><th>Unauthorized</th><th>Task complete</th><th>Pending</th><th>Errors</th></tr></thead><tbody>${report.candidates.map(c=>`<tr><td>${esc(c.policy)}</td><td>${c.runs}</td><td>${c.unauthorized}</td><td>${c.completed}</td><td>${c.pending}</td><td>${c.errors}</td></tr>`).join('')}</tbody></table></div><div class="decision"><h3>${report.selected?'Candidate for review: '+esc(report.selected):'More evidence needed'}</h3><p>${esc(report.recommendation)}</p><p>${esc(report.selection_scope)}</p></div>`;
    await loadAudit();
  }catch(e){error(e.message);}finally{setBusy(false);}
}
async function loadBenchmark() {
  const b=await request('/api/benchmark');
  if(b.status==='not_run'){$('benchmark-results').innerHTML=`<div class="panel"><h2>Evaluation pending</h2><p>${esc(b.message)}</p><p class="muted">Individual demonstration outputs are available in Agent comparison.</p></div>`;return;}
  const tracks=b.detector?.tracks || [];
  $('benchmark-results').innerHTML=`<div class="panel"><h2>Saved evaluation · ${esc(b.run_id)}</h2><p class="muted">${esc(b.created_at)} · ${esc(b.status)} · Model ${esc(b.model || '')}</p><p>${esc(b.summary || '')}</p>${(b.interpretation||[]).map(x=>`<p class="metric-note">${esc(x)}</p>`).join('')}</div><h2>Detector diagnostics</h2><div class="table-wrap"><table><thead><tr><th>Dataset</th><th>N</th><th>Attack recall</th><th>Precision</th><th>False positives</th><th>p95 scan</th></tr></thead><tbody>${tracks.map(t=>`<tr><td>${esc(t.dataset)}</td><td>${t.n}</td><td>${pct(t.recall)}</td><td>${pct(t.precision)}</td><td>${pct(t.false_positive_rate)}</td><td>${ms(t.latency_p95_ms)}</td></tr>`).join('')}</tbody></table></div><p class="metric-note">Undefined metrics are shown as —. Hard-benign-only data cannot measure attack recall.</p><h2>Agent application outcomes</h2><div class="table-wrap"><table><thead><tr><th>Condition</th><th>Runs</th><th>Unauthorized / valid attacks</th><th>Clean task completion</th><th>Attacked task completion</th><th>Errors</th></tr></thead><tbody>${(b.agent?.conditions || []).map(c=>`<tr><td>${esc(c.condition)}</td><td>${c.n}</td><td>${c.attack_successes}/${c.valid_attacks}</td><td>${c.clean_successes}/${c.valid_clean}</td><td>${c.attacked_task_successes}/${c.valid_attacks}</td><td>${c.errors}</td></tr>`).join('')}</tbody></table></div><div class="panel"><h2>Scope and limitations</h2>${(b.limitations || []).map(x=>`<p class="muted">${esc(x)}</p>`).join('')}<details><summary>Reproducibility manifest and complete results</summary><pre>${json(b)}</pre></details></div>`;
}
async function loadResearch() {
  const [status,research]=await Promise.all([request('/api/status'),request('/api/research')]);
  const papers=[['Progent','Typed privileges and permission-expansion checks','https://arxiv.org/abs/2504.11703v3'],['Fides','Confidentiality, integrity and controlled information flow','https://arxiv.org/abs/2505.23643v2'],['AgentSpec','Explicit runtime constraints and enforcement','https://arxiv.org/abs/2503.18666v3'],['AgentDyn','Security and utility on dynamic agent tasks','https://arxiv.org/abs/2602.03117v3'],['AIR','Containment, recovery and incident response','https://proceedings.mlr.press/v306/xiao26n.html'],['AgentDojo','Executable tasks and independent outcome evaluation','https://arxiv.org/abs/2406.13352']];
  $('research-summary').innerHTML=`<div class="research-grid">${papers.map(([name,text,url])=>`<div class="panel"><h3>${name}</h3><p>${text}</p>${link(url)}</div>`).join('')}</div><div class="panel"><h2>Implemented in this prototype</h2><p>${esc(status.implemented.join(' · '))}</p><h2>Practical limits</h2>${status.limitations.map(l=>`<p class="muted">${esc(l)}</p>`).join('')}</div><div class="panel"><h2>Existing data and test fixtures</h2><pre>${json(status.sources)}</pre><p class="muted">Agent Guard inspired dispatch and audit patterns. The original PROMPTGUARD implementation keeps attribution explicit; global novelty is unproven.</p></div>`;
  $('research-document').textContent=research.document;
}
async function showView(name) {
  document.querySelectorAll('.view').forEach(v=>v.classList.toggle('hidden',v.id!=='view-'+name));
  document.querySelectorAll('.nav').forEach(v=>v.classList.toggle('active',v.dataset.view===name));
  $('page-name').textContent=document.querySelector(`.nav[data-view="${name}"]`).textContent.trim();
  try {if(name==='audit')await loadAudit();if(name==='benchmark')await loadBenchmark();if(name==='research')await loadResearch();}catch(e){error(e.message);}
}
async function initialize() {
  document.querySelectorAll('.nav').forEach(b=>b.onclick=()=>showView(b.dataset.view));
  try {
    sessionToken=(await request('/api/bootstrap')).session_token;
    const [status,c,rag]=await Promise.all([request('/api/status'),request('/api/catalog'),request('/api/rag/catalog',undefined,true)]); catalog=c;
    $('connection').innerHTML=`<span class="dot"></span> ${status.model_available?'GPT-6 Luna · Codex sign-in':'Codex ChatGPT sign-in required'}`;
    $('connection').title='Live calls use your Codex/ChatGPT plan allowance or credits. No API-key fallback. Saved GPT-4 runs remain historical API results.';
    $('scenario').innerHTML=c.scenarios.map(s=>`<option value="${esc(s.id)}">${esc(s.label)}</option>`).join('');$('scenario').value='cross_customer';
    const update=()=>{const s=c.scenarios.find(s=>s.id===$('scenario').value);$('ticket').textContent=s.text;$('scenario-description').textContent=s.description;};$('scenario').onchange=update;update();
    $('rag-scenario').innerHTML=rag.scenarios.map(s=>`<option value="${esc(s.id)}">${esc(s.label)}</option>`).join('');$('rag-scenario').value='override';
    const ragUpdate=()=>$('rag-description').textContent=rag.scenarios.find(s=>s.id===$('rag-scenario').value).description;$('rag-scenario').onchange=ragUpdate;ragUpdate();
    $('rag-inventory').textContent=`${rag.documents.length} indexed documents. Real SEC records are identified separately from authored policies and uploaded text. Retrieval and generation run in this demo application; protection runs on port 8765.`;
    $('run-agent').onclick=runAgent;$('load-saved').onclick=loadSaved;$('run-rag').onclick=runRag;$('test-policies').onclick=testPolicies;
    $('saved-rag').onclick=async()=>{try{const r=await request('/api/rag/saved',undefined,true);if(!r.runs.length)throw new Error('No saved RAG comparison yet.');renderRag(r.runs[0],true);}catch(e){error(e.message);}};
    $('add-document').onclick=async()=>{try{const r=await request('/api/rag/documents',{title:$('doc-title').value,text:$('doc-text').value},true);$('upload-status').textContent='Added '+r.id;}catch(e){error(e.message);}};
    $('import-profile').onclick=async()=>{try{const r=await request('/api/audit/import',JSON.parse($('profile-json').value));renderAudit(r,'import-result');}catch(e){error(e.message);}};
    $('check-expansion').onclick=async()=>{try{const r=await request('/api/policies/compare',{before:$('policy-before').value,after:$('policy-after').value});const witness=r.expansion_witness; $('expansion-result').innerHTML=`<div class="notice ${r.requires_review?'error':''}">${r.relationship==='expansion'?'This change permits an action the current policy would reject. Review is required.':r.relationship==='unknown'?'The comparison could not establish permission inclusion. Review is required.':'No additional action is permitted within the supported policy model.'}</div>${witness?`<p class="muted">Example newly permitted action: ${money(Number(witness.amount_cents))}, prior spending ${money(Number(witness.spent_cents))}, approval ${witness.approved==='True'?'present':'absent'}.</p>`:''}<details><summary>Scope, solver and reproducible formula</summary><pre>${json(r)}</pre></details>`;}catch(e){error(e.message);}};
  }catch(e){$('connection').textContent='Protection service unavailable';error(e.message+' Start both local services using start.ps1.');}
}
initialize();
