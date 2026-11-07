// End-to-end check of the exact three parts, using actual CLI model answers.
const fs=require('fs'),path=require('path');
let pw;try{pw=require('playwright')}catch{pw=require(path.join(process.env.USERPROFILE,'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'))}
async function main(){
 const root=process.cwd(),auth=JSON.parse(fs.readFileSync(path.join(root,'artifacts/v2/credentials.json'),'utf8'));
 const browser=await pw.chromium.launch({headless:true,channel:'chrome'});
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(t=>sessionStorage.setItem('pg-v2-admin',t),auth.admin_token);
 await page.goto('http://127.0.0.1:8775/#without');
 await page.locator('#rag-form').waitFor();
 if(await page.locator('.demo-nav').count()!==3)throw Error('Demo must have exactly three parts');
 const request=async(url,method='GET',body)=>{const r=await page.request.fetch('http://127.0.0.1:8775'+url,{method,headers:{Authorization:'Bearer '+auth.admin_token},data:body});if(!r.ok())throw Error('API '+r.status());return r.json()};
 // Preserve existing operator rules; isolate this verification from their settings.
 const rules=await request('/v1/demo/sequences'),disabled=[];let created=null;
 try{
  for(const r of rules.sequences)if(r.enabled){await request('/v1/demo/sequences/'+r.id,'PATCH',{enabled:false});disabled.push(r.id)}
  const run=async(view)=>{
   await page.locator('[data-view="'+view+'"]').click();await page.locator('#scenario').selectOption('override');
   await page.locator('#run').click();await page.waitForFunction(()=>document.querySelector('#notice').textContent.startsWith('RAG run finished')||document.querySelector('#notice').textContent.startsWith('The configured sequence was blocked'),null,{timeout:180000});
   await page.waitForFunction(()=>!document.querySelector('#run').disabled,null,{timeout:10000});
  };
  await run('without');
  if(!await page.locator('#result').innerText().then(t=>t.includes('Unprotected')))throw Error('Baseline calls not logged');
  await page.screenshot({path:path.join(root,'artifacts/v2/part-1-rag-without.png'),fullPage:true});
  await run('with');
  if(!await page.locator('#result').innerText().then(t=>t.includes('Withheld')))throw Error('Actual Horizon finding missing');
  await page.screenshot({path:path.join(root,'artifacts/v2/part-2-rag-with.png'),fullPage:true});
  await page.locator('[data-view="dashboard"]').click();await page.locator('#clear-sequence').click();
  for(const tool of ['search_documents','read_document','generate_answer'])await page.locator('[data-tool="'+tool+'"]').dragTo(page.locator('#dropzone'));
  if(await page.locator('.sequence-node').count()!==3)throw Error('Drag-and-drop sequence builder failed');
  const before=await request('/v1/demo/sequences');
  await page.locator('#block-sequence').click();await page.waitForFunction(()=>document.querySelector('#notice').textContent.startsWith('Sequence blocked'));
  const after=await request('/v1/demo/sequences');created=after.sequences.find(r=>!before.sequences.some(b=>b.id===r.id)).id;
  await run('with');
  if(!await page.locator('#result').innerText().then(t=>t.includes('Answering model was not called')))throw Error('Blocked sequence reached answering model');
  const activity=await request('/v1/demo/rag/activity'),last=activity.events.at(-1);
  if(last.tool_name!=='generate_answer'||last.decision!=='DENY'||last.executed!==false)throw Error('Actual generation function executed despite policy');
  await page.locator('[data-view="dashboard"]').click();await page.locator('#logs tbody tr').first().waitFor();
  await page.screenshot({path:path.join(root,'artifacts/v2/part-3-dashboard.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(root,'artifacts/v2/three-part-mobile.png'),fullPage:true});
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Horizontal mobile overflow');
  if(errors.length)throw Error(errors.join('; '));
  const verification={parts:3,real_cli_baseline:true,real_cli_protected:true,horizon_document_withheld:true,drag_and_drop:true,sequence_denial_prevented_model_call:true,tool_call_logging_both_modes:true,console_errors:errors};
  fs.writeFileSync(path.join(root,'artifacts/v2/three-part-verification.json'),JSON.stringify(verification,null,2));console.log(JSON.stringify(verification));
 }finally{
  if(created)await request('/v1/demo/sequences/'+created,'PATCH',{enabled:false});
  for(const id of disabled)await request('/v1/demo/sequences/'+id,'PATCH',{enabled:true});
  await browser.close();
 }
}
main().catch(e=>{console.error(e.stack);process.exit(1)});
