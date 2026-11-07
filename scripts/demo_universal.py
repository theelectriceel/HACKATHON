"""One CLI-compiled policy, three independent processes, real remote enforcement."""
import json,os,subprocess,sys,time
import httpx
from promptguard.common import ROOT,utcnow
from promptguard.codex_client import child_environment
from promptguard_v2.storage import credentials,V2

def demonstrate(endpoint='http://127.0.0.1:8775'):
    workers=[];auth=credentials();headers={'Authorization':'Bearer '+auth['admin_token']};pid={}
    with httpx.Client(base_url=endpoint,headers=headers,trust_env=False,timeout=180) as api:
        def request(method,path,body=None):
            r=api.request(method,path,json=body);r.raise_for_status();return r.json()
        def publish_draft(draft):
            request('POST','/v1/universal/drafts/'+draft['draft_id']+'/test',{})
            return request('POST','/v1/universal/drafts/'+draft['draft_id']+'/activate',{})
        policy_id='universal-demo-financial-limit'
        existing=request('GET','/v1/universal/coverage')['policies']
        previous=next((p['policy'] for p in existing if p['policy']['id']==policy_id),None)
        if previous:
            previous.update(enabled=False,version=previous['version']+1)
            publish_draft(request('POST','/v1/universal/drafts',previous))
        try:
            for role,tool,capability in [('support','issue_refund','financial_transaction'),('finance','send_payment','financial_transaction'),('sales','apply_discount','discount_adjustment')]:
                agent='universal-demo-'+role
                schema={'type':'object','properties':{'amount':{'type':'number','minimum':0},'currency':{'type':'string','enum':['EUR','USD']}},'required':['amount','currency'],'additionalProperties':False}
                profile={'agent_id':agent,'principal_id':'demo-'+role,'tenant_id':'universal-demo','policy_id':agent,'groups':[role],
                    'tools':[{'name':tool,'capabilities':[capability],'amount_field':'amount','currency_field':'currency','integration':'sdk','arguments_schema':schema,'log_arguments':['amount','currency']}]}
                token=request('POST','/v1/agents',profile)['agent_token']
                policies=request('GET','/v1/policies')['policies'];old=next((p for p in policies if p['policy_id']==agent),None)
                if not old:request('PUT','/v1/policies/'+agent,{'policy_id':agent,'version':1,'rules':[{'id':'permit-'+tool,'tool':tool,'effect':'ALLOW','reason':'Isolated demo operation permitted'}]})
                process=subprocess.Popen([sys.executable,'-m','scripts.universal_worker'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8',cwd=ROOT,env=child_environment(),creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
                process.stdin.write(json.dumps({'agent_id':agent,'token':token,'endpoint':endpoint,'tool':tool,'capability':capability})+'\n');process.stdin.flush()
                workers.append(process);pid[role]=process.pid
            def call(index,amount):
                process=workers[index];process.stdin.write(json.dumps({'amount':amount,'currency':'EUR'})+'\n');process.stdin.flush()
                line=process.stdout.readline()
                if not line:raise RuntimeError('Independent agent exited; no result fabricated')
                return json.loads(line)
            before=[call(0,150),call(1,250),call(2,250)]
            assert all(r['decision']=='ALLOW' for r in before)
            draft=request('POST','/v1/universal/compile',{'instruction':'No agent may perform financial transactions above EUR 100 without manager approval. Create or update the selected global policy.','policy_id':policy_id})
            assert draft['policy']['amount_limit_minor']==10000 and draft['policy']['currency']=='EUR' and draft['policy']['scope']=='global'
            activated=publish_draft(draft)
            restricted=[call(0,150),call(1,250),call(0,50),call(2,250)]
            assert [r['decision'] for r in restricted]==['REQUIRE_APPROVAL','REQUIRE_APPROVAL','ALLOW','ALLOW']
            assert restricted[0]['counter']==before[0]['counter'] and restricted[1]['counter']==before[1]['counter']
            updated=request('POST','/v1/universal/compile',{'instruction':'Change the selected global financial transaction limit to EUR 300; keep its approval requirement and scope.','policy_id':policy_id})
            assert updated['policy']['amount_limit_minor']==30000
            publish_draft(updated)
            after=[call(0,150),call(1,250)]
            assert all(r['decision']=='ALLOW' for r in after)
            report={'created_at':utcnow(),'before':before,'after_100_eur':restricted,'after_300_eur':after,'unchanged_agent_pids':pid,
                'initial_policy':draft['policy'],'updated_policy':updated['policy'],'compiler':draft['compiler'],'coverage':request('GET','/v1/universal/coverage'),
                'limitations':'Three independent scripted tool agents with isolated side-effect counters; no real funds. Sales discounts are deliberately not mapped to financial transactions.'}
            (V2/'universal-demo.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps({k:v for k,v in report.items() if k!='coverage'},indent=2))
            return report
        finally:
            for process in workers:
                try:process.stdin.write('{"stop":true}\n');process.stdin.flush();process.wait(timeout=8)
                except (OSError,subprocess.TimeoutExpired):process.kill()
if __name__=='__main__':demonstrate()
