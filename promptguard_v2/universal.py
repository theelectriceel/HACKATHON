"""Explicit capability mappings and centrally versioned, deny-overriding restrictions."""
import json
import re
import uuid
from decimal import Decimal,InvalidOperation
from typing import Literal
from fastapi import APIRouter,Depends,HTTPException
from pydantic import Field,model_validator
from promptguard.common import canonical,digest
from .schema import Strict,IDENTIFIER

class UniversalPolicy(Strict):
    id: str = Field(pattern=IDENTIFIER)
    name: str = Field(min_length=1,max_length=150)
    version: int = Field(ge=1)
    scope: Literal['global','group','agent'] = 'global'
    targets: list[str] = Field(default_factory=list,max_length=30)
    capability: str = Field(pattern=IDENTIFIER)
    effect: Literal['DENY','REQUIRE_APPROVAL']
    mandatory: bool = True
    enabled: bool = True
    amount_limit_minor: int | None = Field(default=None,ge=0,le=100000000000)
    currency: str | None = Field(default=None,pattern=r'^[A-Z]{3}$')
    except_roles: list[str] = Field(default_factory=list,max_length=20)
    environment: Literal['production','development','test'] | None = None
    @model_validator(mode='after')
    def coherent(self):
        if (self.amount_limit_minor is None)!=(self.currency is None): raise ValueError('Money limits require explicit currency')
        if self.scope!='global' and not self.targets: raise ValueError('Scoped policies require targets')
        if self.scope=='global' and self.targets: raise ValueError('Global scope has no target filter')
        return self

def active(db):
    return [json.loads(r[0]) for r in db.execute('SELECT v.body FROM universal_versions v JOIN universal_active a USING(id,version) ORDER BY id')]

def in_scope(policy,identity):
    return policy['enabled'] and (policy['scope']=='global' or policy['scope']=='agent' and identity['agent_id'] in policy['targets'] or policy['scope']=='group' and bool(set(identity.get('groups',[]))&set(policy['targets'])))

def evaluate(policies,identity,tool,args,resource):
    matches=[];hard=[]
    for p in policies:
        if not in_scope(p,identity) or p['capability'] not in tool.get('capabilities',[]): continue
        if set(p['except_roles'])&set(identity.get('roles',[])): continue
        if p['environment']:
            if resource.get('environment') is None: hard.append('MISSING_TRUSTED_ENVIRONMENT');continue
            if resource['environment']!=p['environment']: continue
        if p['amount_limit_minor'] is not None:
            try:
                currency=args[tool['currency_field']];amount=args[tool['amount_field']]
                if currency!=p['currency']: raise ValueError('CURRENCY_NOT_COMPARABLE')
                if type(amount) not in (int,float,str): raise ValueError('INVALID_MONEY_AMOUNT')
                money=Decimal(str(amount))
                minor=money if tool.get('amount_unit','major')=='minor' else money*100
                if not minor.is_finite() or minor<0 or minor!=minor.to_integral_value(): raise ValueError('INVALID_MONEY_PRECISION')
            except (KeyError,TypeError,InvalidOperation): hard.append('MISSING_OR_INVALID_TRUSTED_MONEY_MAPPING');continue
            except ValueError as exc: hard.append(str(exc));continue
            if minor<=p['amount_limit_minor']: continue
        matches.append({'id':p['id'],'version':p['version'],'effect':p['effect'],'scope':p['scope'],'mandatory':p['mandatory'],'reason':p['name']})
    return matches,hard

def coverage(store,policies=None):
    with store.connection() as db:
        policies=active(db) if policies is None else policies
        identities=[json.loads(r[0]) for r in db.execute('SELECT profile FROM agents')]
        events=[json.loads(r[0]) for r in db.execute('SELECT data FROM events ORDER BY seq DESC LIMIT 100')]
    registry=[{'agent_id':i['agent_id'],'groups':i.get('groups',[]),'roles':i.get('roles',[]),'tool_name':t['name'],'tool_id':i['agent_id']+'::'+t['name'],
        'capabilities':t.get('capabilities',[]),'integration':t.get('integration','unverified'),'arguments_schema':t['arguments_schema'],
        'amount_field':t.get('amount_field'),'currency_field':t.get('currency_field'),'amount_unit':t.get('amount_unit','major'),
        'trusted_context_sources':['administrator-registered identity','administrator-registered resource attributes'],
        'observed_calls':sum(e['agent_id']==i['agent_id'] and e['tool_name']==t['name'] for e in events)} for i in identities for t in i['tools']]
    reports=[]
    for p in policies:
        covered=[r for r in registry if p['capability'] in r['capabilities'] and in_scope(p,next(i for i in identities if i['agent_id']==r['agent_id']))]
        reports.append({'policy':p,'covered_tools':covered,'covered_agents':sorted({r['agent_id'] for r in covered}),
            'unclassified_tools':[r['tool_id'] for r in registry if not r['capabilities']],
            'unverified_tools':[r['tool_id'] for r in covered if r['integration']=='unverified'],
            'status':'active' if p['enabled'] else 'disabled',
            'recent_decisions':[e for e in events if any(m['id']==p['id'] for m in e.get('matched_universal_policies',[]))][:10]})
    return {'registry':registry,'policies':reports,'limitation':'Coverage reflects explicit registration and observed calls. Unregistered agents and direct calls bypassing SDK/MCP are not protected.'}

class Instruction(Strict):
    instruction: str = Field(min_length=8,max_length=3000)
    policy_id: str | None = Field(default=None,pattern=IDENTIFIER)

def router(store,admin,sdk):
    api=APIRouter(prefix='/v1/universal')
    @api.get('/coverage',dependencies=[Depends(admin)])
    def get_coverage(): return coverage(store)

    @api.post('/drafts',dependencies=[Depends(admin)])
    def draft(body: UniversalPolicy):
        with store.transaction() as db:
            row=db.execute('SELECT version FROM universal_active WHERE id=?',(body.id,)).fetchone();base=row[0] if row else 0
            if body.version!=base+1: raise HTTPException(409,'Draft must use the next active version')
            identifier=uuid.uuid4().hex
            db.execute('INSERT INTO universal_drafts VALUES(?,?,?,0)',(identifier,body.model_dump_json(),base))
        return {'draft_id':identifier,'policy':body.model_dump(),'coverage':coverage(store,[body.model_dump()]),'active_changed':False}

    @api.post('/compile',dependencies=[Depends(admin)])
    def compile_policy(value: Instruction):
        from promptguard.codex_client import complete,ModelError
        catalog=coverage(store)
        with store.connection() as db: policies=active(db)
        prompt={'instruction':value.instruction,'selected_policy_id':value.policy_id,'registered_tools':[r for r in catalog['registry'] if r['capabilities']],'confirmed_capability_names':sorted({c for r in catalog['registry'] for c in r['capabilities']}),'existing_policies':policies,'schema':UniversalPolicy.model_json_schema(),
                'engine_semantics':{'amount_limit_minor':'Per-transaction limit. Cumulative limits are unsupported by this universal grammar.',
                    'approval':'REQUIRE_APPROVAL uses existing server-verified, exact-action, principal/session/arguments/policy-bound, expiring one-use approval records granted by an authenticated policy administrator acting as the manager. Never use an agent Boolean.',
                    'scope':'No agent / any agent means global. Selected policy ID may be new; a new ID starts at version 1.'}}
        prompt['engine_semantics']['draft_state']='A draft is inactive because it is not published. Set enabled=true for a draft intended to enforce after activation; enabled=false means explicitly disable the rule even after activation.'
        try:
            response=complete([{'role':'system','content':'Compile one explicit security restriction into JSON matching the supplied schema. The confirmed_capability_names list is the authoritative shared capability registry; tools with the same capability across different agent IDs are intentionally covered by one global policy. Agent-specific tool registration does not limit global policy scope. Use engine_semantics as authoritative implementation information. Return JSON only in content; no tool calls. Match only registered capability names. Never invent tool mappings or trusted attributes. Use the selected existing policy ID for updates; otherwise identify a unique relevant existing policy, or create an ID for a new rule. Version is active version +1, new policies use 1. Currency money limits are integer minor units (EUR100=10000). Roles/groups must come from registry or existing identities. If unsupported or ambiguous return {"error":"explanation"}. Never activate a policy.'},{'role':'user','content':canonical(prompt)}],max_tokens=1200)
            raw=response['message']['content'].strip();raw=re.sub(r'^```(?:json)?\s*|\s*```$','',raw)
            parsed=json.loads(raw)
            if 'error' in parsed: raise HTTPException(422,parsed['error'])
            policy=UniversalPolicy.model_validate(parsed)
            if value.policy_id and policy.id!=value.policy_id: raise HTTPException(422,'Compiler changed the selected policy identity')
            known={c for r in catalog['registry'] for c in r['capabilities']}
            if policy.capability not in known: raise HTTPException(422,'Capability has no developer-confirmed mapping')
        except (ValueError,ModelError) as exc: raise HTTPException(422,'Could not compile a valid draft; no active policy changed') from None
        return {**draft(policy),'compiler':{'model':response['model'],'backend':response['backend'],'uses_api_key':False}}

    @api.get('/drafts/{identifier}',dependencies=[Depends(admin)])
    def get_draft(identifier:str):
        with store.connection() as db:
            row=db.execute('SELECT body,tested FROM universal_drafts WHERE id=?',(identifier,)).fetchone()
        if not row:raise HTTPException(404,'Draft not found')
        body=json.loads(row['body'])
        return {'draft_id':identifier,'policy':body,'coverage':coverage(store,[body]),'tested':bool(row['tested']),'active_changed':False}

    @api.post('/drafts/{identifier}/test',dependencies=[Depends(admin)])
    def test_draft(identifier:str):
        with store.transaction() as db:
            row=db.execute('SELECT body FROM universal_drafts WHERE id=?',(identifier,)).fetchone()
            if not row: raise HTTPException(404,'Draft not found')
            p=json.loads(row[0]);results=[]
            for record in db.execute('SELECT profile FROM agents').fetchall():
                identity=json.loads(record[0])
                for tool in identity['tools']:
                    if p['capability'] not in tool.get('capabilities',[]) or not in_scope(p,identity):continue
                    probes=[{}]
                    if p['amount_limit_minor'] is not None:
                        probes=[{tool.get('amount_field'):(str(Decimal(n)/100) if tool.get('amount_unit','major')=='major' else n),tool.get('currency_field'):p['currency']} for n in [max(0,p['amount_limit_minor']-1),p['amount_limit_minor']+1]]
                    for args in probes:
                        matched,errors=evaluate([p],identity,tool,args,{})
                        results.append({'agent_id':identity['agent_id'],'tool':tool['name'],'probe':args,'decision':'DENY' if errors else matched[0]['effect'] if matched else 'NO_ADDITIONAL_RESTRICTION','errors':errors})
            db.execute('UPDATE universal_drafts SET tested=1 WHERE id=?',(identifier,))
        return {'tests':results,'method':'Boundary probes through the actual universal evaluator; not tool execution','active_changed':False}

    @api.post('/drafts/{identifier}/activate',dependencies=[Depends(admin)])
    def activate(identifier:str):
        with store.transaction() as db:
            row=db.execute('SELECT * FROM universal_drafts WHERE id=?',(identifier,)).fetchone()
            if not row:raise HTTPException(404,'Draft not found')
            if not row['tested']:raise HTTPException(409,'Test the draft before activation')
            body=json.loads(row['body']);current=db.execute('SELECT version FROM universal_active WHERE id=?',(body['id'],)).fetchone()
            if (current[0] if current else 0)!=row['base_version']:raise HTTPException(409,'Active version changed; compile a fresh draft')
            db.execute('INSERT INTO universal_versions VALUES(?,?,?)',(body['id'],body['version'],canonical(body)))
            db.execute('INSERT INTO universal_active VALUES(?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version',(body['id'],body['version']))
            store.audit(db,'universal_policy_activated',body['id'],{'version':body['version']})
        return {'activated':True,'policy':body,'coverage':coverage(store,[body])}

    @api.get('/history/{policy_id}',dependencies=[Depends(admin)])
    def history(policy_id:str):
        with store.connection() as db:return {'versions':[json.loads(r[0]) for r in db.execute('SELECT body FROM universal_versions WHERE id=? ORDER BY version',(policy_id,))]}

    @api.post('/rollback/{policy_id}/{version}',dependencies=[Depends(admin)])
    def rollback(policy_id:str,version:int):
        with store.connection() as db:
            row=db.execute('SELECT body FROM universal_versions WHERE id=? AND version=?',(policy_id,version)).fetchone()
            current=db.execute('SELECT version FROM universal_active WHERE id=?',(policy_id,)).fetchone()
        if not row or not current:raise HTTPException(404,'Policy version not found')
        body=json.loads(row[0]);body['version']=current[0]+1
        return draft(UniversalPolicy.model_validate(body))

    @api.get('/metadata/{tool_name}')
    def metadata(tool_name:str,identity=Depends(sdk)):
        tool=next((t for t in identity['tools'] if t['name']==tool_name),None)
        if not tool:raise HTTPException(404,'Tool not registered')
        return tool
    return api
