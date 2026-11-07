import pytest,uuid
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from promptguard_v2.api import create_app
from promptguard_v2.storage import Store
from promptguard_v2.engine import Engine
from promptguard_v2.schema import AgentRegistration,Policy
from promptguard_v2.sdk import PromptGuard,AuthorizationDenied,ApprovalRequired,ServiceUnavailable

@pytest.fixture
def env(tmp_path):
    store=Store(tmp_path/'universal.sqlite3')
    for agent,tool,cap in [('support','issue_refund','financial_transaction'),('finance','send_payment','financial_transaction'),('sales','apply_discount','discount_adjustment')]:
        spec={'name':tool,'capabilities':[cap],'amount_field':'amount','currency_field':'currency','integration':'sdk',
            'arguments_schema':{'type':'object','properties':{'amount':{'type':'number'},'currency':{'type':'string'},'manager_approved':{'type':'boolean'}},'required':['amount','currency'],'additionalProperties':False}}
        store.register(AgentRegistration(agent_id=agent,principal_id=agent,policy_id=agent,tenant_id='test',groups=[agent],tools=[spec]),agent+'-key')
        Engine(store).publish(Policy(policy_id=agent,version=1,rules=[{'id':'permit','tool':tool,'effect':'ALLOW','reason':'Agent permission'}]))
    with TestClient(create_app(store,'admin')) as client:yield store,client

def publish(client,**changes):
    body={'id':'financial-limit','name':'Financial approval limit','version':1,'scope':'global','capability':'financial_transaction','effect':'REQUIRE_APPROVAL','amount_limit_minor':10000,'currency':'EUR',**changes}
    headers={'Authorization':'Bearer admin'}
    draft=client.post('/v1/universal/drafts',json=body,headers=headers);assert draft.status_code==200,draft.text
    identifier=draft.json()['draft_id']
    assert client.post('/v1/universal/drafts/'+identifier+'/activate',headers=headers).status_code==409
    assert client.post('/v1/universal/drafts/'+identifier+'/test',headers=headers).status_code==200
    assert client.post('/v1/universal/drafts/'+identifier+'/activate',headers=headers).status_code==200
    return identifier

def function(client,agent,tool,counter):
    pg=PromptGuard(agent+'-key','http://testserver',agent,client=client)
    def operation(amount,currency,manager_approved=False):counter.append(amount);return amount
    return pg,pg.protect(name=tool)(operation)

def test_cross_agent_limit_updates_without_recreating_clients(env):
    store,client=env;counts=[]
    ps,refund=function(client,'support','issue_refund',counts);pf,pay=function(client,'finance','send_payment',counts)
    _,discount=function(client,'sales','apply_discount',counts)
    assert refund(150,'EUR')==150 and pay(250,'EUR')==250
    publish(client)
    for fn,amount in [(refund,150),(pay,250)]:
        with pytest.raises(ApprovalRequired) as e:fn(amount,'EUR',manager_approved=True)
        assert e.value.response['matched_universal_policies'][0]['id']=='financial-limit'
        assert e.value.response['matched_universal_policies'][0]['version']==1
    assert counts==[150,250]
    assert refund(50,'EUR')==50 and discount(250,'EUR')==250
    publish(client,version=2,amount_limit_minor=30000)
    assert refund(150,'EUR')==150 and pay(250,'EUR')==250

def test_mandatory_deny_and_group_agent_scopes(env):
    _,client=env;count=[]
    _,refund=function(client,'support','issue_refund',count);_,pay=function(client,'finance','send_payment',count)
    publish(client,effect='DENY',scope='group',targets=['finance'])
    assert refund(150,'EUR')==150
    with pytest.raises(AuthorizationDenied):pay(250,'EUR')
    publish(client,id='mandatory-global',effect='DENY',amount_limit_minor=None,currency=None)
    with pytest.raises(AuthorizationDenied):refund(1,'EUR')
    assert count==[150]

def test_currency_missing_mapping_and_coverage(env):
    store,client=env;count=[];_,refund=function(client,'support','issue_refund',count)
    publish(client)
    with pytest.raises(AuthorizationDenied):refund(150,'USD')
    with store.transaction() as db:
        import json
        row=db.execute('SELECT profile FROM agents WHERE agent_id="support"').fetchone();profile=json.loads(row[0]);profile['tools'][0]['amount_field']=None
        db.execute('UPDATE agents SET profile=? WHERE agent_id="support"',(json.dumps(profile),))
    with pytest.raises(AuthorizationDenied):refund(150,'EUR')
    coverage=client.get('/v1/universal/coverage',headers={'Authorization':'Bearer admin'}).json()
    assert coverage['policies'][0]['covered_agents']==['finance','support']
    assert not count

def test_approval_binding_includes_universal_version(env):
    _,client=env;count=[];pg,refund=function(client,'support','issue_refund',count)
    publish(client)
    with pytest.raises(ApprovalRequired) as error:refund(150,'EUR')
    approval=client.post('/v1/approvals/'+error.value.execution_id,headers={'Authorization':'Bearer admin'}).json()['approval_id']
    publish(client,version=2,amount_limit_minor=12000)
    with pg.session(pg._session.get(),approval):
        with pytest.raises(ApprovalRequired):refund(150,'EUR')
    assert count==[]

def test_decorator_cannot_self_assert_capabilities(env):
    _,client=env
    pg=PromptGuard('sales-key','http://testserver','sales',client=client)
    @pg.protect(name='apply_discount',capability='financial_transaction')
    def discount(amount,currency):pytest.fail('Unconfirmed mapping executed')
    with pytest.raises(ServiceUnavailable):discount(50,'EUR')

def test_concurrent_pending_actions_never_execute(env):
    _,client=env;count=[];_,refund=function(client,'support','issue_refund',count);publish(client)
    def attempt(i):
        try:refund(150,'EUR')
        except ApprovalRequired:return 'pending'
    with ThreadPoolExecutor(max_workers=3) as pool:assert list(pool.map(attempt,range(3)))==['pending']*3
    assert count==[]

def test_drafts_are_inactive_and_admin_only(env):
    _,client=env
    assert client.get('/v1/universal/coverage').status_code==401
    assert client.get('/v1/universal/coverage',headers={'Authorization':'Bearer support-key'}).status_code==403
    assert client.get('/v1/universal/metadata/unregistered',headers={'Authorization':'Bearer support-key'}).status_code==404

def test_verified_approval_is_exact_and_one_use(env):
    _,client=env;count=[];pg,refund=function(client,'support','issue_refund',count);publish(client)
    with pytest.raises(ApprovalRequired) as error:refund(150,'EUR')
    approval=client.post('/v1/approvals/'+error.value.execution_id,headers={'Authorization':'Bearer admin'}).json()['approval_id']
    with pg.session(pg._session.get(),approval):
        assert refund(150,'EUR')==150
        with pytest.raises(ApprovalRequired):refund(150,'EUR')
    assert count==[150]

def test_agent_specific_policy_does_not_restrict_other_agents(env):
    _,client=env;count=[];_,refund=function(client,'support','issue_refund',count);_,pay=function(client,'finance','send_payment',count)
    publish(client,scope='agent',targets=['support'],effect='DENY')
    with pytest.raises(AuthorizationDenied):refund(150,'EUR')
    assert pay(250,'EUR')==250

def test_rollback_creates_reviewable_draft_not_active_change(env):
    _,client=env;headers={'Authorization':'Bearer admin'}
    publish(client);publish(client,version=2,amount_limit_minor=30000)
    rollback=client.post('/v1/universal/rollback/financial-limit/1',headers=headers)
    assert rollback.status_code==200 and rollback.json()['policy']['version']==3
    assert rollback.json()['active_changed'] is False
    active=client.get('/v1/universal/coverage',headers=headers).json()['policies'][0]['policy']
    assert active['version']==2 and active['amount_limit_minor']==30000
