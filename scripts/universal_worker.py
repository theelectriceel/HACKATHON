"""Long-running independent demo agent. Isolated counters, no external payments."""
import json,sys
from promptguard_v2.sdk import PromptGuard,AuthorizationDenied

def main():
    config=json.loads(sys.stdin.readline());count=0
    pg=PromptGuard(config['token'],config['endpoint'],config['agent_id'])
    def operation(amount:float,currency:str):
        nonlocal count
        count+=1
        return {'isolated_invocations':count,'amount':amount,'currency':currency}
    operation.__name__=config['tool']
    protected=pg.protect(capability=config['capability'],amount_field='amount',currency_field='currency')(operation)
    for line in sys.stdin:
        value=json.loads(line)
        if value.get('stop'):break
        try:
            with pg.session():result={'decision':'ALLOW','result':protected(**value),'counter':count}
        except AuthorizationDenied as exc:result={'decision':exc.response['decision'],'counter':count,'authorization':exc.response}
        print(json.dumps(result),flush=True)
    pg.close()
if __name__=='__main__':main()
