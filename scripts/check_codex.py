import json
from promptguard.model_client import authentication_status,complete
if __name__=="__main__":
    print(json.dumps(authentication_status(refresh=True)),flush=True)
    r=complete([{"role":"user","content":"Reply with the single word ready."}])
    print(json.dumps({k:r[k] for k in ("model","backend","authentication","uses_api_key","message","usage")}),flush=True)
