import json
import subprocess
from pathlib import Path
import pytest
from promptguard import codex_client as client

def test_api_secrets_are_removed_only_from_child_environment(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','test-secret')
    monkeypatch.setenv('CODEX_API_KEY','test-secret')
    monkeypatch.setenv('CODEX_ACCESS_TOKEN','test-secret')
    child=client.child_environment()
    assert 'OPENAI_API_KEY' not in child and 'CODEX_API_KEY' not in child and 'CODEX_ACCESS_TOKEN' not in child
    import os
    assert os.environ['OPENAI_API_KEY']=='test-secret'

def test_cli_forces_requested_model_chatgpt_and_readonly(monkeypatch,tmp_path):
    monkeypatch.setattr(client,'cli_command',lambda:['codex.exe'])
    command=client.build_command(tmp_path/'out.json',tmp_path)
    assert command[command.index('--model')+1]=='gpt-6-luna'
    assert command[command.index('--sandbox')+1]=='read-only'
    assert 'forced_login_method="chatgpt"' in command
    assert 'features.shell_tool=false' in command
    assert 'features.apps=false' in command
    assert 'features.multi_agent=false' in command
    assert '--ignore-user-config' in command

def test_key_authenticated_cli_is_refused(monkeypatch):
    monkeypatch.setattr(client,'cli_command',lambda:['codex.exe'])
    monkeypatch.setattr(client.subprocess,'run',lambda *a,**k:subprocess.CompletedProcess(a,0,'Logged in using an API key',''))
    assert client.authentication_status(refresh=True)['available'] is False
    with pytest.raises(client.ModelError):client.complete([{'role':'user','content':'hello'}])

def test_business_intent_is_not_executed_by_adapter():
    tools=[{'function':{'name':'lookup_customer'}}]
    result=client.decode_response({'content':'','tool_calls':[{'name':'lookup_customer','arguments_json':'{"order_id":"ord-1001"}'}]},tools)
    assert result['tool_calls'][0]['function']['name']=='lookup_customer'

@pytest.mark.parametrize('value',[
    {'content':'','tool_calls':[{'name':'shell','arguments_json':'{}'}]},
    {'content':'','tool_calls':[{'name':'lookup_customer','arguments_json':'[]'}]},
    {'content':'','tool_calls':[{'name':'lookup_customer','arguments_json':'{invalid'}]},
])
def test_unavailable_native_or_malformed_intents_rejected(value):
    with pytest.raises(client.ModelError):client.decode_response(value,[{'function':{'name':'lookup_customer'}}])

def test_text_only_rag_cannot_request_tools():
    with pytest.raises(client.ModelError):client.decode_response({'content':'','tool_calls':[{'name':'lookup_customer','arguments_json':'{}'}]},None)
