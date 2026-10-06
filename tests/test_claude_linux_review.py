"""Claude opt-in Linux review must never delegate a failed review to Auto mode."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/'plugin/scripts'
TOOL='mcp__fixture__operate'

@pytest.mark.parametrize('outcome,expected',[
    ('approved',None),('cancelled','deny'),('provider-timeout','deny'),
    ('exception','deny'),('missing-reviewer','deny'),
])
def test_claude_resolves_linux_review_before_host(tmp_path,outcome,expected):
    home=tmp_path/'agw'; packs=home/'policies.d';packs.mkdir(parents=True)
    (packs/'fixture.json').write_text(json.dumps({'settings':{'action_contracts':{
        'version':1,'unmatched':'deny','tools':{TOOL:{'effect':'send',
        'required':['to','body'],'arguments':['to','body']}}}}}))
    payload={'hook_event_name':'PreToolUse','session_id':'fixture-session',
             'tool_use_id':'fixture-call','permission_mode':'auto','cwd':str(tmp_path),
             'tool_name':TOOL,'tool_input':{'to':'nobody@example.invalid','body':'synthetic'}}
    program='''
import sys,runpy,os
sys.path.insert(0,sys.argv[1])
from core import approvals
outcome=sys.argv[3]
if outcome!='missing-reviewer':
 class Fake:
  def request(self,request):
   assert request.exact_operation and request.session_id=='fixture-session'
   if outcome=='exception':raise RuntimeError('fixture failure')
   return approvals.ApprovalResponse(outcome=='approved',outcome)
 approvals.default_provider=lambda *args:Fake()
runpy.run_path(sys.argv[2],run_name='__main__')
'''
    env=dict(os.environ,AGW_HOME=str(home),AGW_APPROVAL_PROVIDER='linux-socket',
             AGW_REVIEWER_UID='99999',AGW_REVIEW_SOCKET='agw-no-server-fixture',
             CLAUDE_PLUGIN_ROOT=str(ROOT/'plugin'),PYTHONDONTWRITEBYTECODE='1')
    r=subprocess.run([sys.executable,'-B','-c',program,str(SCRIPTS),
        str(SCRIPTS/'claude/pretooluse.py'),outcome],input=json.dumps(payload),
        capture_output=True,text=True,env=env,timeout=20)
    assert r.returncode==0,r.stderr
    result=json.loads(r.stdout) if r.stdout.strip() else {}
    assert result.get('hookSpecificOutput',{}).get('permissionDecision')==expected

@pytest.mark.parametrize('name',['unknown-tool','malformed-json'])
def test_claude_early_errors_deny_in_linux_review(tmp_path,name):
    payload='not json' if name=='malformed-json' else json.dumps({
        'tool_name':'UnknownMutation','tool_input':{},'cwd':str(tmp_path),'session_id':'fixture'})
    r=subprocess.run([sys.executable,'-B',str(SCRIPTS/'claude/_dispatch.py'),'pretooluse'],
        input=payload,capture_output=True,text=True,timeout=20,
        env=dict(os.environ,AGW_HOME=str(tmp_path/'agw'),AGW_APPROVAL_PROVIDER='linux-socket'))
    assert r.returncode==0
    assert json.loads(r.stdout)['hookSpecificOutput']['permissionDecision']=='deny'

def test_dispatch_missing_adapter_denies_with_linux_provider(tmp_path):
    dispatch=tmp_path/'_dispatch.py';dispatch.write_bytes((SCRIPTS/'claude/_dispatch.py').read_bytes())
    r=subprocess.run([sys.executable,'-B',str(dispatch),'pretooluse'],input='{}',
        capture_output=True,text=True,timeout=10,
        env=dict(os.environ,AGW_HOME=str(tmp_path/'agw'),AGW_APPROVAL_PROVIDER='linux-socket'))
    assert r.returncode==0
    assert json.loads(r.stdout)['hookSpecificOutput']['permissionDecision']=='deny'

def test_claude_hook_timeout_covers_owner_review():
    hooks=json.loads((ROOT/'plugin/hooks/hooks.json').read_text())
    assert hooks['hooks']['PreToolUse'][0]['hooks'][0]['timeout']>=120
