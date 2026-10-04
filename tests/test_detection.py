from datetime import datetime,timedelta,timezone
from app.core.detection import detect_batch,detect_campaigns

def _ev(**kw):
    base={"timestamp":datetime.now(timezone.utc),"source":"auth","source_ip":"1.1.1.1",
          "user":"a","action":"login","outcome":"failed","message":"x"}
    base.update(kw); return base

def _fails(ip,n,spacing_s=5):
    now=datetime.now(timezone.utc)
    return [_ev(source_ip=ip,timestamp=now-timedelta(seconds=i*spacing_s),_new=True) for i in range(n)]

def test_bruteforce_keyword_rules():
    e={"source_ip":"1.1.1.1","user":"a","action":"process","outcome":"success","message":"powershell -enc abc"}
    assert any(x["rule_id"]=="POWERSHELL_SUSPICIOUS" for x in detect_batch([e]))

def test_bruteforce_one_alert_per_campaign_not_per_event():
    # 5 failed logins -> exactly ONE alert, not five.
    alerts=detect_campaigns([],_fails("10.0.0.1",5))
    bfs=[a for a in alerts if a["rule_id"]=="BRUTE_FORCE"]
    assert len(bfs)==1
    assert bfs[0]["dedup_key"]=="BRUTE_FORCE:10.0.0.1"

def test_bruteforce_requires_time_window():
    # 5 failures spread 30 minutes apart: no campaign, no alert.
    alerts=detect_campaigns([],_fails("10.0.0.2",5,spacing_s=1800))
    assert not [a for a in alerts if a["rule_id"]=="BRUTE_FORCE"]

def test_bruteforce_needs_new_batch_contribution():
    # History alone never re-alerts.
    old=_fails("10.0.0.3",6)
    for e in old: e.pop("_new")
    assert not [a for a in detect_campaigns(old,[]) if a["rule_id"]=="BRUTE_FORCE"]

def test_password_spray():
    now=datetime.now(timezone.utc); evs=[]
    for i,u in enumerate(["u1","u2","u3"]):
        evs.append(_ev(source_ip="10.0.0.4",user=u,timestamp=now-timedelta(seconds=i*10),_new=True))
    alerts=detect_campaigns([],evs)
    assert any(a["rule_id"]=="PASSWORD_SPRAY" for a in alerts)

def test_concurrent_access_honest_rule():
    now=datetime.now(timezone.utc)
    evs=[_ev(source_ip="203.0.113.20",user="carol",action="login",outcome="success",timestamp=now-timedelta(minutes=16),_new=True),
         _ev(source_ip="198.51.100.77",user="carol",action="login",outcome="success",timestamp=now,_new=True)]
    alerts=detect_campaigns([],evs)
    cas=[a for a in alerts if a["rule_id"]=="CONCURRENT_ACCESS"]
    assert len(cas)==1
    assert "carol" in cas[0]["evidence"][0]

def test_no_impossible_travel_keyword_rule():
    # The old fake rule is gone: a message merely mentioning the phrase
    # must not produce an alert.
    e=_ev(action="login",outcome="success",message="impossible travel detected between New York and London",_new=True)
    assert detect_batch([e])==[] and detect_campaigns([],[e])==[]
