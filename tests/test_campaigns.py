from datetime import datetime,timedelta,timezone
from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def _post_event(ip,user="victim",action="login",outcome="failed",ts=None,msg="authentication failure"):
    ts=ts or datetime.now(timezone.utc).isoformat()
    r=client.post("/api/v1/events",json={"timestamp":ts,"source":"auth01","source_ip":ip,
        "user":user,"action":action,"outcome":outcome,"service":"ssh",
        "message":msg,"metadata":{"k":"v"}})
    return r

def _alerts(rule=None):
    a=client.get("/api/v1/alerts?limit=500").json()
    return [x for x in a if rule is None or x["rule_id"]==rule]

def test_single_event_endpoint_returns_200_not_500():
    # Regression: EventOut.metadata used to collide with SQLAlchemy's
    # Model.metadata, 500ing every single-event POST.
    r=_post_event("10.10.99.1")
    assert r.status_code==200, r.text
    body=r.json()
    assert body["metadata"]=={"k":"v"}
    assert body["source_ip"]=="10.10.99.1"

def test_five_failures_yield_one_bruteforce_alert():
    ip="10.10.99.2"; before=len(_alerts("BRUTE_FORCE"))
    for _ in range(5): assert _post_event(ip).status_code==200
    new=[a for a in _alerts("BRUTE_FORCE") if a["dedup_key"]==f"BRUTE_FORCE:{ip}"]
    assert len(_alerts("BRUTE_FORCE"))-before==1
    assert len(new)==1 and "5 failed login attempts" in new[0]["evidence"][0]

def test_cross_batch_correlation():
    # Attack split across two uploads is still caught on the second one.
    ip="10.10.99.3"; before=len(_alerts("BRUTE_FORCE"))
    for _ in range(3): _post_event(ip)
    assert len(_alerts("BRUTE_FORCE"))-before==0  # not enough yet
    for _ in range(2): _post_event(ip)
    assert len(_alerts("BRUTE_FORCE"))-before==1  # history + new batch = 5

def test_no_duplicate_alert_while_campaign_open():
    # More failures while the campaign alert is still open: no second alert.
    ip="10.10.99.4"
    for _ in range(5): _post_event(ip)
    before=len([a for a in _alerts("BRUTE_FORCE") if a["dedup_key"]==f"BRUTE_FORCE:{ip}"])
    assert before==1
    _post_event(ip)
    after=len([a for a in _alerts("BRUTE_FORCE") if a["dedup_key"]==f"BRUTE_FORCE:{ip}"])
    assert after==1

def test_concurrent_access_end_to_end():
    now=datetime.now(timezone.utc)
    _post_event("203.0.113.90",user="dave"+str(now.microsecond),action="login",outcome="success",
               ts=(now-timedelta(minutes=16)).isoformat(),msg="successful login")
    r=_post_event("198.51.100.91",user="dave"+str(now.microsecond),action="login",outcome="success",
                  ts=now.isoformat(),msg="successful login")
    assert r.status_code==200
    cas=[a for a in _alerts("CONCURRENT_ACCESS") if a["dedup_key"]==f"CONCURRENT_ACCESS:dave{now.microsecond}"]
    assert len(cas)==1
