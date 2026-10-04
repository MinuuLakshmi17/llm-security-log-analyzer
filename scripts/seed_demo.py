import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.db import Base,engine,SessionLocal
from app.core.parsers import parse_bytes
from app.models import SecurityEvent,Alert
from app.core.detection import detect_batch,detect_campaigns
Base.metadata.create_all(bind=engine); es=parse_bytes(Path("data/sample_security.jsonl").read_bytes(),"sample_security.jsonl"); db=SessionLocal()
try:
 rows=[]
 for e in es:
  r=SecurityEvent(timestamp=e["timestamp"],source=e["source"],source_ip=e["source_ip"],destination_ip=e["destination_ip"],user=e["user"],action=e["action"],outcome=e["outcome"],service=e["service"],message=e["message"],metadata_json=e["metadata"]); db.add(r); db.flush(); rows.append(r)
 new=[{**e,"_id":r.id,"_new":True} for e,r in zip(es,rows)]
 ds=detect_batch(new)+detect_campaigns([],new)
 for d in ds: db.add(Alert(event_id=d.get("_event_id"),rule_id=d["rule_id"],title=d["title"],severity=d["severity"],risk_score=d["risk_score"],evidence_json=d["evidence"],dedup_key=d.get("dedup_key")))
 db.commit(); print(f"Seeded {len(rows)} events and {len(ds)} alerts.")
finally: db.close()
