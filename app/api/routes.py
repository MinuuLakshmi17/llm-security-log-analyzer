from datetime import datetime,timezone,timedelta
from fastapi import APIRouter,Depends,File,HTTPException,UploadFile
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import SecurityEvent,Alert
from app.schemas import EventCreate,EventOut,AlertOut,StatusUpdate
from app.security import require_api_key
from app.core.parsers import parse_bytes
from app.core.detection import detect_batch,detect_campaigns,CONCURRENT_ACCESS_WINDOW
router=APIRouter(prefix="/api/v1")

def _aware(ts):
    # SQLite returns naive datetimes; detection compares against aware ones.
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts

def event_dict(r): return {"timestamp":_aware(r.timestamp),"source":r.source,"source_ip":r.source_ip,"destination_ip":r.destination_ip,"user":r.user,"action":r.action,"outcome":r.outcome,"service":r.service,"message":r.message,"metadata":r.metadata_json,"_id":r.id}

def event_out(r):
    # Built explicitly: returning the ORM object directly breaks response
    # validation because EventOut.metadata collides with SQLAlchemy's
    # Model.metadata attribute (a MetaData object, not a dict).
    return EventOut(id=r.id,timestamp=_aware(r.timestamp),source=r.source,source_ip=r.source_ip,destination_ip=r.destination_ip,user=r.user,action=r.action,outcome=r.outcome,service=r.service,message=r.message,metadata=r.metadata_json or {})

def ao(r): return AlertOut(id=r.id,event_id=r.event_id,rule_id=r.rule_id,title=r.title,severity=r.severity,risk_score=r.risk_score,status=r.status,evidence=r.evidence_json,dedup_key=r.dedup_key,llm_summary=r.llm_summary,llm_recommendations=r.llm_recommendations,created_at=r.created_at)

def _recent_history(db:Session,minutes:int,exclude_ids:set):
    cutoff=datetime.now(timezone.utc)-timedelta(minutes=minutes)
    rows=db.scalars(select(SecurityEvent).where(SecurityEvent.timestamp>=cutoff.replace(tzinfo=None))).all()
    return [event_dict(r) for r in rows if r.id not in exclude_ids]

def _suppressed(db:Session,dedup_key:str,window:timedelta):
    # Don't open a second alert for a campaign that already has an open one
    # inside its correlation window.
    cutoff=datetime.now(timezone.utc)-window
    return db.scalar(select(Alert.id).where(Alert.dedup_key==dedup_key,Alert.status=="open",Alert.created_at>=cutoff.replace(tzinfo=None)).limit(1)) is not None

def _run_detection(db:Session,new_event_dicts):
    """Batch rules + time-windowed campaign correlation against stored history."""
    history=_recent_history(db,minutes=int(CONCURRENT_ACCESS_WINDOW.total_seconds()//60),exclude_ids={d["_id"] for d in new_event_dicts if d.get("_id")})
    alerts=detect_batch(new_event_dicts)+detect_campaigns(history,new_event_dicts)
    created=0
    for d in alerts:
        if d.get("dedup_key") and d.get("window") and _suppressed(db,d["dedup_key"],d["window"]):
            continue
        db.add(Alert(event_id=d.get("_event_id"),rule_id=d["rule_id"],title=d["title"],severity=d["severity"],risk_score=d["risk_score"],evidence_json=d["evidence"],dedup_key=d.get("dedup_key")))
        created+=1
    return created

@router.get("/health")
def health(): return {"status":"ok"}

@router.post("/events",response_model=EventOut,dependencies=[Depends(require_api_key)])
def create(p:EventCreate,db:Session=Depends(get_db)):
    r=SecurityEvent(timestamp=p.timestamp,source=p.source,source_ip=p.source_ip,destination_ip=p.destination_ip,user=p.user,action=p.action,outcome=p.outcome,service=p.service,message=p.message,metadata_json=p.metadata); db.add(r); db.flush()
    new=[{**event_dict(r),"_new":True}]
    _run_detection(db,new)
    db.commit(); db.refresh(r); return event_out(r)

@router.get("/events",response_model=list[EventOut])
def events(limit:int=100,db:Session=Depends(get_db)): return [event_out(r) for r in db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(min(max(limit,1),500))).all()]

@router.get("/alerts",response_model=list[AlertOut])
def alerts(status:str|None=None,limit:int=100,db:Session=Depends(get_db)):
    q=select(Alert).order_by(Alert.risk_score.desc(),Alert.created_at.desc())
    if status:q=q.where(Alert.status==status)
    return [ao(x) for x in db.scalars(q.limit(min(max(limit,1),500))).all()]

@router.patch("/alerts/{alert_id}",response_model=AlertOut,dependencies=[Depends(require_api_key)])
def update(alert_id:int,p:StatusUpdate,db:Session=Depends(get_db)):
    r=db.get(Alert,alert_id)
    if not r: raise HTTPException(404,"Alert not found")
    r.status=p.status; db.commit(); db.refresh(r); return ao(r)

@router.post("/alerts/{alert_id}/enrich",dependencies=[Depends(require_api_key)])
def enrich_alert(alert_id:int,db:Session=Depends(get_db)):
    from app.core.llm import enrich
    r=db.get(Alert,alert_id)
    if not r: raise HTTPException(404,"Alert not found")
    e=db.get(SecurityEvent,r.event_id)
    if not e: raise HTTPException(400,"Alert has no event")
    x=enrich({"rule_id":r.rule_id,"title":r.title,"severity":r.severity,"risk_score":r.risk_score,"evidence":r.evidence_json},event_dict(e))
    if x.get("summary") is not None:r.llm_summary=x["summary"]; r.llm_recommendations=x["recommendations"]; db.commit()
    return x

@router.post("/ingest/file",dependencies=[Depends(require_api_key)])
async def ingest(file:UploadFile=File(...),db:Session=Depends(get_db)):
    es=parse_bytes(await file.read(),file.filename or "upload.log"); rows=[]
    for e in es:
        r=SecurityEvent(timestamp=e["timestamp"],source=e["source"],source_ip=e["source_ip"],destination_ip=e["destination_ip"],user=e["user"],action=e["action"],outcome=e["outcome"],service=e["service"],message=e["message"],metadata_json=e["metadata"]); db.add(r); db.flush(); rows.append(r)
    new=[{**e,"_id":r.id,"_new":True} for e,r in zip(es,rows)]
    created=_run_detection(db,new)
    db.commit(); return {"filename":file.filename,"events_ingested":len(rows),"alerts_created":created}

@router.get("/stats")
def stats(db:Session=Depends(get_db)):
    return {"events":db.scalar(select(func.count()).select_from(SecurityEvent)),"alerts":db.scalar(select(func.count()).select_from(Alert)),"high_or_critical":db.scalar(select(func.count()).select_from(Alert).where(Alert.severity.in_(["high","critical"])))}
