from datetime import datetime
from pydantic import BaseModel,Field,ConfigDict
class EventCreate(BaseModel):
    timestamp:datetime; source:str="unknown"; source_ip:str|None=None; destination_ip:str|None=None
    user:str|None=None; action:str="unknown"; outcome:str|None=None; service:str|None=None
    message:str; metadata:dict=Field(default_factory=dict)
class EventOut(EventCreate):
    id:int
    model_config=ConfigDict(from_attributes=True)
class AlertOut(BaseModel):
    id:int; event_id:int|None; rule_id:str; title:str; severity:str; risk_score:int; status:str
    evidence:list; dedup_key:str|None=None; llm_summary:str|None=None; llm_recommendations:list|None=None; created_at:datetime
class StatusUpdate(BaseModel):
    status:str=Field(pattern="^(open|acknowledged|resolved)$")
