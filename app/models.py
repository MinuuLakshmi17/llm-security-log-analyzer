from datetime import datetime,timezone
from sqlalchemy import DateTime,Integer,String,Text,JSON
from sqlalchemy.orm import Mapped,mapped_column
from app.db import Base
def now(): return datetime.now(timezone.utc)
class SecurityEvent(Base):
    __tablename__="security_events"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    timestamp:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    source:Mapped[str]=mapped_column(String(100),index=True)
    source_ip:Mapped[str|None]=mapped_column(String(64),index=True,nullable=True)
    destination_ip:Mapped[str|None]=mapped_column(String(64),nullable=True)
    user:Mapped[str|None]=mapped_column(String(255),index=True,nullable=True)
    action:Mapped[str]=mapped_column(String(100),index=True)
    outcome:Mapped[str|None]=mapped_column(String(50),nullable=True)
    service:Mapped[str|None]=mapped_column(String(100),nullable=True)
    message:Mapped[str]=mapped_column(Text)
    metadata_json:Mapped[dict]=mapped_column(JSON,default=dict)
class Alert(Base):
    __tablename__="alerts"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    event_id:Mapped[int|None]=mapped_column(Integer,index=True,nullable=True)
    rule_id:Mapped[str]=mapped_column(String(100),index=True)
    title:Mapped[str]=mapped_column(String(255))
    severity:Mapped[str]=mapped_column(String(30),index=True)
    risk_score:Mapped[int]=mapped_column(Integer)
    status:Mapped[str]=mapped_column(String(30),default="open",index=True)
    evidence_json:Mapped[list]=mapped_column(JSON,default=list)
    dedup_key:Mapped[str|None]=mapped_column(String(255),nullable=True,index=True)
    llm_summary:Mapped[str|None]=mapped_column(Text,nullable=True)
    llm_recommendations:Mapped[list|None]=mapped_column(JSON,nullable=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
