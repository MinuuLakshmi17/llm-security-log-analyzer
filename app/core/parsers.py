import csv,io,json,re
from datetime import datetime,timezone
def _dt(v):
    if isinstance(v,datetime): d=v
    else:
        s=str(v).strip().replace("Z","+00:00")
        try: d=datetime.fromisoformat(s)
        except ValueError: d=datetime.strptime(s,"%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
def normalize(obj):
    x={str(k).lower():v for k,v in obj.items()}
    return {"timestamp":_dt(x.get("timestamp") or x.get("@timestamp") or datetime.now(timezone.utc)),
            "source":str(x.get("source") or x.get("host") or "unknown"),
            "source_ip":x.get("source_ip") or x.get("src_ip") or x.get("client_ip") or x.get("ip"),
            "destination_ip":x.get("destination_ip") or x.get("dst_ip"),
            "user":x.get("user") or x.get("username") or x.get("account"),
            "action":str(x.get("action") or x.get("event_type") or x.get("type") or "unknown").lower(),
            "outcome":str(x.get("outcome") or x.get("result") or "").lower() or None,
            "service":x.get("service") or x.get("application"),
            "message":str(x.get("message") or x.get("msg") or json.dumps(obj,sort_keys=True)),
            "metadata":obj}
def parse_text_line(line):
    m=re.match(r"^(\S+)\s+(\S+)\s+(.*)$",line.strip())
    if not m:return normalize({"message":line})
    obj={"timestamp":m.group(1),"source":m.group(2)}
    for k,v in re.findall(r"""(\w+)=('.*?'|".*?"|\S+)""",m.group(3)): obj[k]=v.strip("'\"")
    obj["message"]=obj.get("message",line)
    return normalize(obj)
def parse_bytes(data,filename):
    text=data.decode("utf-8",errors="replace")
    ext=filename.lower().rsplit(".",1)[-1] if "." in filename else ""
    if ext=="json":
        x=json.loads(text); return [normalize(v) for v in (x if isinstance(x,list) else [x])]
    if ext=="jsonl": return [normalize(json.loads(l)) for l in text.splitlines() if l.strip()]
    if ext=="csv": return [normalize(r) for r in csv.DictReader(io.StringIO(text))]
    return [parse_text_line(l) for l in text.splitlines() if l.strip()]
