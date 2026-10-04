from app.core.parsers import parse_bytes
def test_jsonl():
 rows=parse_bytes(b'{"timestamp":"2026-01-01T00:00:00Z","source":"auth","source_ip":"1.1.1.1","action":"login","outcome":"failed","message":"bad"}\n',"x.jsonl")
 assert len(rows)==1 and rows[0]["source_ip"]=="1.1.1.1"
def test_csv(): assert len(parse_bytes(b"timestamp,source,message\n2026-01-01T00:00:00Z,fw,hello\n","x.csv"))==1
