import os,requests,pandas as pd,streamlit as st
st.set_page_config(page_title="Security Log Analyzer",layout="wide"); st.title("LLM-Powered Security Log Analyzer")
base=st.sidebar.text_input("API URL",os.getenv("API_URL","http://127.0.0.1:8000")); key=st.sidebar.text_input("API Key",os.getenv("API_KEY",""),type="password"); headers={"X-API-Key":key} if key else {}
try: stats=requests.get(f"{base}/api/v1/stats",timeout=5).json(); alerts=requests.get(f"{base}/api/v1/alerts?limit=200",timeout=5).json()
except Exception as e: st.error(f"API unavailable: {e}"); st.stop()
a,b,c=st.columns(3); a.metric("Events",stats.get("events",0)); b.metric("Alerts",stats.get("alerts",0)); c.metric("High/Critical",stats.get("high_or_critical",0))
if alerts:
    df=pd.DataFrame(alerts); st.dataframe(df[["id","rule_id","title","severity","risk_score","status","created_at"]],use_container_width=True)
    chosen=st.number_input("Alert ID",min_value=1,step=1)
    if st.button("LLM Enrich"): st.json(requests.post(f"{base}/api/v1/alerts/{int(chosen)}/enrich",headers=headers,timeout=40).json())
else: st.info("No alerts yet. Seed or ingest demo logs.")
