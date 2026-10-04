# LLM-Powered Security Log Analyzer

Master's-level defensive security analytics platform with FastAPI, SQLAlchemy, explainable detection rules, optional LLM enrichment, and Streamlit dashboard.

## Run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

Dashboard:
```bash
streamlit run dashboard/app.py
```

Seed demo:
```bash
python scripts/seed_demo.py
```

Docker:
```bash
docker compose up --build
```

LLM is optional. Set `LLM_ENABLED=true`, `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL` in `.env`.

The deterministic detection layer is authoritative; the LLM only enriches alerts. Logs are treated as untrusted data, never as instructions.

Detection rules: brute force (5+ failed logins from one IP in 10 minutes), password spraying (one IP failing against 3+ accounts in 10 minutes), concurrent access (one user logging in from 2+ IPs in 30 minutes), port scanning, privilege escalation indicators, and suspicious PowerShell. Correlation is time-windowed and cross-batch: attacks split across uploads are still caught, and each campaign produces one alert, not one per event — an open campaign is not re-alerted inside its window.

Input formats: JSON, JSONL, CSV, and simple key=value text logs.

This is a strong graduate portfolio/reference implementation, not a claim of enterprise SIEM completeness.
