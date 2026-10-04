"""Detection engine.

Two layers:

1. ``detect_batch`` — stateless, per-event rules (suspicious PowerShell,
   privilege-escalation indicators, port-scan keywords). At most one alert
   per (rule, event).

2. ``detect_campaigns`` — stateful correlation over a trailing time window.
   Takes previously stored ``history`` events plus the newly ingested batch
   and emits **one alert per campaign** (per IP / per user), no matter how
   many individual events make it up. Because it looks at stored history, an
   attack split across several uploads is still caught.

The old "impossible travel" keyword rule is gone: matching the literal words
"impossible travel" in a log line is not detection. It is replaced by
``CONCURRENT_ACCESS`` — the same user authenticating successfully from two
or more distinct source IPs inside a short window, which is an honest,
computable signal.
"""
from collections import defaultdict
from datetime import timedelta

from .scoring import score, severity

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
SPRAY_ACCOUNT_THRESHOLD = 3
SPRAY_WINDOW = timedelta(minutes=10)
CONCURRENT_ACCESS_WINDOW = timedelta(minutes=30)

FAILED = {"failed", "failure", "denied"}
SUCCESS = {"success", "successful", "succeeded"}


def _alert(event_id, rule_id, title, risk, evidence, dedup_key=None, window=None):
    return {
        "_event_id": event_id,
        "rule_id": rule_id,
        "title": title,
        "severity": severity(risk),
        "risk_score": risk,
        "evidence": evidence,
        "dedup_key": dedup_key,
        "window": window,
    }


def _is_failed_login(e):
    return e.get("outcome") in FAILED and "login" in str(e.get("action", "")).lower()


def _is_successful_login(e):
    return e.get("outcome") in SUCCESS and "login" in str(e.get("action", "")).lower()


def detect_batch(events):
    """Stateless per-event rules. One alert per (rule, event) at most."""
    out = []
    for e in events:
        msg = str(e.get("message", "")).lower()
        act = str(e.get("action", "")).lower()
        eid = e.get("_id")
        if "port scan" in msg or ("scan" in act and "port" in msg):
            out.append(_alert(eid, "PORT_SCAN", "Potential network port scan", 72,
                              ["Event indicates port scanning behavior"]))
        if any(x in msg for x in ["sudo", "privilege escalation",
                                  "user added to administrators", "setuid"]):
            out.append(_alert(eid, "PRIV_ESC", "Potential privilege escalation", 82,
                              ["Privilege-sensitive indicator found"]))
        if "powershell" in msg and any(x in msg for x in
                                      ["-enc", "encodedcommand", "downloadstring",
                                       "invoke-expression", "iex ", "bypass"]):
            out.append(_alert(eid, "POWERSHELL_SUSPICIOUS",
                              "Suspicious PowerShell execution", 75,
                              ["PowerShell contains a high-risk execution/download indicator"]))
    return out


def _windowed(events, window):
    if not events:
        return []
    latest = max(e["timestamp"] for e in events)
    cutoff = latest - window
    return [e for e in events if e["timestamp"] >= cutoff]


def _newest(evs):
    return max(evs, key=lambda e: e["timestamp"])


def detect_campaigns(history, new_events):
    """Time-windowed correlation. One alert per campaign.

    ``history``: previously stored events (dicts, no ``_new`` flag).
    ``new_events``: the just-ingested batch, each marked with ``_new=True``.
    A campaign only fires when the new batch contributes to it, so re-reading
    old data never re-alerts.
    """
    out = []
    all_events = list(history) + list(new_events)

    # --- Brute force: many failed logins from one IP inside the window ---
    fails = _windowed([e for e in all_events if _is_failed_login(e)], BRUTE_FORCE_WINDOW)
    by_ip = defaultdict(list)
    for e in fails:
        if e.get("source_ip"):
            by_ip[e["source_ip"]].append(e)
    for ip, evs in by_ip.items():
        if len(evs) >= BRUTE_FORCE_THRESHOLD and any(e.get("_new") for e in evs):
            mins = int(BRUTE_FORCE_WINDOW.total_seconds() // 60)
            out.append(_alert(_newest(evs).get("_id"), "BRUTE_FORCE",
                              "Repeated authentication failures",
                              score(70, min(20, len(evs) - BRUTE_FORCE_THRESHOLD)),
                              [f"{len(evs)} failed login attempts from {ip} in the last {mins} minutes"],
                              dedup_key=f"BRUTE_FORCE:{ip}",
                              window=BRUTE_FORCE_WINDOW))

    # --- Password spraying: one IP failing against many accounts ---
    sprayed = _windowed([e for e in all_events if _is_failed_login(e)], SPRAY_WINDOW)
    by_ip_spray = defaultdict(list)
    for e in sprayed:
        if e.get("source_ip") and e.get("user"):
            by_ip_spray[e.get("source_ip")].append(e)
    for ip, evs in by_ip_spray.items():
        users = {e["user"] for e in evs}
        if len(users) >= SPRAY_ACCOUNT_THRESHOLD and any(e.get("_new") for e in evs):
            mins = int(SPRAY_WINDOW.total_seconds() // 60)
            out.append(_alert(_newest(evs).get("_id"), "PASSWORD_SPRAY",
                              "Potential password spraying", 78,
                              [f"{ip} generated failures against {len(users)} distinct "
                               f"accounts in the last {mins} minutes"],
                              dedup_key=f"PASSWORD_SPRAY:{ip}",
                              window=SPRAY_WINDOW))

    # --- Concurrent access: one user, successful logins from distinct IPs ---
    logins = _windowed([e for e in all_events if _is_successful_login(e)],
                       CONCURRENT_ACCESS_WINDOW)
    by_user = defaultdict(list)
    for e in logins:
        if e.get("user") and e.get("source_ip"):
            by_user[e["user"]].append(e)
    for user, evs in by_user.items():
        ips = sorted({e["source_ip"] for e in evs})
        if len(ips) >= 2 and any(e.get("_new") for e in evs):
            mins = int(CONCURRENT_ACCESS_WINDOW.total_seconds() // 60)
            out.append(_alert(_newest(evs).get("_id"), "CONCURRENT_ACCESS",
                              "Logins from multiple source IPs in a short window", 68,
                              [f"User '{user}' authenticated from {len(ips)} distinct IPs "
                               f"within {mins} minutes: {', '.join(ips)}"],
                              dedup_key=f"CONCURRENT_ACCESS:{user}",
                              window=CONCURRENT_ACCESS_WINDOW))
    return out
