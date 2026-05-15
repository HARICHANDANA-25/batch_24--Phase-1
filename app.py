import streamlit as st
import requests
import hashlib
import json
import os
import re
import random
import string
import uuid as _uuid
from datetime import datetime, timedelta
from pathlib import Path
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
SPLUNK_HEC_URL   = "https://10.236.6.52:8088/services/collector/event"
SPLUNK_HEC_TOKEN = "e513dc9a-497a-42a0-a093-b9bbea3f61a4"

DIRS = {
    "generated": Path("generated_logs"),
    "uploads":   Path("uploads"),
    "ingested":  Path("ingested_logs"),
}
for d in DIRS.values():
    d.mkdir(exist_ok=True)

# ─── DEFAULT SOURCES ──────────────────────────────────────────────────────────
DEFAULT_SOURCES = ["firewall", "windows", "linux", "switches", "routers"]

LOG_FILES = {
    "firewall": "firewall_logs.txt",
    "windows":  "windows_logs.txt",
    "linux":    "linux_logs.txt",
    "switches": "switches_logs.txt",
    "routers":  "routers_logs.txt",
}

SOURCETYPES = {
    "firewall": "firewall",
    "windows":  "windows",
    "linux":    "linux",
    "switches": "switches",
    "routers":  "routers",
}

# ─── VALIDATION PATTERNS ──────────────────────────────────────────────────────
VALIDATION_PATTERNS = {
    "firewall": re.compile(r"action=(ALLOW|DENY|DROP)\s+src=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    "windows":  re.compile(r"EventID=\d+\s+\S+"),
    "linux":    re.compile(r"sshd\[\d+\]:|kernel:|systemd\[|sudo:|cron\[|auth|\[INFO\]|\[WARN\]|\[ERROR\]"),
    "switches": re.compile(r"%SWITCH-\d-\S+|SWITCH_PORT_(UP|DOWN|ERR)\s+interface=\S+"),
    "routers":  re.compile(r"%[A-Z]+-\d-\S+|ROUTER_(BGP|OSPF|STATIC)\s+neighbor=\S+"),
}

# ─── LOG GENERATORS ───────────────────────────────────────────────────────────

def _ts(offset_s=0):
    return (datetime.now() - timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S")

def _ip():
    return f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_firewall_logs(n=20):
    actions   = ["ALLOW", "DENY", "DROP", "REJECT"]
    protocols = ["TCP", "UDP", "ICMP"]
    zones     = ["INSIDE", "OUTSIDE", "DMZ"]
    logs = []
    for i in range(n):
        src_ip   = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        dst_ip   = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        sport    = random.randint(1024, 65535)
        dport    = random.choice([22, 80, 443, 3389, 53, 8080, 21, 25])
        action   = random.choice(actions)
        proto    = random.choice(protocols)
        sz       = random.randint(64, 1500)
        src_zone = random.choice(zones)
        dst_zone = random.choice(zones)
        logs.append(
            f"{_ts(i*3)} FIREWALL action={action} src={src_ip} dst={dst_ip} "
            f"sport={sport} dport={dport} proto={proto} bytes={sz} "
            f"src_zone={src_zone} dst_zone={dst_zone} policy_id={random.randint(1,100)}"
        )
    return logs

def generate_windows_logs(n=20):
    event_ids = [4624, 4625, 4634, 4648, 4672, 4688, 4720, 4726, 7036, 1102]
    levels    = ["Information", "Warning", "Error", "Critical"]
    users     = ["Administrator", "SYSTEM", "NetworkService", "jsmith", "adavis", "mlee"]
    hosts     = [f"WIN-SRV-{i:03d}" for i in range(1, 6)]
    logs = []
    for i in range(n):
        eid   = random.choice(event_ids)
        level = random.choice(levels)
        user  = random.choice(users)
        host  = random.choice(hosts)
        pid   = random.randint(1000, 9999)
        logs.append(
            f"{_ts(i*3)} EventID={eid} Level={level} Host={host} User={user} "
            f"PID={pid} Source=Security Channel=Security "
            f"Message=\"A {level.lower()} event occurred for user {user} on {host}\""
        )
    return logs

def generate_linux_logs(n=20):
    facilities = ["auth", "kern", "daemon", "syslog", "user", "cron"]
    severities = ["INFO", "WARN", "ERROR", "DEBUG", "CRIT"]
    services   = ["sshd", "cron", "kernel", "systemd", "sudo", "nginx", "auditd"]
    hosts      = [f"linux-host-{i:02d}" for i in range(1, 6)]
    users      = ["root", "ubuntu", "deploy", "www-data", "nobody"]
    logs = []
    for i in range(n):
        ts   = (datetime.now() - timedelta(seconds=i*3)).strftime("%b %d %H:%M:%S")
        host = random.choice(hosts)
        svc  = random.choice(services)
        sev  = random.choice(severities)
        fac  = random.choice(facilities)
        user = random.choice(users)
        pid  = random.randint(100, 9999)
        msgs = [
            f"Accepted publickey for {user} from {_ip()}",
            f"Failed password for {user} from {_ip()}",
            f"session opened for user {user} by (uid=0)",
            f"COMMAND=/bin/ls ; USER={user}",
            f"Starting {svc} service...",
            f"Stopped {svc} service.",
        ]
        logs.append(
            f"{ts} {host} {svc}[{pid}]: [{sev}] [{fac}] {random.choice(msgs)}"
        )
    return logs

def generate_switch_logs(n=20):
    switches   = [f"SW-CORE-{i:02d}" for i in range(1, 5)]
    vlans      = [10, 20, 30, 40, 100, 200]
    iface_pool = [f"GigabitEthernet1/0/{random.randint(1,48)}" for _ in range(10)]
    events = [
        "STP: port transitioned to FORWARDING",
        "MAC address table overflow",
        "Interface line protocol changed to UP",
        "Interface line protocol changed to DOWN",
        "VLAN created",
        "Port security violation",
        "CDP neighbor discovered",
        "LACP partner information changed",
    ]
    logs = []
    for i in range(n):
        sw    = random.choice(switches)
        iface = random.choice(iface_pool)
        vlan  = random.choice(vlans)
        evt   = random.choice(events)
        logs.append(
            f"{_ts(i*3)} {sw} %SWITCH-5-NOTICE: Interface {iface} VLAN {vlan} - {evt} "
            f"[Uptime: {random.randint(0,999)}d {random.randint(0,23)}h]"
        )
    return logs

def generate_router_logs(n=20):
    routers    = [f"RTR-EDGE-{i:02d}" for i in range(1, 5)]
    protocols  = ["BGP", "OSPF", "EIGRP", "ISIS", "RIP"]
    iface_pool = [
        f"Serial0/0/{random.randint(0,3)}",
        f"GigabitEthernet0/{random.randint(0,3)}",
        f"Tunnel{random.randint(0,10)}",
    ]
    events = [
        "Neighbor state changed to ESTABLISHED",
        "Route redistribution policy applied",
        "Interface bandwidth changed",
        "NAT translation table full",
        "BGP prefix limit exceeded",
        "OSPF adjacency dropped",
        "QoS policy applied on interface",
        "ACL matched on inbound traffic",
    ]
    logs = []
    for i in range(n):
        rtr   = random.choice(routers)
        proto = random.choice(protocols)
        iface = random.choice(iface_pool)
        evt   = random.choice(events)
        peer  = _ip()
        logs.append(
            f"{_ts(i*3)} {rtr} %{proto}-5-ADJCHANGE: {iface} Peer {peer} - {evt} "
            f"AS{random.randint(1000,65000)}"
        )
    return logs

def generate_generic_logs(source, n=20):
    logs = []
    for i in range(n):
        rand_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        logs.append(
            f"{_ts(i*3)} {source.upper()} event_id={rand_id} "
            f"host={_ip()} severity={random.choice(['INFO','WARN','ERROR','CRITICAL'])} "
            f"msg='Automated log entry for {source}'"
        )
    return logs

GENERATORS = {
    "firewall": generate_firewall_logs,
    "windows":  generate_windows_logs,
    "linux":    generate_linux_logs,
    "switches": generate_switch_logs,
    "routers":  generate_router_logs,
}

# ─── HASH UTILITIES ───────────────────────────────────────────────────────────
def log_hash(line: str) -> str:
    return hashlib.sha256(line.strip().encode()).hexdigest()

def load_ingested_hashes(source: str) -> set:
    path = DIRS["ingested"] / f"{source.lower()}_hashes.json"
    if path.exists():
        try:
            with open(path) as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_ingested_hashes(source: str, hashes: set):
    path = DIRS["ingested"] / f"{source.lower()}_hashes.json"
    with open(path, "w") as f:
        json.dump(list(hashes), f)

# ─── HEC CONNECTION TEST ──────────────────────────────────────────────────────
def _hec_headers(token: str) -> dict:
    """Build HEC headers. X-Splunk-Request-Channel is required when indexer
    acknowledgement is enabled on the HEC input (error code 10 without it)."""
    return {
        "Authorization":           f"Splunk {token}",
        "Content-Type":            "application/json",
        "X-Splunk-Request-Channel": str(_uuid.uuid4()),
    }

def _probe_url(url: str, token: str) -> tuple:
    """Try one URL. Returns (status_code_or_None, short_result_string)."""
    headers = _hec_headers(token)
    payload = json.dumps({
        "time":       datetime.now().timestamp(),
        "source":     "logflow_test",
        "sourcetype": "logflow",
        "index":      "main",
        "event":      "LogFlow HEC connectivity test",
    })
    try:
        resp = requests.post(url, data=payload, headers=headers, verify=False, timeout=5)
        return resp.status_code, resp.text.strip()[:120]
    except requests.exceptions.SSLError:
        return None, "SSL error (cert issue — but HTTPS is the right protocol)"
    except requests.exceptions.ConnectionError as e:
        msg = str(e)
        if "10054" in msg or "ConnectionReset" in msg:
            return None, "Connection reset (wrong protocol for this port)"
        if "10061" in msg or "refused" in msg.lower():
            return None, "Connection refused (port closed or Splunk not running)"
        return None, f"Connection error: {msg[:80]}"
    except requests.exceptions.Timeout:
        return None, "Timed out"
    except Exception as e:
        return None, str(e)[:80]

def test_hec_connection():
    """
    Auto-probes all 4 combinations of http/https × port 8088/8000.
    Returns (success: bool, report_lines: list[str])
    """
    host = "10.236.6.52"
    candidates = [
        f"http://{host}/services/collector/event",
        f"https://{host}/services/collector/event",
        f"http://{host}:8088/services/collector/event",
        f"https://{host}:8088/services/collector/event",
    ]
    lines = ["🔍 Probing all HEC endpoint combinations…", ""]
    working_url = None

    for url in candidates:
        code, result = _probe_url(url, SPLUNK_HEC_TOKEN)
        if code == 200:
            lines.append(f"✅ WORKING  → {url}")
            lines.append(f"   Response : {result}")
            working_url = url
        elif code in (400, 401, 403):
            # Got an HTTP response — endpoint exists, but token/index issue
            lines.append(f"⚠️  REACHED  → {url}  [HTTP {code}]")
            lines.append(f"   Response : {result}")
            lines.append(f"   (HEC is reachable but token/index may need fixing)")
            if working_url is None:
                working_url = url   # reachable is still progress
        elif code == 404:
            lines.append(f"🟡 404      → {url}  (HEC not found at this path)")
        else:
            lines.append(f"🔴 FAILED   → {url}")
            lines.append(f"   Reason   : {result}")

    lines.append("")
    if working_url:
        lines.append(f"👉 Use this URL in SPLUNK_HEC_URL:  {working_url}")
        return True, lines
    else:
        lines.append("❌ No working endpoint found. Verify:")
        lines.append("   1. Splunk is running on 10.236.8.44")
        lines.append("   2. HEC is enabled: Settings → Data Inputs → HTTP Event Collector → Global Settings → Enabled")
        lines.append("   3. Token is Active and allowed on index 'main'")
        lines.append("   4. Firewall allows port 8088 from this machine")
        return False, lines

# ─── SPLUNK INGEST (BATCH) ────────────────────────────────────────────────────
def ingest_to_splunk(lines: list, source: str):
    """
    FIX: Sends all events in a single batched POST (newline-delimited JSON)
    instead of one request per line. This is far faster and is the correct
    way to use the Splunk HEC /services/collector/event endpoint.
    """
    sourcetype = SOURCETYPES.get(source, source.lower())
    # _hec_headers adds X-Splunk-Request-Channel (required when HEC ack is ON)
    headers = _hec_headers(SPLUNK_HEC_TOKEN)

    existing_hashes = load_ingested_hashes(source)
    new_hashes      = set()
    status_log      = []

    # ── Deduplicate ───────────────────────────────────────────────────────────
    unique = []
    dupes  = 0
    for line in lines:
        h = log_hash(line)
        if h in existing_hashes:
            dupes += 1
        else:
            unique.append((line, h))

    status_log.append(f"📊 Total lines      : {len(lines)}")
    status_log.append(f"🔁 Duplicates found : {dupes}")
    status_log.append(f"✅ Unique to ingest : {len(unique)}")
    status_log.append("")

    if not unique:
        status_log.append("ℹ️  Nothing new to ingest — all lines are duplicates.")
        return status_log

    # ── Build batched payload (newline-delimited HEC JSON) ───────────────────
    # Each line is a separate JSON object separated by newlines (no array wrapper).
    # Splunk HEC accepts up to ~1 MB per request; we chunk at 500 events to be safe.
    CHUNK_SIZE = 500
    success = 0
    failed  = 0

    chunks = [unique[i:i+CHUNK_SIZE] for i in range(0, len(unique), CHUNK_SIZE)]
    status_log.append(f"📦 Sending {len(unique)} events in {len(chunks)} batch(es)…")
    status_log.append("")

    for chunk_idx, chunk in enumerate(chunks, 1):
        batch_payload = "\n".join(
            json.dumps({
                "time":       datetime.now().timestamp(),
                "source":     source,
                "sourcetype": sourcetype,
                "index":      "main",
                "event":      line.strip(),
            })
            for line, _ in chunk
        )
        try:
            resp = requests.post(
                SPLUNK_HEC_URL,
                data=batch_payload,
                headers=headers,
                verify=False,
                timeout=30,
            )
            if resp.status_code == 200:
                success += len(chunk)
                for _, h in chunk:
                    new_hashes.add(h)
                status_log.append(
                    f"  Batch {chunk_idx}/{len(chunks)} · [{resp.status_code}] "
                    f"{len(chunk)} events sent ✅"
                )
            else:
                failed += len(chunk)
                try:
                    err_body = resp.json()
                    err_msg  = err_body.get("text", resp.text.strip()[:200])
                    err_code = err_body.get("code", "")
                    status_log.append(
                        f"  Batch {chunk_idx}/{len(chunks)} · [{resp.status_code}] "
                        f"FAILED — {err_msg} (code={err_code})"
                    )
                    # Helpful hints for common HEC error codes
                    if resp.status_code == 403 or err_body.get("code") == 4:
                        status_log.append(
                            "  💡 HEC token invalid or disabled. "
                            "Check Settings → Data Inputs → HTTP Event Collector in Splunk."
                        )
                    elif resp.status_code == 400 and err_body.get("code") == 6:
                        status_log.append(
                            "  💡 Index 'main' not found or not allowed for this token. "
                            "Check the token's allowed indexes in Splunk HEC settings."
                        )
                except Exception:
                    status_log.append(
                        f"  Batch {chunk_idx}/{len(chunks)} · [{resp.status_code}] "
                        f"{resp.reason} — {resp.text.strip()[:200]}"
                    )
        except requests.exceptions.ConnectionError as e:
            failed += len(chunk)
            status_log.append(
                f"  Batch {chunk_idx}/{len(chunks)} · [ERR] Connection failed — "
                f"is Splunk running and HEC enabled on port 8088? ({e})"
            )
        except requests.exceptions.Timeout:
            failed += len(chunk)
            status_log.append(f"  Batch {chunk_idx}/{len(chunks)} · [ERR] Request timed out after 30 s")
        except Exception as e:
            failed += len(chunk)
            status_log.append(f"  Batch {chunk_idx}/{len(chunks)} · [ERR] {e}")

    # ── Persist hashes only for events that were successfully sent ────────────
    existing_hashes.update(new_hashes)
    save_ingested_hashes(source, existing_hashes)

    status_log.append("")
    status_log.append(f"🟢 Ingested successfully : {success}")
    status_log.append(f"🔴 Failed               : {failed}")
    status_log.append(f"🔁 Skipped (duplicate)  : {dupes}")
    return status_log

# ─── VALIDATE UPLOAD ──────────────────────────────────────────────────────────
def validate_log_file(content: str, source: str):
    lines = [l for l in content.splitlines() if l.strip()]
    if not lines:
        return False, "File is empty.", []
    pattern = VALIDATION_PATTERNS.get(source)
    if pattern is None:
        return True, f"No strict pattern for '{source}'. Accepting all lines.", lines
    matched = [l for l in lines if pattern.search(l)]
    ratio = len(matched) / len(lines)
    if ratio == 0:
        return False, (
            f"❌ 0 of {len(lines)} lines match the {source} pattern. "
            "This does not appear to be the right log format."
        ), []
    elif ratio < 0.3:
        return False, (
            f"⚠️ Only {len(matched)}/{len(lines)} lines ({ratio:.0%}) match {source} format. "
            "File rejected — too many non-conforming lines."
        ), []
    else:
        return True, (
            f"✅ {len(matched)}/{len(lines)} lines ({ratio:.0%}) validated as {source} format."
        ), lines

# ─── PAGE SETUP ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LogFlow Portal",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── DARK TERMINAL CSS ────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@700;800&family=Inter:wght@400;500;600&display=swap');
:root {
  --bg: #0a0d14; --surface: #111520; --surface2: #181d2e;
  --border: #1e2a40; --accent: #00d4ff; --accent2: #7c3aed;
  --green: #22c55e; --red: #ef4444; --yellow: #f59e0b;
  --text: #e2e8f0; --muted: #64748b;
  --mono: 'JetBrains Mono', monospace;
  --sans: 'Inter', sans-serif;
  --display: 'Syne', sans-serif;
}
html, body, [class*="css"] {
  background-color: var(--bg) !important;
  color: var(--text) !important;
  font-family: var(--sans) !important;
}
section[data-testid="stSidebar"] {
  background: var(--surface) !important;
  border-right: 1px solid var(--border) !important;
}
.logflow-header {
  display:flex; align-items:center; gap:16px;
  padding:24px 0 32px; border-bottom:1px solid var(--border); margin-bottom:32px;
}
.logflow-logo {
  font-family:var(--display); font-size:2.4rem; font-weight:800;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  -webkit-background-clip:text; -webkit-text-fill-color:transparent; letter-spacing:-1px;
}
.logflow-sub { font-family:var(--mono); font-size:0.75rem; color:var(--muted); letter-spacing:0.1em; text-transform:uppercase; }
.source-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:20px 24px; margin-bottom:16px; transition:border-color 0.2s; }
.source-card:hover { border-color:var(--accent); }
.source-title { font-family:var(--display); font-size:1.1rem; font-weight:700; color:var(--accent); letter-spacing:-0.5px; margin-bottom:4px; }
.source-badge { display:inline-block; font-family:var(--mono); font-size:0.65rem; color:var(--muted); background:var(--surface2); border:1px solid var(--border); border-radius:4px; padding:2px 8px; text-transform:uppercase; letter-spacing:0.08em; }
.terminal-box { background:#060810; border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:8px; padding:16px; font-family:var(--mono); font-size:0.72rem; color:#a0e4ff; line-height:1.7; max-height:340px; overflow-y:auto; white-space:pre-wrap; word-break:break-all; }
.pill { display:inline-block; padding:3px 12px; border-radius:20px; font-family:var(--mono); font-size:0.7rem; font-weight:600; margin:2px; }
.pill-green  { background:rgba(34,197,94,.15);  color:var(--green);  border:1px solid rgba(34,197,94,.3); }
.pill-red    { background:rgba(239,68,68,.15);  color:var(--red);    border:1px solid rgba(239,68,68,.3); }
.pill-blue   { background:rgba(0,212,255,.1);   color:var(--accent); border:1px solid rgba(0,212,255,.25); }
.pill-yellow { background:rgba(245,158,11,.12); color:var(--yellow); border:1px solid rgba(245,158,11,.3); }
.stButton > button { background:var(--surface2) !important; color:var(--accent) !important; border:1px solid var(--accent) !important; border-radius:8px !important; font-family:var(--mono) !important; font-size:0.75rem !important; font-weight:600 !important; letter-spacing:0.05em !important; padding:8px 18px !important; transition:all 0.2s !important; }
.stButton > button:hover { background:var(--accent) !important; color:#000 !important; box-shadow:0 0 18px rgba(0,212,255,.3) !important; }
.stTextInput > div > div > input, .stSelectbox > div > div > div, .stTextArea > div > textarea { background:var(--surface2) !important; border:1px solid var(--border) !important; border-radius:8px !important; color:var(--text) !important; font-family:var(--mono) !important; font-size:0.8rem !important; }
.streamlit-expanderHeader { background:var(--surface2) !important; border:1px solid var(--border) !important; border-radius:8px !important; font-family:var(--display) !important; font-weight:700 !important; }
.stFileUploader > div { background:var(--surface2) !important; border:1px dashed var(--border) !important; border-radius:8px !important; }
hr { border-color:var(--border) !important; }
::-webkit-scrollbar { width:6px; }
::-webkit-scrollbar-track { background:var(--surface); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:4px; }
::-webkit-scrollbar-thumb:hover { background:var(--accent); }
.metric-row { display:flex; gap:12px; flex-wrap:wrap; margin:12px 0; }
.metric-card { background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:10px 18px; min-width:130px; text-align:center; }
.metric-val { font-family:var(--mono); font-size:1.4rem; font-weight:700; color:var(--accent); }
.metric-lbl { font-size:0.65rem; color:var(--muted); text-transform:uppercase; letter-spacing:0.08em; margin-top:2px; }
</style>
""", unsafe_allow_html=True)

# ─── SESSION STATE ────────────────────────────────────────────────────────────
if "custom_sources" not in st.session_state:
    st.session_state.custom_sources = []
if "log_store" not in st.session_state:
    st.session_state.log_store = {}

# ─── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='padding:16px 0 8px;'>
      <div style='font-family:"Syne",sans-serif;font-size:1.3rem;font-weight:800;
        background:linear-gradient(135deg,#00d4ff,#7c3aed);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;'>
        ⚡ LogFlow
      </div>
      <div style='font-family:"JetBrains Mono",monospace;font-size:0.65rem;
        color:#64748b;letter-spacing:.1em;margin-top:2px;'>
        SPLUNK HEC PORTAL
      </div>
    </div>
    <hr style='border-color:#1e2a40;margin:8px 0 20px;'/>
    """, unsafe_allow_html=True)

    st.markdown("**🔌 Splunk HEC Config**")
    st.code(f"URL: 10.236.6.52:8088\nToken: e513dc9a-...", language="text")

    # ── HEC Connection Test Button ─────────────────────────────────────────
    st.markdown("**🔍 HEC Connectivity Test**")
    if st.button("🔍 Test HEC Connection", use_container_width=True):
        with st.spinner("Probing all endpoints…"):
            ok, report = test_hec_connection()
        report_text = "\n".join(report)
        st.markdown(
            f"<div class='terminal-box'>{report_text}</div>",
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown("**➕ Add Custom Source**")
    with st.form("add_source_form", clear_on_submit=True):
        new_src        = st.text_input("Source name",  placeholder="e.g. PaloAlto, Fortinet")
        new_sourcetype = st.text_input("Sourcetype",   placeholder="e.g. pan:traffic")
        submitted = st.form_submit_button("Add Source")
        if submitted:
            name = new_src.strip()
            if not name:
                st.error("Name cannot be empty.")
            elif name in DEFAULT_SOURCES or name in st.session_state.custom_sources:
                st.warning(f"'{name}' already exists.")
            else:
                st.session_state.custom_sources.append(name)
                if new_sourcetype.strip():
                    SOURCETYPES[name] = new_sourcetype.strip()
                st.success(f"✅ '{name}' added!")

    st.markdown("---")
    st.markdown("**📁 Active Sources**")
    all_sources_sidebar = DEFAULT_SOURCES + st.session_state.custom_sources
    for s in all_sources_sidebar:
        icon = "🔵" if s in DEFAULT_SOURCES else "🟣"
        st.markdown(
            f"<div style='font-family:\"JetBrains Mono\",monospace;font-size:0.75rem;"
            f"padding:4px 8px;color:#e2e8f0;'>{icon} {s}</div>",
            unsafe_allow_html=True,
        )
    st.markdown("---")
    st.caption("LogFlow v1.1 · Splunk HEC Automation")

# ─── MAIN HEADER ──────────────────────────────────────────────────────────────
st.markdown("""
<div class="logflow-header">
  <div>
    <div class="logflow-logo">⚡ LogFlow Portal</div>
    <div class="logflow-sub">Splunk HEC Log Automation · Real-time Ingestion · Duplicate Detection</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ─── GLOBAL STATS ─────────────────────────────────────────────────────────────
total_ingested  = sum(len(load_ingested_hashes(s)) for s in DEFAULT_SOURCES + st.session_state.custom_sources)
total_log_lines = sum(len(v) for v in st.session_state.log_store.values())

col1, col2, col3, col4 = st.columns(4)
with col1: st.metric("Total Sources",            len(DEFAULT_SOURCES) + len(st.session_state.custom_sources))
with col2: st.metric("Log Lines Loaded",          total_log_lines)
with col3: st.metric("Total Ingested (all time)", total_ingested)
with col4: st.metric("HEC Endpoint",              "10.236.6.52:8088 ✓")
st.markdown("---")

# ─── SOURCE ICONS ─────────────────────────────────────────────────────────────
SOURCE_ICONS = {
    "firewall": "🔥",
    "windows":  "🪟",
    "linux":    "🐧",
    "switches": "🔀",
    "routers":  "📡",
}

# ─── RENDER SOURCE CARD ───────────────────────────────────────────────────────
def render_source_card(source: str):
    icon      = SOURCE_ICONS.get(source, "🔌")
    is_custom = source not in DEFAULT_SOURCES

    with st.expander(f"{icon} {source}", expanded=False):
        pill_type = "blue" if not is_custom else "yellow"
        pill_label = "BUILT-IN" if not is_custom else "CUSTOM"
        st.markdown(
            f"<span class='pill pill-{pill_type}'>{pill_label}</span>"
            f"<span class='pill pill-blue'>{SOURCETYPES.get(source, source.lower())}</span>",
            unsafe_allow_html=True,
        )
        st.markdown("")

        tab1, tab2, tab3 = st.tabs(["⚡ Generate & Ingest", "📤 Upload & Validate", "📋 Log Preview"])

        # ── TAB 1: Generate & Ingest ──────────────────────────────────────────
        with tab1:
            col_a, col_b = st.columns([1, 1])
            with col_a:
                n_logs = st.slider("Log count", 5, 100, 20, key=f"slider_{source}")
                if st.button("⚡ Generate Logs", key=f"gen_{source}"):
                    generator = GENERATORS.get(source, lambda n: generate_generic_logs(source, n))
                    logs = generator(n_logs)
                    st.session_state.log_store[source] = logs
                    fname = LOG_FILES.get(source, f"{source.lower()}_logs.txt")
                    fpath = DIRS["generated"] / fname
                    with open(fpath, "w") as f:
                        f.write("\n".join(logs))
                    st.markdown(
                        f"<span class='pill pill-green'>✅ {len(logs)} lines generated → {fpath}</span>",
                        unsafe_allow_html=True,
                    )
            with col_b:
                lines_loaded = len(st.session_state.log_store.get(source, []))
                st.markdown(
                    f"<div class='metric-card'>"
                    f"<div class='metric-val'>{lines_loaded}</div>"
                    f"<div class='metric-lbl'>lines ready</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
                if st.button("🚀 Ingest to Splunk", key=f"ingest_{source}"):
                    logs = st.session_state.log_store.get(source, [])
                    if not logs:
                        st.warning("⚠️ No logs loaded. Generate or upload first.")
                    else:
                        with st.spinner("Ingesting…"):
                            results = ingest_to_splunk(logs, source)
                        st.markdown(
                            f"<div class='terminal-box'>{chr(10).join(results)}</div>",
                            unsafe_allow_html=True,
                        )

        # ── TAB 2: Upload & Validate ──────────────────────────────────────────
        with tab2:
            uploaded = st.file_uploader(
                "Upload .log file", type=["log", "txt"],
                key=f"upload_{source}",
                help="Upload a .log or .txt file to validate and ingest",
            )
            if uploaded:
                raw = uploaded.read().decode("utf-8", errors="replace")
                valid, msg, lines = validate_log_file(raw, source)
                pill_cls = "pill-green" if valid else "pill-red"
                st.markdown(f"<span class='pill {pill_cls}'>{msg}</span>", unsafe_allow_html=True)
                if valid and lines:
                    save_path = DIRS["uploads"] / f"{source.lower()}_{uploaded.name}"
                    with open(save_path, "w") as f:
                        f.write("\n".join(lines))
                    st.markdown(
                        f"<span class='pill pill-blue'>💾 Saved → {save_path}</span>",
                        unsafe_allow_html=True,
                    )
                    if st.button(f"📥 Load into {source} & Ingest", key=f"load_upload_{source}"):
                        st.session_state.log_store[source] = lines
                        with st.spinner("Ingesting uploaded logs…"):
                            results = ingest_to_splunk(lines, source)
                        st.markdown(
                            f"<div class='terminal-box'>{chr(10).join(results)}</div>",
                            unsafe_allow_html=True,
                        )

        # ── TAB 3: Log Preview ────────────────────────────────────────────────
        with tab3:
            logs = st.session_state.log_store.get(source, [])
            if not logs:
                st.info("No logs loaded yet. Generate or upload logs first.")
            else:
                existing_hashes = load_ingested_hashes(source)
                unique_count = sum(1 for l in logs if log_hash(l) not in existing_hashes)
                dupe_count   = len(logs) - unique_count
                col_x, col_y, col_z = st.columns(3)
                col_x.metric("Total Lines", len(logs))
                col_y.metric("Unique",       unique_count)
                col_z.metric("Duplicates",   dupe_count)
                preview = "\n".join(logs[:50])
                st.markdown(
                    f"<div class='terminal-box'>{preview}</div>",
                    unsafe_allow_html=True,
                )
                if len(logs) > 50:
                    st.caption(f"Showing 50 of {len(logs)} lines.")

# ─── RENDER ALL SOURCES ───────────────────────────────────────────────────────
all_sources = DEFAULT_SOURCES + st.session_state.custom_sources
st.subheader("📦 Log Sources")
for source in all_sources:
    render_source_card(source)

# ─── BULK OPERATIONS ──────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("⚡ Bulk Operations")
bcol1, bcol2 = st.columns(2)

with bcol1:
    if st.button("⚡ Generate ALL Source Logs", use_container_width=True):
        count = 0
        for src in all_sources:
            gen  = GENERATORS.get(src, lambda n: generate_generic_logs(src, n))
            logs = gen(20)
            st.session_state.log_store[src] = logs
            fname = LOG_FILES.get(src, f"{src.lower()}_logs.txt")
            with open(DIRS["generated"] / fname, "w") as f:
                f.write("\n".join(logs))
            count += len(logs)
        st.success(f"✅ Generated {count} log lines across {len(all_sources)} sources.")

with bcol2:
    if st.button("🚀 Ingest ALL Sources to Splunk", use_container_width=True):
        summary = []
        for src in all_sources:
            logs = st.session_state.log_store.get(src, [])
            if logs:
                results = ingest_to_splunk(logs, src)
                summary.append(f"=== {src} ===")
                summary.extend(results)
                summary.append("")
        if summary:
            st.markdown(
                f"<div class='terminal-box'>{chr(10).join(summary)}</div>",
                unsafe_allow_html=True,
            )
        else:
            st.warning("No logs loaded. Generate logs first.")

# ─── FOOTER ───────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align:center;font-family:\"JetBrains Mono\",monospace;"
    "font-size:0.65rem;color:#334155;padding:16px;'>"
    "LogFlow Portal v1.1 · Splunk HEC Integration · Duplicate-Safe Batch Ingestion"
    "</div>",
    unsafe_allow_html=True,
)

