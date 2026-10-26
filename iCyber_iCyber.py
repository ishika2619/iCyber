"""iCyber - Threat Intelligence Aggregator (single-file submission version).
Run the dashboard:  streamlit run iCyber_iCyber.py
Requires sample_data/samples.json next to this file for Demo mode.
The modular version with tests is in the full project zip.
"""

# ==================== config.py ====================
import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


def _get(name: str) -> Optional[str]:
    value = os.getenv(name, "").strip()
    return value or None


def get_vt_key() -> Optional[str]:
    return _get("VT_API_KEY")


def get_otx_key() -> Optional[str]:
    return _get("OTX_API_KEY")

# ==================== validators.py ====================
import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse


class InvalidIndicatorError(ValueError):
    """Raised when the user's input is not a supported indicator."""


HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")  # MD5 / SHA-1 / SHA-256
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.I)
MAX_LEN = 2048


def refang(value: str) -> str:
    """Convert 'defanged' indicators (hxxp://evil[.]com) back to normal form."""
    value = re.sub(r"^hxxp", "http", value, flags=re.I)
    return value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def detect_indicator(raw: str) -> Tuple[str, str]:
    """Return (type, normalized_value) where type is 'ip', 'domain', 'url' or 'hash'."""
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidIndicatorError("Please enter an IP address, domain, URL or file hash.")
    value = refang(raw.strip())
    if len(value) > MAX_LEN:
        raise InvalidIndicatorError("Input is too long to be a valid indicator.")

    if re.match(r"^https?://", value, re.I):
        if not urlparse(value).netloc:
            raise InvalidIndicatorError("That looks like a URL but has no host name.")
        return "url", value
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if HASH_RE.match(value):
        return "hash", value.lower()
    if DOMAIN_RE.match(value):
        return "domain", value.lower()
    raise InvalidIndicatorError(
        "Unrecognised input. Use an IPv4/IPv6 address, a domain (example.com), "
        "a full URL (starting with http:// or https://), or an MD5/SHA-1/SHA-256 hash."
    )


def ip_warning(value: str) -> Optional[str]:
    """Non-public IPs (private, loopback, documentation ranges) rarely have threat intel."""
    try:
        if not ipaddress.ip_address(value).is_global:
            return "This is not a public internet IP address, so threat feeds are unlikely to have data on it."
    except ValueError:
        pass
    return None

# ==================== clients.py ====================
import base64
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import requests

TIMEOUT = 15  # seconds
VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"


@dataclass
class SourceResult:
    """Outcome of asking one source about one indicator.

    status: ok | not_found | rate_limited | auth_error | no_key | error
    data:   normalised fields (only filled when status == 'ok')
    """
    source: str
    status: str
    data: dict = field(default_factory=dict)
    message: str = ""


class RateLimiter:
    """Client-side limiter so we stop *before* the provider blocks us (VT public key: ~4 requests/min)."""

    def __init__(self, max_calls: int, period: float):
        self.max_calls, self.period, self.calls = max_calls, period, deque()

    def wait_time(self) -> float:
        now = time.time()
        while self.calls and now - self.calls[0] > self.period:
            self.calls.popleft()
        if len(self.calls) < self.max_calls:
            return 0.0
        return self.period - (now - self.calls[0])

    def record(self) -> None:
        self.calls.append(time.time())


VT_LIMITER = RateLimiter(max_calls=4, period=60)


def _get(source: str, url: str, headers: dict, limiter: Optional[RateLimiter] = None) -> SourceResult:
    """One HTTP GET with defensive error handling. Never puts the URL/headers (keys) into messages."""
    if limiter:
        wait = limiter.wait_time()
        if wait > 0:
            return SourceResult(source, "rate_limited", message=f"Local rate limit reached. Try again in ~{int(wait) + 1}s.")
        limiter.record()
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
    except requests.Timeout:
        return SourceResult(source, "error", message=f"{source} timed out. Try again shortly.")
    except requests.RequestException:
        return SourceResult(source, "error", message=f"Could not reach {source}. Check your internet connection.")

    code = resp.status_code
    if code == 404:
        return SourceResult(source, "not_found", message=f"{source} has no record of this indicator.")
    if code == 429:
        return SourceResult(source, "rate_limited", message=f"{source} rate limit / quota exceeded. Wait and retry.")
    if code in (401, 403):
        return SourceResult(source, "auth_error", message=f"{source} rejected the API key (HTTP {code}). Check your .env file.")
    if code != 200:
        return SourceResult(source, "error", message=f"{source} returned unexpected HTTP {code}.")
    try:
        payload = resp.json()
    except ValueError:
        return SourceResult(source, "error", message=f"{source} returned a response that was not valid JSON.")
    return SourceResult(source, "ok", data={"raw": payload})


def _iso(ts) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        return None


def parse_vt(raw: dict) -> dict:
    """Pull the useful fields out of a VirusTotal v3 object response."""
    attrs = (raw.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    cats = attrs.get("categories") or {}
    return {
        "malicious": stats.get("malicious") if stats else None,
        "suspicious": stats.get("suspicious") if stats else None,
        "harmless": stats.get("harmless") if stats else None,
        "undetected": stats.get("undetected") if stats else None,
        "engines_total": sum(v for v in stats.values() if isinstance(v, int)) if stats else None,
        "reputation": attrs.get("reputation"),
        "last_analysis_date": _iso(attrs.get("last_analysis_date")),
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "name": attrs.get("meaningful_name") or attrs.get("title"),
        "file_type": attrs.get("type_description"),
        "tags": attrs.get("tags") or [],
        "categories": sorted(set(cats.values())) if isinstance(cats, dict) else [],
    }


def parse_otx(raw: dict) -> dict:
    """Pull the useful fields out of an OTX '/general' response."""
    info = raw.get("pulse_info") or {}
    pulses = info.get("pulses") or []
    tags, families, adversaries = set(), set(), set()
    for p in pulses:
        tags.update(p.get("tags") or [])
        if p.get("adversary"):
            adversaries.add(p["adversary"])
        for fam in p.get("malware_families") or []:
            name = (fam.get("display_name") or fam.get("id")) if isinstance(fam, dict) else fam
            if name:
                families.add(str(name))
    return {
        "pulse_count": info.get("count", len(pulses)) or 0,
        "pulse_names": [p.get("name", "(unnamed)") for p in pulses[:5]],
        "tags": sorted(tags)[:15],
        "malware_families": sorted(families),
        "adversaries": sorted(adversaries),
        "reputation": raw.get("reputation"),
        "country": raw.get("country_name"),
        "asn": raw.get("asn"),
    }


def vt_path(itype: str, value: str) -> str:
    if itype == "ip":
        return f"/ip_addresses/{value}"
    if itype == "domain":
        return f"/domains/{value}"
    if itype == "hash":
        return f"/files/{value}"
    # URLs are identified by the unpadded URL-safe base64 of the URL
    return "/urls/" + base64.urlsafe_b64encode(value.encode()).decode().strip("=")


def query_virustotal(itype: str, value: str, api_key: Optional[str]) -> SourceResult:
    if not api_key:
        return SourceResult("VirusTotal", "no_key", message="VT_API_KEY is not set.")
    res = _get("VirusTotal", VT_BASE + vt_path(itype, value), {"x-apikey": api_key}, VT_LIMITER)
    if res.status == "ok":
        res.data = parse_vt(res.data["raw"])
    return res


def otx_path(itype: str, value: str) -> str:
    if itype == "ip":
        return f"/indicators/{'IPv6' if ':' in value else 'IPv4'}/{quote(value, safe=':')}/general"
    if itype == "domain":
        return f"/indicators/domain/{value}/general"
    if itype == "hash":
        return f"/indicators/file/{value}/general"
    return f"/indicators/url/{quote(value, safe='')}/general"


def query_otx(itype: str, value: str, api_key: Optional[str]) -> SourceResult:
    if not api_key:
        return SourceResult("AlienVault OTX", "no_key", message="OTX_API_KEY is not set.")
    res = _get("AlienVault OTX", OTX_BASE + otx_path(itype, value), {"X-OTX-API-KEY": api_key})
    if res.status == "ok":
        res.data = parse_otx(res.data["raw"])
    return res

# ==================== risk.py ====================
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RiskAssessment:
    level: str
    points: int
    reasons: List[str] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)


def assess_risk(vt: Optional[dict], otx: Optional[dict]) -> RiskAssessment:
    points, reasons, caveats = 0, [], []
    vt_has_stats = bool(vt) and vt.get("malicious") is not None

    if vt_has_stats:
        mal, sus = vt["malicious"] or 0, vt.get("suspicious") or 0
        total = vt.get("engines_total")
        if mal >= 5:
            points += 3
            reasons.append(f"+3: {mal} VirusTotal engines flagged it malicious (rule: >=5).")
        elif mal >= 1:
            points += 2
            reasons.append(f"+2: {mal} VirusTotal engine(s) flagged it malicious (rule: 1-4).")
        else:
            reasons.append(f"+0: no VirusTotal engines flagged it malicious (out of {total}).")
        if sus >= 1:
            points += 1
            reasons.append(f"+1: {sus} VirusTotal engine(s) rated it suspicious.")
        rep = vt.get("reputation")
        if isinstance(rep, int) and rep <= -10:
            points += 1
            reasons.append(f"+1: VirusTotal community reputation is {rep} (rule: <= -10).")
    elif vt:
        caveats.append("VirusTotal returned a record without analysis statistics.")
    else:
        caveats.append("No VirusTotal data was available for this indicator.")

    if otx:
        n = otx.get("pulse_count") or 0
        if n >= 5:
            points += 2
            reasons.append(f"+2: appears in {n} OTX pulses (rule: >=5).")
        elif n >= 1:
            points += 1
            reasons.append(f"+1: appears in {n} OTX pulse(s) (rule: 1-4).")
        else:
            reasons.append("+0: OTX knows the indicator but it is in no pulses.")
        if otx.get("malware_families"):
            points += 1
            reasons.append("+1: OTX pulses name malware families: " + ", ".join(otx["malware_families"][:5]) + ".")
        if n:
            caveats.append("OTX pulses are community-submitted and can include benign or shared infrastructure - verify manually.")
    else:
        caveats.append("No AlienVault OTX data was available for this indicator.")

    if not vt_has_stats and not otx:
        return RiskAssessment("Unknown", 0, ["No usable intelligence was returned by any source."],
                              caveats + ["Absence of data is NOT evidence that the indicator is safe."])
    if points >= 4:
        level = "High"
    elif points >= 2:
        level = "Medium"
    elif vt_has_stats:
        level = "Low"
        caveats.append("Low means no strong findings in the sources queried - it is not proof of safety.")
    else:
        level = "Unknown"
        caveats.append("Without VirusTotal analysis data there is not enough evidence to call this Low.")
    return RiskAssessment(level, points, reasons, caveats)

# ==================== report.py ====================
from datetime import datetime, timezone

import pandas as pd


SEC_VT = "Confirmed API finding - VirusTotal"
SEC_OTX = "Confirmed API finding - AlienVault OTX"
SEC_RISK = "Tool risk assessment (rule-based, NOT an API finding)"


def build_report(indicator: str, itype: str, vt: SourceResult, otx: SourceResult,
                 risk: RiskAssessment, demo: bool) -> dict:
    def pack(r):
        return {"status": r.status, "message": r.message, "data": r.data}
    return {
        "indicator": indicator,
        "type": itype,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "mode": "Demo (sample data)" if demo else "Live APIs",
        "virustotal": pack(vt),
        "otx": pack(otx),
        "risk": {"level": risk.level, "points": risk.points, "reasons": risk.reasons, "caveats": risk.caveats},
    }


def _fmt(v) -> str:
    if v is None or v == [] or v == "":
        return "Not available"
    return "; ".join(map(str, v)) if isinstance(v, list) else str(v)


def report_to_dataframe(report: dict) -> pd.DataFrame:
    rows = [("Investigation", k, v) for k, v in [
        ("Indicator", report["indicator"]), ("Type", report["type"]),
        ("Time", report["timestamp"]), ("Data mode", report["mode"])]]
    for section, key in ((SEC_VT, "virustotal"), (SEC_OTX, "otx")):
        src = report[key]
        rows.append((section, "Status", src["status"] + (f" - {src['message']}" if src["message"] else "")))
        for k, v in src["data"].items():
            rows.append((section, k.replace("_", " ").title(), _fmt(v)))
    risk = report["risk"]
    rows.append((SEC_RISK, "Risk level", risk["level"]))
    rows.append((SEC_RISK, "Points", risk["points"]))
    rows += [(SEC_RISK, "Reason", r) for r in risk["reasons"]]
    rows += [(SEC_RISK, "Caveat", c) for c in risk["caveats"]]
    return pd.DataFrame(rows, columns=["Section", "Field", "Value"])


def history_row(report: dict) -> dict:
    return {
        "Time": report["timestamp"], "Indicator": report["indicator"], "Type": report["type"],
        "Risk (tool)": report["risk"]["level"],
        "VT malicious": report["virustotal"]["data"].get("malicious"),
        "OTX pulses": report["otx"]["data"].get("pulse_count"),
        "Mode": report["mode"],
    }

# ==================== demo.py ====================
import json
from pathlib import Path


SAMPLES = Path(__file__).resolve().parent / "sample_data" / "samples.json"


def list_scenarios() -> list:
    return json.loads(SAMPLES.read_text(encoding="utf-8"))


def _to_result(name: str, spec: dict, parser) -> SourceResult:
    if spec.get("status") == "ok":
        return SourceResult(name, "ok", data=parser(spec["raw"]))
    return SourceResult(name, spec.get("status", "not_found"), message=spec.get("message", ""))


def load_demo(value: str):
    for s in list_scenarios():
        if s["indicator"].lower() == value.lower():
            return _to_result("VirusTotal", s["virustotal"], parse_vt), _to_result("AlienVault OTX", s["otx"], parse_otx)
    msg = "Not in the demo sample set. Pick a sample scenario or switch to Live mode."
    return SourceResult("VirusTotal", "not_found", message=msg), SourceResult("AlienVault OTX", "not_found", message=msg)

# ==================== investigator.py ====================


def investigate(raw_input: str, demo: bool = False) -> dict:
    itype, value = detect_indicator(raw_input)  # raises InvalidIndicatorError
    if demo:
        vt, otx = load_demo(value)
    else:
        vt = query_virustotal(itype, value, get_vt_key())
        otx = query_otx(itype, value, get_otx_key())
    risk = assess_risk(vt.data if vt.status == "ok" else None, otx.data if otx.status == "ok" else None)
    return build_report(value, itype, vt, otx, risk, demo)

# ==================== Streamlit dashboard ====================
import time

import pandas as pd
import streamlit as st


CACHE_TTL = 600  # seconds; re-using results avoids wasting API quota
COLORS = {"High": "#c0392b", "Medium": "#e67e22", "Low": "#27ae60", "Unknown": "#7f8c8d"}

st.set_page_config(page_title="iCyber - Threat Intelligence Aggregator", page_icon="🛡️", layout="wide")
st.session_state.setdefault("history", [])
st.session_state.setdefault("cache", {})
st.session_state.setdefault("current", None)

# ---------------- sidebar ----------------
with st.sidebar:
    st.header("Settings")
    mode = st.radio("Data source", ["Demo (sample data)", "Live APIs"])
    demo = mode.startswith("Demo")
    choice = "(type my own)"
    if demo:
        st.info("Demo mode uses mock data from sample_data/samples.json. No API calls, no credits used.")
        scenarios = list_scenarios()
        choice = st.selectbox("Sample scenario", ["(type my own)"] + [s["label"] for s in scenarios])
    else:
        st.write("VirusTotal key:", "✅ configured" if get_vt_key() else "❌ missing")
        st.write("OTX key:", "✅ configured" if get_otx_key() else "❌ missing")
        st.caption("Keys are read from environment variables / .env and are never displayed.")
        st.caption("VirusTotal public keys allow roughly 4 requests/minute; results are cached for 10 minutes.")
    if st.button("Clear history"):
        st.session_state["history"] = []

# ---------------- main ----------------
st.title("🛡️ iCyber")
st.caption("Threat Intelligence Aggregator. Combines VirusTotal and AlienVault OTX data into one report. For education and triage - always verify manually.")

default = ""
if demo and choice != "(type my own)":
    default = next(s["indicator"] for s in list_scenarios() if s["label"] == choice)
indicator = st.text_input("Indicator (IP, domain, URL or file hash)", value=default, key=f"ind_{choice}_{demo}",
                          placeholder="e.g. 8.8.8.8, example.com, https://example.com/path, or an MD5/SHA-1/SHA-256 hash")

if st.button("Investigate", type="primary"):
    try:
        itype, value = detect_indicator(indicator)
        if itype == "ip" and ip_warning(value):
            st.warning(ip_warning(value))
        cache_key, cached = (demo, value), st.session_state["cache"].get((demo, value))
        if not demo and cached and time.time() - cached[0] < CACHE_TTL:
            report = cached[1]
            st.caption("Showing a cached result from the last 10 minutes to save API quota.")
        else:
            with st.spinner("Querying sources..."):
                report = investigate(value, demo=demo)
            st.session_state["cache"][cache_key] = (time.time(), report)
            st.session_state["history"].append(history_row(report))
        st.session_state["current"] = report
    except InvalidIndicatorError as exc:
        st.error(str(exc))
    except Exception:  # last-resort guard so the dashboard never shows a raw traceback
        st.error("Something unexpected went wrong. Please try again.")


def show_source(title: str, src: dict, metrics: list):
    st.subheader(title)
    if src["status"] != "ok":
        (st.warning if src["status"] in ("rate_limited", "no_key", "auth_error", "error") else st.info)(
            f"Status: {src['status']}. {src['message']}")
        return
    cols = st.columns(len(metrics))
    for col, (label, key) in zip(cols, metrics):
        v = src["data"].get(key)
        col.metric(label, "N/A" if v is None else v)
    rows = [(k.replace("_", " ").title(), "; ".join(map(str, v)) if isinstance(v, list) else v)
            for k, v in src["data"].items() if v not in (None, [], "") and k not in dict((m[1], 1) for m in metrics)]
    if rows:
        st.dataframe(pd.DataFrame(rows, columns=["Field", "Value"]).astype(str), hide_index=True, use_container_width=True)


report = st.session_state["current"]
if report:
    risk = report["risk"]
    st.divider()
    st.markdown(f"**Indicator:** `{report['indicator']}`  |  **Type:** {report['type']}  |  **Mode:** {report['mode']}")
    st.markdown(
        f"<div style='padding:14px;border-radius:8px;background:{COLORS[risk['level']]};color:white;font-size:1.3rem'>"
        f"Tool risk assessment: <b>{risk['level']}</b> ({risk['points']} points)</div>", unsafe_allow_html=True)
    st.caption("This rating is produced by this tool's own transparent rules. It is not an API finding.")
    with st.expander("Why this rating? (rules applied)", expanded=True):
        for r in risk["reasons"]:
            st.write("•", r)
        for c in risk["caveats"]:
            st.write("⚠️", c)

    st.markdown("### Confirmed API findings")
    c1, c2 = st.columns(2)
    with c1:
        show_source("VirusTotal", report["virustotal"],
                    [("Malicious", "malicious"), ("Suspicious", "suspicious"), ("Harmless", "harmless"), ("Reputation", "reputation")])
    with c2:
        show_source("AlienVault OTX", report["otx"], [("Pulses", "pulse_count"), ("Reputation", "reputation")])

    df = report_to_dataframe(report)
    st.download_button("⬇️ Export report as CSV", df.to_csv(index=False).encode("utf-8"),
                       file_name=f"threat_report_{report['type']}.csv", mime="text/csv")
    with st.expander("Full report table"):
        st.dataframe(df.astype(str), hide_index=True, use_container_width=True)

if st.session_state["history"]:
    st.divider()
    st.subheader("Investigation history (this session)")
    hist = pd.DataFrame(st.session_state["history"])
    st.dataframe(hist.astype(str), hide_index=True, use_container_width=True)
    st.download_button("⬇️ Export history as CSV", hist.to_csv(index=False).encode("utf-8"),
                       file_name="investigation_history.csv", mime="text/csv")
