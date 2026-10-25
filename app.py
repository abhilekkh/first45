"""First45 - from security advisory to working defenses in 45 seconds.

Run:  streamlit run app.py

Flow:  1 Read (Gemma 4)  ->  2 Defend (open-standard rules)  ->  3 Hunt (logs)
       ->  4 Respond (notify + human-approved blocking + Gemma incident report)
"""
from __future__ import annotations

import ipaddress
import json
import mimetypes
from pathlib import Path

import pandas as pd
import streamlit as st

import gemma_client
import hunt
import notify
import protect
import rules

ROOT = Path(__file__).resolve().parent
SAMPLE_ADVISORY = ROOT / "samples" / "php2shell_advisory.txt"
SAMPLE_THREAT = ROOT / "samples" / "threat_php2shell.json"
SAMPLE_REPORT = ROOT / "samples" / "report_php2shell.md"

st.set_page_config(page_title="First45", page_icon="🛡️", layout="wide")

st.markdown("""<style>
.chain{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 4px}
.chip{padding:4px 10px;border-radius:999px;font-size:.85rem;border:1px solid #64748b;opacity:.3}
.chip.on{opacity:1;font-weight:600}
.chip.prev{opacity:1;text-decoration:line-through;background:#14532d;color:#dcfce7;border-color:#22c55e}
.s-recon.on{background:#334155;color:#e2e8f0}
.s-exploit_attempt.on{background:#facc15;color:#1a1a1a}
.s-web_shell.on{background:#fb923c;color:#1a1a1a}
.s-loader_download.on{background:#ef4444;color:#fff}
.s-c2_contact.on{background:#b91c1c;color:#fff}
.s-ddos.on{background:#0f0f0f;color:#fff;border-color:#ef4444}
</style>""", unsafe_allow_html=True)


# ----------------------------------------------------------------- helpers ---
def is_external_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        return False


def chain_html(stages_hit: set[str], stages_prevented: set[str]) -> str:
    chips = []
    for s in hunt.STAGES:
        cls = "prev" if s in stages_prevented and s not in stages_hit else ("on" if s in stages_hit else "")
        label = hunt.STAGE_LABEL[s] + (" 🛡️" if cls == "prev" else "")
        chips.append(f'<span class="chip s-{s} {cls}">{label}</span>')
    return '<div class="chain">' + "→".join(chips) + "</div>"


@st.cache_data(show_spinner=False)
def gemma_read_text(text: str) -> dict:
    return gemma_client.extract_threat(text=text)


@st.cache_data(show_spinner=False)
def gemma_read_image(data: bytes, mime: str) -> dict:
    return gemma_client.extract_threat(image_bytes=data, mime_type=mime)


@st.cache_data(show_spinner=False)
def logs():
    return hunt.load_logs()


# ----------------------------------------------------------------- sidebar ---
with st.sidebar:
    st.header("1 · Read the advisory")
    source = st.radio("Advisory source", [
        "PHP2Shell sample (saved Gemma 4 result)",
        "Paste advisory text",
        "Upload PDF or screenshot",
        "No advisory (behaviour detectors only)",
    ])
    if source.startswith("PHP2Shell"):
        st.session_state.threat = json.loads(SAMPLE_THREAT.read_text(encoding="utf-8"))
        if st.button("Re-run Gemma 4 live on the sample (~1 min)"):
            with st.spinner("Gemma 4 is reading the advisory..."):
                st.session_state.threat = gemma_client.extract_threat(text=SAMPLE_ADVISORY.read_text(encoding="utf-8"))
    elif source.startswith("Paste"):
        text = st.text_area("Advisory text", height=200, placeholder="Paste any security advisory or news article...")
        if st.button("Read with Gemma 4", type="primary", disabled=not text.strip()):
            with st.spinner("Gemma 4 is reading the advisory..."):
                st.session_state.threat = gemma_read_text(text)
    elif source.startswith("Upload"):
        up = st.file_uploader("PDF, PNG, JPG or TXT", type=["pdf", "png", "jpg", "jpeg", "webp", "txt"])
        if up and st.button("Read with Gemma 4", type="primary"):
            data = up.getvalue()
            mime = up.type or mimetypes.guess_type(up.name)[0] or ""
            with st.spinner("Gemma 4 is reading the advisory..."):
                if mime.startswith("image/"):
                    st.session_state.threat = gemma_read_image(data, mime)
                elif mime == "application/pdf":
                    st.session_state.threat = gemma_read_text(gemma_client.read_pdf_text(data))
                else:
                    st.session_state.threat = gemma_read_text(data.decode("utf-8", "ignore"))
    else:
        st.session_state.threat = None

    st.divider()
    st.header("Response settings")
    approve_mode = st.toggle("Approval mode (allow blocking)", value=False,
                             help="Off = dry run: First45 only shows what it would block.")
    approver = st.text_input("Approver name", value="IT admin")
    if st.button("Reset demo (clear all blocks)"):
        protect.reset()
        st.rerun()

threat = st.session_state.get("threat")

# ------------------------------------------------------------------ header ---
st.title("🛡️ First45")
st.caption("PHP2Shell was attacked **45 minutes** after disclosure. First45 turns any security advisory into "
           "working defenses in **45 seconds**, for teams with no security staff. Open-weight AI: **Gemma 4**.")

# ------------------------------------------------------------- threat card ---
if threat:
    meta = threat.get("_meta", {})
    chk = meta.get("ioc_check", {})
    nv, nu = len(chk.get("verified", [])), len(chk.get("unverified", []))
    c1, c2, c3, c4 = st.columns([3, 1, 1, 1])
    c1.subheader(f"{threat.get('name', 'Threat')}  ·  {', '.join(threat.get('cves', []))}")
    c1.write(threat.get("summary", ""))
    c2.metric("CVSS", threat.get("cvss") or "-")
    c3.metric("Indicators", nv + nu)
    c4.metric("Verified in advisory", f"{nv}/{nv + nu}")
    st.caption(f"Read by **{meta.get('model', '?')}** (Gemma 4, open weights, Apache 2.0) "
               f"from {meta.get('input', 'text')} in {meta.get('seconds', '?')} s. "
               "Every indicator is cross-checked against the advisory text to catch AI hallucinations.")
    if nu:
        st.warning(f"⚠️ Not found in the advisory (treated as unverified, not auto-blocked): {', '.join(chk['unverified'])}")
    v1, v2 = st.columns(2)
    v1.success("**Fixed versions:** " + ", ".join(threat.get("fixed_versions", [])) if threat.get("fixed_versions") else "No fixed versions listed")
    if threat.get("no_fix_branches"):
        v2.error("**No patch for:** " + ", ".join(threat["no_fix_branches"]) + " → upgrade")
else:
    st.info("No advisory loaded: running **behaviour detectors only** (day-zero mode). "
            "They catch web exploits, brute force, scans, web shells, malware downloads, botnet beaconing, DDoS and odd DNS.")

findings, summary = hunt.hunt(logs(), threat, protect.blocked_ips())

tab_hunt, tab_rules, tab_report, tab_ai = st.tabs(
    ["🎯 Hunt & respond", "📜 Defenses (rules)", "📝 Incident report", "🔍 How the AI is used"])

# -------------------------------------------------------------------- hunt ---
with tab_hunt:
    comp = summary[summary["verdict"].str.contains("COMPROMISED")]
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Servers", len(summary))
    m2.metric("Compromised", len(comp))
    m3.metric("Attacked", int(summary["verdict"].str.contains("ATTACKED").sum()))
    m4.metric("Alerts", len(findings))
    m5.metric("Prevented (replay)", int(findings["prevented"].sum()) if len(findings) else 0)

    if len(comp):
        names = ", ".join(comp["host"])
        st.error(f"🚨 **{len(comp)} server(s) compromised: {names}.** Isolate them and review the steps below.")
        if st.button("📲 Send alert to admins"):
            lines = [f"{r.host}: {r.verdict} - {r.furthest_stage}" for r in summary.itertuples()]
            sent = notify.send_alert(f"First45: {len(comp)} server(s) compromised", "\n".join(lines))
            st.toast("Alert sent via " + ", ".join(sent) if sent else
                     "No push channel set (add NTFY_TOPIC in .env). Alert shown here only.")

    for row in summary.itertuples():
        hf = findings[findings["host"] == row.host] if len(findings) else findings
        live = set(hf[~hf["prevented"]]["stage"]) if len(hf) else set()
        prevented = set(hf[hf["prevented"]]["stage"]) if len(hf) else set()
        with st.container(border=True):
            a, b = st.columns([3, 2])
            a.markdown(f"**{row.host}** · {row.role} · `{row.ip}` — **{row.verdict}**")
            b.markdown(row.patch)
            st.markdown(chain_html(live, prevented), unsafe_allow_html=True)
            if not len(hf):
                continue
            with st.expander(f"Evidence ({len(hf)} alerts)"):
                agg = (hf.groupby(["stage", "family", "detector", "actor"], sort=False)
                         .agg(first_seen=("ts", "min"), count=("ts", "size"),
                              evidence=("evidence", "first"), prevented=("prevented", "all"))
                         .reset_index())
                agg["stage"] = agg["stage"].map(hunt.STAGE_LABEL)
                agg["stage_order"] = agg["stage"].map({v: i for i, v in enumerate(hunt.STAGE_LABEL.values())})
                st.dataframe(agg.sort_values(["stage_order", "first_seen"]).drop(columns="stage_order"),
                             hide_index=True, width="stretch")

            actors = sorted({x for x in hf["actor_ip"] if is_external_ip(x)} |
                            {x for x in hf["actor"] if "." in x and not x[0].isdigit()})
            if actors:
                st.markdown("**Prevent** (AI recommends, a human approves):")
                blocked = protect.blocked_ips()
                cols = st.columns(min(len(actors), 4))
                for i, ip in enumerate(actors):
                    col = cols[i % len(cols)]
                    if ip in blocked:
                        col.success(f"🛡️ {ip} blocked")
                        if col.button("Undo", key=f"undo-{row.host}-{ip}"):
                            protect.unblock(ip, approver)
                            st.rerun()
                    elif approve_mode:
                        if col.button(f"Approve block {ip}", key=f"blk-{row.host}-{ip}"):
                            protect.approve_block(ip, approver, f"{row.host}: {', '.join(sorted(live))}")
                            st.rerun()
                    else:
                        col.code(f"would block {ip}", language=None)

    log = protect.audit_log()
    if log:
        with st.expander("Audit log (who approved what)"):
            st.code("\n".join(log), language=None)

# ------------------------------------------------------------------- rules ---
with tab_rules:
    if threat:
        st.write("Generated from the advisory in **open formats**: deploy in any open-source SIEM, IDS, web server or firewall.")
        for fname, text in rules.all_rules(threat).items():
            st.markdown(f"**{fname}**")
            lang = "yaml" if fname.endswith(".yml") else ("bash" if fname.endswith(".txt") else None)
            st.code(text, language=lang)
            st.download_button(f"Download {fname}", text, file_name=fname, key=f"dl-{fname}")
    else:
        st.info("Load an advisory to generate advisory-specific rules. Behaviour detectors are always on.")
    st.markdown("**Always-on behaviour detectors** (no advisory needed): " +
                ", ".join(d.__name__.replace("_", " ") for d in hunt.BEHAVIOUR_DETECTORS))

# ------------------------------------------------------------------ report ---
with tab_report:
    st.write("Gemma 4 turns the evidence into a plain-English report for a non-expert admin. "
             "It may only use facts from the threat and findings below.")
    use_saved = SAMPLE_REPORT.exists() and source.startswith("PHP2Shell")
    if use_saved:
        st.caption("Showing the saved Gemma 4 report for the PHP2Shell sample.")
        st.session_state.setdefault("report", SAMPLE_REPORT.read_text(encoding="utf-8"))
    if st.button("✍️ Write incident report with Gemma 4", type="primary"):
        payload = summary.drop(columns=["stages"]).to_dict("records")
        top = (findings.groupby(["host", "stage", "detector", "actor"]).agg(
            first_seen=("ts", "min"), count=("ts", "size"), evidence=("evidence", "first"))
            .reset_index().to_dict("records")) if len(findings) else []
        with st.spinner("Gemma 4 is writing the report..."):
            st.session_state.report = gemma_client.write_report(threat or {"name": "behaviour detections"},
                                                                {"hosts": payload, "evidence": top})
        if source.startswith("PHP2Shell"):
            SAMPLE_REPORT.write_text(st.session_state.report, encoding="utf-8")
    if st.session_state.get("report"):
        st.markdown(st.session_state.report)
        st.download_button("Download report (.md)", st.session_state.report, file_name="first45-incident-report.md")

# -------------------------------------------------------------- how AI used ---
with tab_ai:
    st.markdown(f"""
| Step | Where in the code | AI? |
|------|-------------------|-----|
| Read advisory (text / PDF / screenshot) → threat JSON | `gemma_client.py` → `extract_threat()` | **Gemma 4** `{gemma_client.MODEL}` via Gemini API |
| Anti-hallucination check | `gemma_client.py` → `verify_iocs()` | No: every indicator must appear in the advisory |
| Write Sigma / Suricata / nginx / firewall rules | `rules.py` | No: deterministic templates |
| Hunt logs (advisory + behaviour detectors) | `hunt.py` | No: explainable rules |
| Block attackers | `protect.py` | No: **human approval required**, audit log |
| Incident report | `gemma_client.py` → `write_report()` | **Gemma 4** |
| Reusable by any AI agent | `skills/advisory-to-detection/SKILL.md` | Agent Skills standard |

**Model:** Gemma 4 (open weights) — licence: Apache 2.0 ·
[Gemma 4 docs](https://ai.google.dev/gemma/docs/core) ·
[Apache 2.0 announcement](https://opensource.googleblog.com/2026/03/gemma-4-expanding-the-gemmaverse-with-apache-20.html)

**Safety:** defensive only. Demo logs are synthetic, exploit payloads are redacted, and First45 never changes a
system firewall by itself.
""")
