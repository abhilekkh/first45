"""First45 - from security advisory to working defenses in 45 seconds.

Run:  streamlit run app.py

Four simple steps:
  1. Threat   - Gemma 4 reads an advisory (sample, URL, text, PDF or screenshot)
  2. Servers  - pick real access logs (upload) or the recorded college network
  3. Results  - plain-English verdict per server + kill-chain replay
  4. Fix      - human-approved blocking, defense files, Gemma 4 incident report, alerts
"""
from __future__ import annotations

import ipaddress
import json
import mimetypes
import time
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
STEPS = ["① Threat", "② Servers", "③ Results", "④ Fix & report"]

st.set_page_config(page_title="First45", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.chain{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:6px 0}
.chip{padding:5px 11px;border-radius:999px;font-size:.88rem;border:1px solid #64748b;opacity:.28}
.chip.on{opacity:1;font-weight:600}
.chip.prev{opacity:1;text-decoration:line-through;background:#14532d;color:#dcfce7;border-color:#22c55e}
.s-recon.on{background:#334155;color:#e2e8f0}
.s-exploit_attempt.on{background:#facc15;color:#1a1a1a}
.s-web_shell.on{background:#fb923c;color:#1a1a1a}
.s-loader_download.on{background:#ef4444;color:#fff}
.s-c2_contact.on{background:#b91c1c;color:#fff}
.s-ddos.on{background:#0f0f0f;color:#fff;border-color:#ef4444}
.big{font-size:1.35rem;font-weight:650;margin:.2rem 0 .6rem}
</style>""", unsafe_allow_html=True)

# ------------------------------------------------------- plain English ---
EXPLAIN = {
    "known attacker IP": "This address is named in the advisory as an attacker.",
    "connection to IOC": "Your server talked to the attackers' computers.",
    "C2 domain lookup": "Your server looked up the botnet's control address.",
    "SQL injection": "Tried to trick the database into revealing data such as passwords.",
    "Path traversal": "Tried to read secret files on the server.",
    "Command injection / RCE": "Tried to run its own commands on your server.",
    "Cross-site scripting": "Tried to plant code that runs in visitors' browsers.",
    "Brute-force login": "Guessed passwords on the login page again and again.",
    "Vulnerability scan": "Probed for forgotten files and admin pages.",
    "Web shell used": "Used a hidden backdoor page to control the server.",
    "Executable downloaded": "The server downloaded a program: very likely malware.",
    "Botnet beaconing": "The server keeps checking in with a remote controller, like a botnet member.",
    "Outbound flood": "The server is flooding another network with traffic (DDoS).",
    "Suspicious domain lookup": "Looked up an unusual web address.",
}
STAGE_STORY = {
    "recon": "was scanned for weak spots",
    "exploit_attempt": "faced break-in attempts",
    "web_shell": "had a hidden backdoor page installed",
    "loader_download": "downloaded malware",
    "c2_contact": "is taking orders from a botnet controller",
    "ddos": "is being used to attack other networks",
}


def explain(detector: str) -> str:
    for key, text in EXPLAIN.items():
        if key.lower() in detector.lower():
            return text
    return ""


def story(host: str, stages: list[str]) -> str:
    if not stages:
        return f"No signs of attack on **{host}**."
    parts = [STAGE_STORY[s] for s in stages]
    return f"**{host}** " + (", ".join(parts[:-1]) + " and " + parts[-1] if len(parts) > 1 else parts[0]) + "."


def chain_html(hit: set[str], prevented: set[str] = frozenset()) -> str:
    chips = []
    for s in hunt.STAGES:
        cls = "on" if s in hit else ("prev" if s in prevented else "")
        chips.append(f'<span class="chip s-{s} {cls}">{hunt.STAGE_LABEL[s]}{" 🛡️" if cls == "prev" else ""}</span>')
    return '<div class="chain">' + " → ".join(chips) + "</div>"


INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


def is_blockable(value: str) -> bool:
    """Outside attackers (IPs not in our internal network, or domains) can be blocked."""
    try:
        ip = ipaddress.ip_address(value)
        return not any(ip in net for net in INTERNAL)
    except ValueError:
        return "." in value and not value[0].isdigit()   # a domain


# ---------------------------------------------------------- cached work ---
@st.cache_data(show_spinner=False)
def read_text(text: str) -> dict:
    return gemma_client.extract_threat(text=text)


@st.cache_data(show_spinner=False)
def read_image(data: bytes, mime: str) -> dict:
    return gemma_client.extract_threat(image_bytes=data, mime_type=mime)


@st.cache_data(show_spinner=False)
def demo_logs():
    return hunt.load_logs()


def go(step: int) -> None:
    """Move to another step (applied on the next run, before the step selector is drawn)."""
    st.session_state.pending_step = step
    st.rerun()


ss = st.session_state
ss.setdefault("step", STEPS[0])
if "pending_step" in ss:
    ss.step = STEPS[ss.pop("pending_step")]
ss.setdefault("threat", json.loads(SAMPLE_THREAT.read_text(encoding="utf-8")))
ss.setdefault("threat_source", "PHP2Shell sample")

# ---------------------------------------------------------------- header ---
st.title("🛡️ First45")
st.markdown("PHP2Shell was attacked **45 minutes** after it was announced. First45 turns any security advisory into "
            "working defenses in **45 seconds**, for colleges and small teams with no security staff.")
step = st.radio("Step", STEPS, horizontal=True, key="step", label_visibility="collapsed")

with st.sidebar:
    st.subheader("How it works")
    st.markdown("1. **Gemma 4** (open-weight AI) reads the advisory\n"
                "2. First45 writes defense rules in open formats\n"
                "3. It checks your server logs for the attack\n"
                "4. **You** approve every block")
    st.divider()
    ss.approver = st.text_input("Your name (for the approval log)", value=ss.get("approver", "IT admin"))
    if st.button("Reset demo"):
        protect.reset()
        for k in ("report", "logs", "log_source"):
            ss.pop(k, None)
        st.rerun()
    st.caption("Open source (MIT) · Gemma 4 (Apache 2.0)")

threat = ss.threat

# ======================================================== STEP 1: THREAT ===
if step == STEPS[0]:
    st.markdown('<div class="big">What threat are you worried about?</div>', unsafe_allow_html=True)
    choice = st.radio("Advisory", ["PHP2Shell (this week's attack, instant)", "Paste a news / advisory link",
                                   "Paste advisory text", "Upload a PDF or screenshot",
                                   "No advisory: just look for any attack"], label_visibility="collapsed")
    new = None
    try:
        if choice.startswith("PHP2Shell"):
            if st.button("Load PHP2Shell", type="primary"):
                new = json.loads(SAMPLE_THREAT.read_text(encoding="utf-8"))
            if st.button("…or let Gemma 4 read it live (about 1 minute)"):
                with st.spinner("Gemma 4 is reading the advisory…"):
                    new = gemma_client.extract_threat(text=SAMPLE_ADVISORY.read_text(encoding="utf-8"))
        elif choice.startswith("Paste a news"):
            url = st.text_input("Link to a security advisory or news article", placeholder="https://…")
            if st.button("Read it with Gemma 4", type="primary", disabled=not url.startswith("http")):
                with st.spinner("Downloading the page and asking Gemma 4 to read it…"):
                    new = read_text(gemma_client.fetch_url_text(url))
        elif choice.startswith("Paste advisory"):
            text = st.text_area("Advisory text", height=220)
            if st.button("Read it with Gemma 4", type="primary", disabled=not text.strip()):
                with st.spinner("Gemma 4 is reading…"):
                    new = read_text(text)
        elif choice.startswith("Upload"):
            up = st.file_uploader("PDF, PNG, JPG or TXT", type=["pdf", "png", "jpg", "jpeg", "webp", "txt"])
            if up and st.button("Read it with Gemma 4", type="primary"):
                data, mime = up.getvalue(), up.type or mimetypes.guess_type(up.name)[0] or ""
                with st.spinner("Gemma 4 is reading…"):
                    if mime.startswith("image/"):
                        new = read_image(data, mime)
                    elif mime == "application/pdf":
                        new = read_text(gemma_client.read_pdf_text(data))
                    else:
                        new = read_text(data.decode("utf-8", "ignore"))
        else:
            if st.button("Continue without an advisory", type="primary"):
                ss.threat, ss.threat_source = None, "none"
                go(1)
    except Exception as error:
        st.error(f"Could not read that advisory: {error}")
    if new:
        ss.threat, ss.threat_source = new, choice
        st.rerun()

    threat = ss.threat
    if threat:
        meta, chk = threat.get("_meta", {}), threat.get("_meta", {}).get("ioc_check", {})
        nv, nu = len(chk.get("verified", [])), len(chk.get("unverified", []))
        with st.container(border=True):
            st.markdown(f"### {threat.get('name', 'Threat')}  \n{threat.get('summary', '')}")
            a, b, c = st.columns(3)
            a.metric("Danger (CVSS, out of 10)", threat.get("cvss") or "?")
            b.metric("Attacker addresses found", len(threat["iocs"]["ips"]) + len(threat["iocs"]["domains"]))
            c.metric("Checked against the article", f"{nv}/{nv + nu} ✅" if not nu else f"{nv}/{nv + nu} ⚠️")
            if threat.get("fixed_versions"):
                st.success("**Safe versions:** " + ", ".join(threat["fixed_versions"]))
            if threat.get("no_fix_branches"):
                st.error("**No fix exists for:** " + ", ".join(threat["no_fix_branches"]) + ". These must be upgraded.")
            if nu:
                st.warning("Not found in the article, so treated as unverified: " + ", ".join(chk["unverified"]))
            st.caption(f"Read by Gemma 4 ({meta.get('model', '?')}, open weights) in {meta.get('seconds', '?')} s. "
                       "Every address is double-checked against the article so the AI can't invent one.")
            with st.expander("Details Gemma extracted"):
                st.json({k: v for k, v in threat.items() if k != "_meta"})
        if st.button("Next: check my servers →", type="primary"):
            go(1)

# ======================================================= STEP 2: SERVERS ===
elif step == STEPS[1]:
    st.markdown('<div class="big">Which servers should First45 check?</div>', unsafe_allow_html=True)
    src = st.radio("Logs", ["College network: 5 servers, logs from 22 Oct (demo data)",
                            "Upload my own server's access.log (nginx or Apache)"], label_visibility="collapsed")
    if src.startswith("College"):
        logs = demo_logs()
        st.caption("Real log formats (nginx access logs, DNS and connection logs). Generated for the demo, "
                   "with exploit payloads removed.")
        with st.expander("Peek at a raw log file (web-club.access.log)"):
            raw = (ROOT / "demo_logs" / "access" / "web-club.access.log").read_text(encoding="utf-8").splitlines()
            st.code("\n".join(raw[30:42]), language=None)
    else:
        up = st.file_uploader("access.log", type=["log", "txt"])
        name = st.text_input("Server name", value="my-server")
        logs = None
        if up:
            logs = hunt.logs_from_access_log(up.getvalue().decode("utf-8", "ignore"), name)
            st.success(f"Read {len(logs['web'])} requests from {up.name}.")
            if not len(logs["web"]):
                st.error("No lines in nginx/Apache format were found in this file.")
                logs = None
    if logs is not None:
        w, d, c = len(logs["web"]), len(logs["dns"]), len(logs["conn"])
        st.write(f"**{len(logs['inventory'])} server(s)** · {w:,} web requests · {d:,} DNS lookups · {c:,} connections")
        if st.button("🔎 Scan now", type="primary"):
            bar = st.progress(0, text="Starting…")
            checks = ["Matching the advisory's attacker addresses"] + \
                     [f"Looking for {d.__name__.replace('_', ' ')}" for d in hunt.BEHAVIOUR_DETECTORS]
            for i, label in enumerate(checks, 1):
                bar.progress(i / len(checks), text=label + "…")
                time.sleep(0.15)
            ss.logs, ss.log_source = logs, src
            go(2)

# ======================================================= STEP 3: RESULTS ===
elif step == STEPS[2]:
    if "logs" not in ss:
        st.info("First choose which servers to check.")
        if st.button("← Go to step ②"):
            go(1)
        st.stop()
    findings, summary = hunt.hunt(ss.logs, threat, protect.blocked_ips())
    infected = summary[summary["verdict"].str.contains("COMPROMISED")]
    attacked = summary[summary["verdict"].str.contains("ATTACKED")]
    protected = summary[summary["verdict"].str.contains("PROTECTED")]
    clean = summary[summary["verdict"].str.contains("SAFE")]
    head = []
    if len(infected):
        head.append(f"🔴 <b>{len(infected)} infected</b>")
    if len(attacked):
        head.append(f"🟡 {len(attacked)} attacked but not broken into")
    if len(protected):
        head.append(f"🛡️ {len(protected)} now protected")
    if len(clean):
        head.append(f"🟢 {len(clean)} clean")
    st.markdown('<div class="big">' + " · ".join(head) + "</div>", unsafe_allow_html=True)

    order = {"🔴": 0, "🟡": 1, "🛡": 2, "🟢": 3}
    summary["o"] = summary["verdict"].str[0].map(order).fillna(9)
    for row in summary.sort_values("o").itertuples():
        hf = findings[findings["host"] == row.host] if len(findings) else findings
        live = [s for s in hunt.STAGES if len(hf) and s in set(hf[~hf["prevented"]]["stage"])]
        prev = {s for s in hunt.STAGES if len(hf) and s in set(hf[hf["prevented"]]["stage"])}
        with st.container(border=True):
            a, b = st.columns([3, 2])
            a.markdown(f"#### {row.verdict.split(' ', 1)[0]} {row.host}  \n<small>{row.role}</small>", unsafe_allow_html=True)
            b.markdown(f"**{row.verdict.split(' ', 1)[1]}**  \n{row.patch}")
            st.markdown(story(row.host, live) if live else
                        ("All attacks against this server are now blocked." if prev else story(row.host, [])))
            if len(hf):
                st.markdown(chain_html(set(live), prev), unsafe_allow_html=True)
                c1, c2 = st.columns([1, 4])
                if live and c1.button("▶ Replay attack", key=f"rp-{row.host}"):
                    box = st.empty()
                    seen, lines = set(), []
                    for s in hunt.STAGES:
                        sf = hf[(hf["stage"] == s) & ~hf["prevented"]].sort_values("ts")
                        if sf.empty:
                            continue
                        first = sf.iloc[0]
                        seen.add(s)
                        lines.append(f"`{first.ts:%d %b %H:%M:%S}` **{hunt.STAGE_LABEL[s]}** — {explain(first.detector)} "
                                     f"*(from {first.actor})*")
                        box.markdown(chain_html(seen) + "\n\n" + "\n\n".join(lines), unsafe_allow_html=True)
                        time.sleep(1.0)
                with c2.expander(f"Evidence ({len(hf)} alerts)"):
                    agg = (hf.groupby(["stage", "detector", "actor"], sort=False)
                             .agg(first_seen=("ts", "min"), times=("ts", "size"),
                                  example=("evidence", "first"), blocked=("prevented", "all")).reset_index())
                    agg.insert(2, "what it means", agg["detector"].map(explain))
                    agg["stage"] = agg["stage"].map(hunt.STAGE_LABEL)
                    st.dataframe(agg, hide_index=True, width="stretch")
    if st.button("Next: fix it →", type="primary"):
        go(3)

# ==================================================== STEP 4: FIX & REPORT ===
else:
    if "logs" not in ss:
        st.info("First scan your servers.")
        if st.button("← Go to step ②"):
            go(1)
        st.stop()
    findings, summary = hunt.hunt(ss.logs, threat, protect.blocked_ips())
    st.markdown('<div class="big">Stop the attackers</div>', unsafe_allow_html=True)
    st.caption("First45 recommends. **You decide.** Every block is written to an approval log and can be undone. "
               "First45 never changes your firewall by itself: it writes a blocklist your web server reads.")

    blocked = protect.blocked_ips()
    if len(findings):
        att = findings[findings["actor_ip"].map(is_blockable) | findings["actor"].map(is_blockable)].copy()
        att["who"] = att.apply(lambda r: r.actor_ip if is_blockable(r.actor_ip) else r.actor, axis=1)
        att["rank"] = att["stage"].map({s: i for i, s in enumerate(hunt.STAGES)})
        for who, g in sorted(att.groupby("who"), key=lambda kv: -kv[1]["rank"].max()):
            worst = g.loc[g["rank"].idxmax()]
            with st.container(border=True):
                a, b = st.columns([4, 1])
                a.markdown(f"**{who}** · {hunt.STAGE_LABEL[worst.stage]} · {', '.join(sorted(g['host'].unique()))}  \n"
                           f"{explain(worst.detector)} *({len(g)} alerts)*")
                if who in blocked:
                    b.success("🛡️ Blocked")
                    if b.button("Undo", key=f"u-{who}"):
                        protect.unblock(who, ss.approver)
                        st.rerun()
                elif b.button("🛡️ Block", key=f"b-{who}", type="primary"):
                    protect.approve_block(who, ss.approver, f"{worst.detector} on {', '.join(sorted(g['host'].unique()))}")
                    st.rerun()
        if blocked:
            st.info("Blocked attackers are now refused. Open step ③ again: their attacks show as 🛡️ prevented.")
    else:
        st.success("No attackers to block.")

    st.divider()
    left, right = st.columns(2)
    with left:
        st.markdown("#### 📢 Alert the team")
        if st.button("Send alert to admins' phones"):
            lines = [f"{r.host}: {r.verdict}" for r in summary.itertuples()]
            sent = notify.send_alert("First45 security alert", "\n".join(lines))
            st.toast("Sent via " + ", ".join(sent) if sent else
                     "No phone channel configured yet (set NTFY_TOPIC in .env).")
        st.markdown("#### 📜 Defense files")
        if threat:
            notes = {".sigma.yml": "for security dashboards (Sigma)", ".rules": "for intrusion detection (Suricata)",
                     ".nginx-deny.conf": "for the web server (nginx)", ".firewall.txt": "firewall commands (Linux / Windows)"}
            for fname, text in rules.all_rules(threat).items():
                note = next((v for k, v in notes.items() if fname.endswith(k)), "")
                st.download_button(f"⬇ {fname}  ·  {note}", text, file_name=fname, key=f"dl-{fname}")
            with st.expander("Preview the rules"):
                for fname, text in rules.all_rules(threat).items():
                    st.markdown(f"`{fname}`")
                    st.code(text, language="yaml" if fname.endswith(".yml") else None)
        else:
            st.caption("Load an advisory in step ① to get advisory-specific rules.")
        log = protect.audit_log()
        if log:
            with st.expander("Approval log"):
                st.code("\n".join(log), language=None)
    with right:
        st.markdown("#### 📝 Incident report (written by Gemma 4)")
        if "report" not in ss and SAMPLE_REPORT.exists() and ss.get("threat_source", "").startswith("PHP2Shell") \
                and ss.get("log_source", "").startswith("College"):
            ss.report = SAMPLE_REPORT.read_text(encoding="utf-8")
        if st.button("✍️ Write the report", type="primary"):
            hosts = summary.drop(columns=["stages"]).to_dict("records")
            ev = (findings.groupby(["host", "stage", "detector", "actor"]).agg(
                first_seen=("ts", "min"), times=("ts", "size"), example=("evidence", "first"))
                .reset_index().to_dict("records")) if len(findings) else []
            with st.spinner("Gemma 4 is writing (about a minute)…"):
                try:
                    ss.report = gemma_client.write_report(threat or {"name": "general attack check"},
                                                          {"hosts": hosts, "evidence": ev})
                    if ss.get("threat_source", "").startswith("PHP2Shell") and ss.get("log_source", "").startswith("College"):
                        SAMPLE_REPORT.write_text(ss.report, encoding="utf-8")
                except Exception as error:
                    st.error(f"Gemma could not write the report: {error}")
        if ss.get("report"):
            st.download_button("⬇ Download report", ss.report, file_name="first45-incident-report.md")
            with st.container(border=True, height=520):
                st.markdown(ss.report)
