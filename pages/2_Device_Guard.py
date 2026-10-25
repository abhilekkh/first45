"""First45 Device Guard page - is THIS computer part of a botnet?

Server logs (main page) show attacks from outside. This page looks from inside:
every connection on this computer -> the program that opened it -> botnet behaviour.
AI recommends, a human decides: nothing is stopped or blocked without a click.
"""
from __future__ import annotations

import html
import importlib
import json
import platform
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import psutil
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import device_guard as dg  # noqa: E402
import gemma_client  # noqa: E402
import notify  # noqa: E402
import ui  # noqa: E402

import os  # noqa: E402

if os.getenv("FIRST45_DEV"):          # hot-reload only in dev; off = snappier clicks
    for _m in (ui, dg):
        importlib.reload(_m)

SAMPLE_THREAT = ROOT / "samples" / "threat_php2shell.json"
SIMULATOR = ROOT / "simulate_bot.py"

MODE = ui.setup("device", "First45 · Device Guard")

EXPLAIN = {
    "Talks to advisory attacker IP": "Talking to a computer the advisory names as the attackers' server.",
    "Uses advisory C2 port": "Connecting on the botnet control port named in the advisory.",
    "Botnet beaconing": "Checking in with one server at a steady rhythm, like a bot waiting for orders.",
    "Botnet port open": "Listening on a port that botnets use to receive commands.",
    "Scanning to spread": "Dialling many computers on one port, looking for new victims.",
    "Outbound flood": "Firing hundreds of connections at one target (a DDoS attack).",
    "Runs from a temp/download folder": "Running from a Temp or Downloads folder, where malware is usually dropped.",
}

ss = st.session_state
if "threat" not in ss:                      # page opened before the main page
    ss.threat = json.loads(SAMPLE_THREAT.read_text(encoding="utf-8"))
ss.setdefault("stopped", set())
ss.setdefault("dev_msgs", [])
ss.setdefault("alerted", set())
threat = ss.threat


def chain_html(stages: list[str], prevented: bool) -> str:
    chips = []
    for s in dg.STAGES:
        on = s in stages
        cls = "chip prev" if (on and prevented) else f"chip s-{s}{' on' if on else ''}"
        chips.append(f'<span class="{cls}">{dg.STAGE_LABEL[s]}</span>')
    return '<div class="chain">' + '<span class="sep">/</span>'.join(chips) + "</div>"


def sim_running() -> bool:
    pid = ss.get("sim_pid")
    return bool(pid) and psutil.pid_exists(pid)


def start_sim() -> None:
    flags = subprocess.CREATE_NEW_CONSOLE if platform.system() == "Windows" else 0
    ss.sim_pid = subprocess.Popen([sys.executable, str(SIMULATOR)], cwd=str(ROOT), creationflags=flags).pid


def stop_sim() -> None:
    try:
        parent = psutil.Process(ss.get("sim_pid"))
        for child in parent.children(recursive=True):
            child.terminate()
        parent.terminate()
    except (psutil.NoSuchProcess, TypeError, ValueError):
        pass
    ss.pop("sim_pid", None)


def run_scan(seconds: int, loopback: bool) -> None:
    # Live phase console: show the detection happening step by step, not a black box.
    console = st.empty()
    steps: list[str] = []

    def show(line: str) -> None:
        steps.append(line)
        console.code("\n".join(steps), language=None)

    show(f"Watching every live network connection on this computer for {seconds} s ...")
    bar = st.progress(0.0, text="Watching connections  0%")
    samples = dg.watch(seconds, progress=lambda f: bar.progress(f, text=f"Watching connections  {int(f * 100)}%"))
    bar.empty()
    conns = sum(len(rows) for _, rows in samples)
    show(f"Captured {len(samples)} snapshots, {conns} socket observations.")
    time.sleep(0.3)
    show("Linking each connection to the program (PID) that opened it ...")
    time.sleep(0.3)
    show("Checking: advisory attacker IPs/ports, beaconing rhythm, scanning, outbound flood, temp-folder origin ...")
    time.sleep(0.3)
    ss.dev_result = dg.analyse(samples, threat, include_loopback=loopback)
    flagged = ss.dev_result["stats"]["flagged"]
    show(f"Done. {ss.dev_result['stats']['programs']} programs seen, {flagged} flagged.")
    time.sleep(0.4)
    console.empty()
    if ss.dev_result["findings"]:
        ss.last_findings = ss.dev_result["findings"]       # kept so Gemma can explain after a clean re-scan
    ss.dev_scanned_at = datetime.now().strftime("%H:%M:%S")
    ss.stopped = {pid for pid in ss.stopped if psutil.pid_exists(pid)}
    new_bad = [f for f in ss.dev_result["findings"]
               if f["verdict"] == "LIKELY BOTNET" and f["pid"] not in ss.alerted]
    if new_bad:
        sent = notify.send_alert("First45: botnet behaviour on this computer",
                                 "; ".join(f"{f['name']} (pid {f['pid']})" for f in new_bad))
        ss.alerted |= {f["pid"] for f in new_bad}
        if sent:
            ss.dev_msgs.append("Alert sent: " + ", ".join(sent))


# ------------------------------------------------------------------ hero ---
ui.hero("Device Guard · this computer",
        "Is this machine part of a botnet?",
        "Device Guard links every network connection to the program that opened it and looks for botnet "
        "behaviour: phoning home, scanning to spread, flooding a target. It checks the attacker addresses "
        "Gemma 4 extracted from the advisory. Nothing is stopped or blocked until you approve it.")

# ---------------------------------------------------------- control panel ---
with st.container(border=True):
    c1, c2, c3, c4 = st.columns([2.2, 1.6, 1.4, 1.6], vertical_alignment="center")
    seconds = c1.slider("Watch window (seconds)", 10, 60, 20, step=5)
    loopback = c2.checkbox("Include loopback", value=sim_running(),
                           help="Needed for the safe simulator, which never leaves this computer.")
    guard = c3.toggle("Keep guarding", help="Re-scan continuously and alert on new botnet behaviour.")
    scan_clicked = c4.button("Scan this computer", type="primary", width="stretch")
    s1, s2, s3 = st.columns([2.2, 1.6, 3.0], vertical_alignment="center")
    if sim_running():
        s1.markdown(ui.badge(f"Simulator running · pid {ss.sim_pid}", "high"), unsafe_allow_html=True)
        if s2.button("Stop simulator", width="stretch"):
            stop_sim()
            st.rerun()
    else:
        s1.markdown('<span class="f45-muted">Safe demo bot: imitates Mirai, talks only to 127.0.0.1</span>',
                    unsafe_allow_html=True)
        if s2.button("Start simulator", width="stretch"):
            start_sim()
            time.sleep(1.5)
            st.rerun()
    s3.markdown(f'<div style="text-align:right">'
                f'{ui.badge("Administrator", "ok") if dg.is_admin() else ui.badge("Standard user", "low")}'
                f' <span class="f45-muted" style="font-size:.85rem">&nbsp;Advisory: '
                f'{html.escape((threat or {}).get("name") or "none")}</span></div>', unsafe_allow_html=True)
    ss.approver = st.session_state.get("approver", "IT admin")

if scan_clicked or guard:
    run_scan(10 if guard else seconds, loopback)

for msg in ss.dev_msgs[-4:]:
    st.info(msg)

# --------------------------------------------------------------- results ---
result = ss.get("dev_result")
if result:
    stats, findings = result["stats"], result["findings"]
    bad = [f for f in findings if f["pid"] not in ss.stopped]
    ui.section(f"Scan at {ss.dev_scanned_at}")
    if not findings:
        st.success(f"No botnet behaviour seen. {stats['programs']} programs and {stats['connections_seen']} "
                   f"connections watched over {stats['seconds']} s.")
    elif not bad:
        st.success(f"All {len(findings)} flagged programs were stopped. Scan again to confirm.")
    else:
        worst = sum(f["verdict"] == "LIKELY BOTNET" for f in bad)
        st.error(f"{len(bad)} program(s) on this computer behave like a botnet ({worst} likely).")
    m = st.columns(4)
    m[0].metric("Programs seen", stats["programs"])
    m[1].metric("Connections watched", f"{stats['connections_seen']:,}")
    m[2].metric("Flagged", stats["flagged"])
    m[3].metric("Advisory IOCs checked", stats["ioc_ips"] + stats["ioc_ports"])

    for f in findings:
        stopped = f["pid"] in ss.stopped
        level = "ok" if stopped else ("crit" if f["verdict"] == "LIKELY BOTNET" else "high")
        label = "Stopped" if stopped else f["verdict"].title()
        with st.container(border=True):
            st.markdown(f'<div class="f45-host"><span class="f45-dot d-{level}"></span><b>{html.escape(f["name"])}</b>'
                        f'<span class="role">pid {f["pid"]} · score {f["score"]}</span>{ui.badge(label, level)}</div>',
                        unsafe_allow_html=True)
            st.markdown(chain_html(f["stages"], stopped), unsafe_allow_html=True)
            rows = "".join(
                f'<li><b>{html.escape(d["detector"])}</b>: {EXPLAIN.get(d["detector"], "")}<br>'
                f'<span class="f45-ev">{html.escape(d["detail"])}</span></li>' for d in f["detections"])
            st.markdown(f'<ul style="margin:.3rem 0 .4rem 1rem">{rows}</ul>', unsafe_allow_html=True)
            st.markdown(f'<div class="f45-ev">{html.escape(f["exe"] or "?")}<br>{html.escape(f["cmdline"][:200])}</div>',
                        unsafe_allow_html=True)

            a, b = st.columns(2, vertical_alignment="bottom")
            with a:
                ok = st.checkbox("I approve stopping this program", key=f"ok_stop_{f['pid']}", disabled=stopped)
                if st.button("Stop program", key=f"stop_{f['pid']}", disabled=stopped or not ok, type="primary"):
                    msg = dg.stop_process(f["pid"], ss.approver, "; ".join(x["detector"] for x in f["detections"]))
                    ss.dev_msgs.append(msg)
                    if msg.startswith(("Stopped", "Already")):
                        ss.stopped.add(f["pid"])
                    st.rerun()
            with b:
                ips = [ip for ip in f["remote_ips"] if not dg._is_loopback(ip)]
                if ips:
                    ip = st.selectbox("Remote address", ips, key=f"ip_{f['pid']}")
                    if st.button("Block in firewall", key=f"fw_{f['pid']}"):
                        ss.dev_msgs.append(dg.block_ip(ip, ss.approver, f"{f['name']} pid {f['pid']}"))
                        st.rerun()
                else:
                    st.caption("No internet address to block: it talks only to this computer.")

    with st.expander("Raw findings (JSON)"):
        st.json(findings)

    ui.section("Plain-English explanation, written by Gemma 4")
    explain_these = findings or ss.get("last_findings", [])
    if st.button("Explain with Gemma 4", disabled=not explain_these):
        with st.spinner("Gemma 4 is writing the explanation"):
            try:
                ss.dev_report = gemma_client.explain_device(threat, explain_these, dg.audit_log())
            except Exception as error:
                st.error(f"Gemma call failed: {error}")
    if ss.get("dev_report"):
        with st.container(border=True):
            st.markdown(ss.dev_report)
        st.download_button("Download explanation (.md)", ss.dev_report, "device_report.md")

blocked = dg.blocked_ips()
with st.expander(f"Action log and firewall blocks ({len(blocked)} IPs blocked)"):
    for ip, info in blocked.items():
        col, undo = st.columns([4, 1])
        col.markdown(f'<span class="f45-ev">{ip} · {html.escape(info["reason"])} · by {html.escape(info["by"])} '
                     f'at {info["at"]}</span>', unsafe_allow_html=True)
        if undo.button("Undo", key=f"undo_{ip}"):
            ss.dev_msgs.append(dg.unblock_ip(ip, ss.approver))
            st.rerun()
    log = dg.audit_log()
    if log:
        st.dataframe(pd.DataFrame([line.split("\t") for line in log],
                                  columns=["time", "action", "target", "by", "reason"]),
                     hide_index=True, width="stretch")
    else:
        st.caption("No actions yet.")

ui.footer()

if guard:
    st.caption("Guarding. Next scan in 3 s. Turn off Keep guarding to stop.")
    time.sleep(3)
    st.rerun()
