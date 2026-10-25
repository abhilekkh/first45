"""SAFE botnet simulator for demoing First45 Device Guard.

It never touches the internet: every connection goes to 127.0.0.1 (this computer).
It only *imitates the network behaviour* of a Mirai-style bot so the detectors fire:

  launcher (this file)  ->  fake C2 server on 127.0.0.1:50792  (50792 = C2 port named in the
                                                                PHP2Shell advisory)
                        ->  copies the "bot" to your Temp folder and starts it there
  bot (Temp copy)       ->  checks in with the C2 every 3 s       (beaconing)
                        ->  every 20 s opens 120 connections      (flood burst)

Stop it with Ctrl+C, or let First45 "Stop process" the bot: the launcher notices and exits.
It also stops by itself after 10 minutes.

Run:  python simulate_bot.py
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HOST, PORT = "127.0.0.1", 50792
MAX_RUNTIME = 600


def c2_server(stop: threading.Event) -> None:
    """Accept connections and keep each open a few seconds (so snapshots can see them)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(512)
    srv.settimeout(0.5)
    held: list[tuple[float, socket.socket]] = []
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
            held.append((time.time(), conn))
        except socket.timeout:
            pass
        now = time.time()
        for t, conn in [h for h in held if now - h[0] > 6]:
            conn.close()
        held = [h for h in held if now - h[0] <= 6]
    srv.close()


def bot() -> None:
    """The 'infected program'. Only talks to 127.0.0.1."""
    start, last_flood = time.time(), 0.0
    while time.time() - start < MAX_RUNTIME:
        try:
            beacon = socket.create_connection((HOST, PORT), timeout=2)
            time.sleep(1.5)                      # hold the check-in briefly
            beacon.close()
        except OSError:
            return                               # C2 gone -> exit
        if time.time() - last_flood > 20:
            burst = []
            for _ in range(120):
                try:
                    burst.append(socket.create_connection((HOST, PORT), timeout=2))
                except OSError:
                    break
            time.sleep(4)
            for s in burst:
                s.close()
            last_flood = time.time()
        time.sleep(1.5)


def launcher() -> None:
    stop = threading.Event()
    threading.Thread(target=c2_server, args=(stop,), daemon=True).start()
    drop = Path(tempfile.gettempdir()) / "first45_sim"
    drop.mkdir(exist_ok=True)
    copy = drop / "svc_update.py"                # a name real droppers like to use
    shutil.copy(__file__, copy)
    time.sleep(0.5)
    child = subprocess.Popen([sys.executable, str(copy), "--bot"])
    print(f"[sim] fake C2 listening on {HOST}:{PORT}")
    print(f"[sim] bot started from Temp: {copy} (pid {child.pid})")
    print("[sim] open First45 > Device Guard, tick 'Include loopback', and scan. Ctrl+C to stop.")
    try:
        while child.poll() is None:
            time.sleep(1)
        print(f"[sim] bot stopped (exit code {child.returncode}). First45 prevented it. Bye.")
    except KeyboardInterrupt:
        child.terminate()
        print("[sim] stopped by you.")
    stop.set()


if __name__ == "__main__":
    bot() if "--bot" in sys.argv else launcher()
