#!/usr/bin/env python3
"""Supervisor enxuto: 20 bots lógicos em um único worker Python."""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

CONTAINER_NAME = os.getenv("CONTAINER_NAME", "container5").strip()
BOT_COUNT = int(os.getenv("BOT_COUNT_TARGET", "10"))
os.environ["CONTAINER_NAME"] = CONTAINER_NAME
os.environ["BOT_COUNT"] = str(BOT_COUNT)

import ip_rotator
from ip_rotator import all_bots
from tor_manager import start_shared_tor

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
PID_DIR = BASE_DIR / "pids"
STATE_DIR = BASE_DIR / "state"
CMD_DIR = BASE_DIR / "commands"

for directory in (LOG_DIR, PID_DIR, STATE_DIR, CMD_DIR):
    directory.mkdir(exist_ok=True)

TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "19050"))
IP_AUDIT_INTERVAL = int(os.getenv("IP_AUDIT_INTERVAL", "90"))

print(f"[manager] build={CONTAINER_NAME}-shared-worker-v1", flush=True)

tor = start_shared_tor(BASE_DIR, STATE_DIR, LOG_DIR, TOR_SOCKS_PORT, CONTAINER_NAME)
tor_process = tor["process"]
if tor["socks_url"]:
    os.environ["TOR_SOCKS_URL"] = tor["socks_url"]
    print(f"[tor] SOCKS pronto: {tor['socks_url']}", flush=True)
else:
    print("[tor] sem SOCKS; bots sem proxy dedicado usarao o IP da VPS", flush=True)


def spawn(name, script, log_name=None):
    stdout = None
    handle = None
    if log_name:
        handle = open(LOG_DIR / log_name, "ab", buffering=0)
        stdout = handle
    proc = subprocess.Popen(
        [sys.executable, str(BASE_DIR / script)],
        cwd=str(BASE_DIR),
        env=os.environ.copy(),
        stdout=stdout,
        stderr=subprocess.STDOUT if stdout is not None else None,
    )
    return proc, handle


worker, worker_log = spawn("worker", "shared_worker.py", "shared-worker.stdout.log")
bridge, bridge_log = spawn("bridge", "remote_bridge.py")

for bot in all_bots():
    (PID_DIR / f"{bot}.pid").write_text(str(worker.pid), encoding="utf-8")

print(f"[manager] {BOT_COUNT} bots lógicos no worker pid={worker.pid}", flush=True)
print(f"[manager] bridge externo iniciado pid={bridge.pid}", flush=True)

if IP_AUDIT_INTERVAL > 0:
    threading.Thread(
        target=ip_rotator.audit_loop,
        args=(IP_AUDIT_INTERVAL,),
        daemon=True,
    ).start()
    print(f"[manager] auditoria de IP ativa (intervalo={IP_AUDIT_INTERVAL}s)", flush=True)

try:
    while True:
        for bot in all_bots():
            reason = ip_rotator.consume_rotation(bot)
            if reason:
                gen = ip_rotator.bump_generation(bot, reason)
                print(f"[route] {bot} -> geração {gen} ({reason})", flush=True)

        if worker.poll() is not None:
            print(f"[manager] shared worker caiu ({worker.returncode}); reiniciando", flush=True)
            if worker_log:
                try:
                    worker_log.close()
                except OSError:
                    pass
            worker, worker_log = spawn("worker", "shared_worker.py", "shared-worker.stdout.log")
            for bot in all_bots():
                (PID_DIR / f"{bot}.pid").write_text(str(worker.pid), encoding="utf-8")

        if bridge.poll() is not None:
            print(f"[manager] bridge caiu ({bridge.returncode}); reiniciando", flush=True)
            bridge, bridge_log = spawn("bridge", "remote_bridge.py")

        time.sleep(1)

except KeyboardInterrupt:
    print("[manager] encerrando...", flush=True)

finally:
    for proc in (bridge, worker, tor_process):
        if proc is not None and proc.poll() is None:
            proc.terminate()

    for handle in (worker_log, bridge_log):
        if handle:
            try:
                handle.close()
            except OSError:
                pass

    for bot in all_bots():
        (STATE_DIR / f"{bot}.json").unlink(missing_ok=True)

    print("[manager] finalizado", flush=True)
