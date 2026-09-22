#!/usr/bin/env python3
"""Bot worker - IP publico proprio por processo.

Rotas suportadas (definidas pelo start.py via env):
  * BOT_PROXY        -> proxy dedicado (http/socks) para este bot
  * TOR_SOCKS_URL +  TOR_ISOLATION_ID -> circuito Tor isolado por bot
  * nenhuma          -> saida direta pela VPS
"""
import asyncio
import json
import os
import platform
import shutil
import socket
import sys
import time
import urllib.request
from pathlib import Path

import requests

BOT_ID = os.getenv("BOT_ID", "bot-unknown")
BOT_PROXY = os.getenv("BOT_PROXY", "").strip()
TOR_SOCKS_URL = os.getenv("TOR_SOCKS_URL", "").strip()
TOR_ISOLATION_ID = os.getenv("TOR_ISOLATION_ID", BOT_ID).strip()
BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / "state"
LOG_DIR = BASE_DIR / "logs"
CMD_DIR = BASE_DIR / "commands"

for d in (STATE_DIR, LOG_DIR, CMD_DIR):
    d.mkdir(exist_ok=True)

STARTED_AT = time.time()
WORKER_BUILD = "multi-ip-v1"

ALLOWED_COMMANDS = {
    "ping", "status", "uptime", "hostname",
    "disk", "memory", "echo", "logs", "internet", "public_ip",
}


def read_tor_state():
    path = STATE_DIR / "tor-state.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "stage": "state_read_error", "detail": str(exc)}


def read_mem():
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            data = {}
            for line in f:
                key, value = line.split(":", 1)
                data[key] = value.strip()
            return {
                "MemTotal": data.get("MemTotal"),
                "MemAvailable": data.get("MemAvailable"),
            }
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def build_requests_proxies():
    """Monta o dicionario de proxies efetivo deste bot."""
    if TOR_SOCKS_URL:
        base = TOR_SOCKS_URL
        if "://" not in base:
            base = "socks5h://" + base
        scheme, rest = base.split("://", 1)
        if "@" in rest:
            rest = rest.split("@", 1)[1]
        isolated = f"{scheme}://{TOR_ISOLATION_ID}:x@{rest}"
        return {"http": isolated, "https": isolated}

    if BOT_PROXY:
        return {"http": BOT_PROXY, "https": BOT_PROXY}

    return {}


def describe_route():
    if TOR_SOCKS_URL:
        return {"mode": "tor", "isolation_id": TOR_ISOLATION_ID}
    if BOT_PROXY:
        host = BOT_PROXY.split("@")[-1]
        return {"mode": "proxy", "endpoint": host}
    return {"mode": "direct"}


def check_google_internet():
    target = "www.google.com"
    url = "https://www.google.com/generate_204"
    started = time.perf_counter()

    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False, "bot": BOT_ID, "internet": False,
            "target": target, "stage": "dns", "error": str(exc),
        }

    try:
        response = requests.get(
            url,
            headers={"User-Agent": "BotVertra-Connectivity/1.0"},
            timeout=10,
            proxies=build_requests_proxies(),
        )
        status = int(response.status_code)
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        return {
            "ok": status in (200, 204),
            "bot": BOT_ID,
            "internet": status in (200, 204),
            "target": target,
            "resolved_ip": resolved_ip,
            "http_status": status,
            "latency_ms": latency_ms,
        }
    except Exception as exc:  # noqa: BLE001
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        return {
            "ok": False, "bot": BOT_ID, "internet": False,
            "target": target, "resolved_ip": resolved_ip,
            "stage": "https", "latency_ms": latency_ms, "error": str(exc),
        }


def get_public_ip():
    url = "https://api.ipify.org?format=json"
    started = time.perf_counter()
    try:
        response = requests.get(
            url,
            headers={"User-Agent": "BotVertra-IPCheck/1.0"},
            timeout=10,
            proxies=build_requests_proxies(),
        )
        response.raise_for_status()
        payload = response.json()
        ip = str(payload.get("ip", "")).strip()
        return {
            "ok": bool(ip),
            "bot": BOT_ID,
            "public_ip": ip or None,
            "route": describe_route(),
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False, "bot": BOT_ID, "public_ip": None,
            "route": describe_route(), "error": str(exc),
        }


def tail_logs(lines=40):
    lines = max(1, min(int(lines), 200))
    result = []
    for path in (LOG_DIR / f"{BOT_ID}.log", LOG_DIR / f"{BOT_ID}.stdout.log"):
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace").splitlines()
            result.append({"file": path.name, "lines": content[-lines:]})
    return result


def execute_command(payload: dict):
    cmd = str(payload.get("command", "")).strip().lower()
    args = payload.get("args", [])

    if cmd not in ALLOWED_COMMANDS:
        return {
            "ok": False, "bot": BOT_ID,
            "error": f"command_not_allowed: {cmd}",
            "allowed": sorted(ALLOWED_COMMANDS),
        }

    if cmd == "ping":
        return {"ok": True, "bot": BOT_ID, "result": "pong"}

    if cmd == "status":
        return {
            "ok": True,
            "bot": BOT_ID,
            "status": "online",
            "pid": os.getpid(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "worker_build": WORKER_BUILD,
            "features": sorted(ALLOWED_COMMANDS),
            "route": describe_route(),
            "proxy_configured": bool(BOT_PROXY),
            "tor_configured": bool(TOR_SOCKS_URL),
            "tor_isolation_id": TOR_ISOLATION_ID if TOR_SOCKS_URL else None,
            "tor_state": read_tor_state(),
        }

    if cmd == "uptime":
        return {"ok": True, "bot": BOT_ID, "uptime_seconds": round(time.time() - STARTED_AT, 2)}

    if cmd == "hostname":
        return {"ok": True, "bot": BOT_ID, "hostname": socket.gethostname()}

    if cmd == "disk":
        total, used, free = shutil.disk_usage("/")
        return {
            "ok": True, "bot": BOT_ID,
            "disk": {
                "total_mb": total // 1024 // 1024,
                "used_mb": used // 1024 // 1024,
                "free_mb": free // 1024 // 1024,
            },
        }

    if cmd == "memory":
        return {"ok": True, "bot": BOT_ID, "memory": read_mem()}

    if cmd == "internet":
        return check_google_internet()

    if cmd == "public_ip":
        return get_public_ip()

    if cmd == "echo":
        return {"ok": True, "bot": BOT_ID, "result": " ".join(str(x) for x in args)[:500]}

    if cmd == "logs":
        amount = args[0] if args else 40
        try:
            amount = int(amount)
        except Exception:  # noqa: BLE001
            amount = 40
        return {"ok": True, "bot": BOT_ID, "logs": tail_logs(amount)}

    return {"ok": False, "bot": BOT_ID, "error": "unknown"}


async def process_inbox():
    inbox = CMD_DIR / f"{BOT_ID}.json"
    outbox = CMD_DIR / f"{BOT_ID}.out.json"

    while True:
        if inbox.exists():
            try:
                payload = json.loads(inbox.read_text(encoding="utf-8"))
                result = execute_command(payload)
                outbox.write_text(json.dumps(result, indent=2), encoding="utf-8")
                inbox.unlink(missing_ok=True)

                with open(LOG_DIR / f"{BOT_ID}.log", "a", encoding="utf-8") as log:
                    log.write(json.dumps({
                        "ts": time.time(),
                        "input": payload,
                        "output": result,
                    }) + "\n")

            except Exception as e:  # noqa: BLE001
                err = {"ok": False, "bot": BOT_ID, "error": str(e)}
                outbox.write_text(json.dumps(err, indent=2), encoding="utf-8")
                inbox.unlink(missing_ok=True)

        await asyncio.sleep(0.25)


async def main():
    state = {"bot": BOT_ID, "pid": os.getpid(), "started_at": time.time()}
    (STATE_DIR / f"{BOT_ID}.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(f"[{BOT_ID}] online pid={os.getpid()} route={describe_route()}", flush=True)
    try:
        await process_inbox()
    finally:
        (STATE_DIR / f"{BOT_ID}.json").unlink(missing_ok=True)
        print(f"[{BOT_ID}] offline", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
