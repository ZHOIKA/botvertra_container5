#!/usr/bin/env python3
"""Worker compartilhado: 20 bots lógicos em um único processo Python."""

import asyncio
import json
import os
import platform
import shutil
import socket
import sys
import time
from pathlib import Path

import requests
import ip_rotator

BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / "state"
LOG_DIR = BASE_DIR / "logs"
CMD_DIR = BASE_DIR / "commands"

for directory in (STATE_DIR, LOG_DIR, CMD_DIR):
    directory.mkdir(exist_ok=True)

CONTAINER_NAME = os.getenv("CONTAINER_NAME", "container").strip()
BOT_COUNT = int(os.getenv("BOT_COUNT", "20"))
BOTS = [f"bot-{i:02d}" for i in range(1, BOT_COUNT + 1)]
STARTED_AT = time.time()
WORKER_BUILD = "shared-worker-v1"

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
    except Exception as exc:
        return {"ok": False, "stage": "state_read_error", "detail": str(exc)}


def _read_int(path):
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
        if value == "max":
            return None
        return int(value)
    except Exception:
        return None


def process_rss_bytes():
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except Exception:
        pass
    return None


def memory_snapshot():
    current = _read_int("/sys/fs/cgroup/memory.current")
    limit = _read_int("/sys/fs/cgroup/memory.max")

    if current is None:
        current = _read_int("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    if limit is None:
        limit = _read_int("/sys/fs/cgroup/memory/memory.limit_in_bytes")

    result = {
        "worker_shared": True,
        "worker_pid": os.getpid(),
        "worker_rss_mb": round(process_rss_bytes() / 1024 / 1024, 2) if process_rss_bytes() else None,
        "cgroup_used_mb": round(current / 1024 / 1024, 2) if current is not None else None,
        "cgroup_limit_mb": round(limit / 1024 / 1024, 2) if limit is not None else None,
    }
    if current is not None and limit:
        result["cgroup_percent"] = round(current * 100 / limit, 2)
    return result


def route_for(bot):
    gen = ip_rotator.generation(bot)
    return ip_rotator.resolve_route(bot, gen), gen


def build_proxies(route):
    env = route.get("env", {})
    proxy = env.get("BOT_PROXY", "").strip()
    tor_url = env.get("TOR_SOCKS_URL", "").strip()
    isolation = env.get("TOR_ISOLATION_ID", "").strip()

    if tor_url:
        base = tor_url if "://" in tor_url else "socks5h://" + tor_url
        scheme, rest = base.split("://", 1)
        if "@" in rest:
            rest = rest.split("@", 1)[1]
        isolated = f"{scheme}://{isolation or 'shared'}:x@{rest}"
        return {"http": isolated, "https": isolated}

    if proxy:
        return {"http": proxy, "https": proxy}

    return {}


def describe_route(route, gen):
    mode = route.get("mode", "direct")
    target = route.get("target", "vps")
    return {"mode": mode, "target": target, "generation": gen}


def public_ip(bot):
    route, gen = route_for(bot)
    started = time.perf_counter()
    try:
        response = requests.get(
            "https://api.ipify.org?format=json",
            headers={"User-Agent": "BotVertra-IPCheck/2.0"},
            timeout=10,
            proxies=build_proxies(route),
        )
        response.raise_for_status()
        ip = str(response.json().get("ip", "")).strip()
        return {
            "ok": bool(ip),
            "bot": bot,
            "public_ip": ip or None,
            "route": describe_route(route, gen),
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except Exception as exc:
        return {
            "ok": False,
            "bot": bot,
            "public_ip": None,
            "route": describe_route(route, gen),
            "error": str(exc),
        }


def internet_check(bot):
    route, gen = route_for(bot)
    started = time.perf_counter()
    try:
        response = requests.get(
            "https://www.google.com/generate_204",
            headers={"User-Agent": "BotVertra-Connectivity/2.0"},
            timeout=10,
            proxies=build_proxies(route),
        )
        status = int(response.status_code)
        return {
            "ok": status in (200, 204),
            "bot": bot,
            "internet": status in (200, 204),
            "http_status": status,
            "route": describe_route(route, gen),
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except Exception as exc:
        return {
            "ok": False,
            "bot": bot,
            "internet": False,
            "route": describe_route(route, gen),
            "error": str(exc),
        }


def write_json_atomic(path, payload):
    """Publica JSON completo de uma vez para evitar leitura parcial pelo bridge."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    data = json.dumps(payload, indent=2)

    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(tmp, path)


def tail_logs(bot, lines=40):
    lines = max(1, min(int(lines), 200))
    result = []
    for path in (LOG_DIR / f"{bot}.log", LOG_DIR / "shared-worker.stdout.log"):
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace").splitlines()
            result.append({"file": path.name, "lines": content[-lines:]})
    return result


def execute_command(bot, payload):
    cmd = str(payload.get("command", "")).strip().lower()
    args = payload.get("args", [])

    if cmd not in ALLOWED_COMMANDS:
        return {"ok": False, "bot": bot, "error": f"command_not_allowed: {cmd}"}

    if cmd == "ping":
        return {"ok": True, "bot": bot, "result": "pong"}

    if cmd == "status":
        route, gen = route_for(bot)
        env = route.get("env", {})
        return {
            "ok": True,
            "bot": bot,
            "status": "online",
            "pid": os.getpid(),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "worker_build": WORKER_BUILD,
            "shared_worker": True,
            "route": describe_route(route, gen),
            "proxy_configured": bool(env.get("BOT_PROXY")),
            "tor_configured": bool(env.get("TOR_SOCKS_URL")),
            "tor_isolation_id": env.get("TOR_ISOLATION_ID"),
            "tor_state": read_tor_state(),
        }

    if cmd == "uptime":
        return {"ok": True, "bot": bot, "uptime_seconds": round(time.time() - STARTED_AT, 2)}

    if cmd == "hostname":
        return {"ok": True, "bot": bot, "hostname": socket.gethostname()}

    if cmd == "disk":
        total, used, free = shutil.disk_usage("/")
        return {
            "ok": True, "bot": bot,
            "disk": {
                "total_mb": total // 1024 // 1024,
                "used_mb": used // 1024 // 1024,
                "free_mb": free // 1024 // 1024,
            },
        }

    if cmd == "memory":
        return {"ok": True, "bot": bot, "memory": memory_snapshot()}

    if cmd == "internet":
        return internet_check(bot)

    if cmd == "public_ip":
        return public_ip(bot)

    if cmd == "echo":
        return {"ok": True, "bot": bot, "result": " ".join(str(x) for x in args)[:500]}

    if cmd == "logs":
        amount = args[0] if args else 40
        try:
            amount = int(amount)
        except Exception:
            amount = 40
        return {"ok": True, "bot": bot, "logs": tail_logs(bot, amount)}

    return {"ok": False, "bot": bot, "error": "unknown"}


async def bot_loop(bot):
    inbox = CMD_DIR / f"{bot}.json"
    outbox = CMD_DIR / f"{bot}.out.json"
    state = STATE_DIR / f"{bot}.json"

    state.write_text(json.dumps({
        "bot": bot,
        "pid": os.getpid(),
        "shared_worker": True,
        "started_at": STARTED_AT,
    }, indent=2), encoding="utf-8")

    try:
        while True:
            if inbox.exists():
                try:
                    payload = json.loads(inbox.read_text(encoding="utf-8"))
                    result = await asyncio.to_thread(execute_command, bot, payload)
                    write_json_atomic(outbox, result)
                    inbox.unlink(missing_ok=True)

                    with open(LOG_DIR / f"{bot}.log", "a", encoding="utf-8") as log:
                        log.write(json.dumps({
                            "ts": time.time(),
                            "input": payload,
                            "output": result,
                        }) + "\n")
                except Exception as exc:
                    write_json_atomic(outbox, {
                        "ok": False, "bot": bot, "error": str(exc)
                    })
                    inbox.unlink(missing_ok=True)

            await asyncio.sleep(0.15)
    finally:
        state.unlink(missing_ok=True)


async def main():
    print(
        f"[shared-worker] {CONTAINER_NAME} • {len(BOTS)} bots lógicos • pid={os.getpid()}",
        flush=True,
    )
    await asyncio.gather(*(bot_loop(bot) for bot in BOTS))


if __name__ == "__main__":
    asyncio.run(main())
