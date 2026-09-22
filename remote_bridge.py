#!/usr/bin/env python3
"""Bridge com o controller externo.

Alem de repassar comandos, detecta timeouts (local_timeout / bot_timeout) e
pede rotacao de IP via ip_rotator. Tambem aceita do controller uma mensagem
{"type": "rotate", "bot": ..., "reason": "bot_timeout"}.
"""
import asyncio
import json
import os
import time
from pathlib import Path

import websockets

import ip_rotator

BASE_DIR = Path(__file__).resolve().parent
CMD_DIR = BASE_DIR / "commands"
STATE_DIR = BASE_DIR / "state"

DEFAULT_CONTROLLER_URL = "wss://botvertra-controller.onrender.com/ws/agent"
CONTROLLER_URL = os.getenv("CONTROLLER_URL", "").strip()
CONTROLLER_TOKEN = os.getenv("CONTROLLER_TOKEN", "").strip()
CONTAINER_NAME = os.getenv("CONTAINER_NAME", "container5").strip()

if not CONTROLLER_TOKEN:
    raise SystemExit("CONTROLLER_TOKEN precisa estar configurado")

if not (CONTROLLER_URL.startswith("ws://") or CONTROLLER_URL.startswith("wss://")):
    print("[bridge] CONTROLLER_URL inválida; usando controller padrão do Render", flush=True)
    CONTROLLER_URL = DEFAULT_CONTROLLER_URL

def safe_error(exc):
    text = str(exc)
    if CONTROLLER_TOKEN:
        text = text.replace(CONTROLLER_TOKEN, "<redacted>")
    if CONTROLLER_URL:
        text = text.replace(CONTROLLER_URL, "<controller>")
    return text

BOT_COUNT = int(os.getenv("BOT_COUNT", "10"))
BOTS = [f"bot-{i:02d}" for i in range(1, BOT_COUNT + 1)]

TIMEOUT_ERRORS = {"local_timeout", "bot_timeout", "lock_timeout"}


def should_rotate(result):
    """Erros que indicam que o bot deve tentar um IP diferente."""
    if not isinstance(result, dict):
        return None
    err = result.get("error")
    if isinstance(err, str):
        for prefix in ("invalid_local_response",):
            if err.startswith(prefix):
                return prefix
        if err in TIMEOUT_ERRORS:
            return err
    return None


async def run_local(bot, command, args):
    inbox = CMD_DIR / f"{bot}.json"
    outbox = CMD_DIR / f"{bot}.out.json"

    locked = await asyncio.to_thread(ip_rotator.acquire_bot_lock, bot)
    if not locked:
        return {"ok": False, "bot": bot, "error": "lock_timeout"}

    try:
        outbox.unlink(missing_ok=True)
        inbox.write_text(
            json.dumps({"command": command, "args": args}, indent=2),
            encoding="utf-8",
        )

        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if outbox.exists():
                try:
                    return json.loads(outbox.read_text(encoding="utf-8"))
                except Exception as exc:  # noqa: BLE001
                    return {"ok": False, "bot": bot, "error": f"invalid_local_response: {exc}"}
            await asyncio.sleep(0.1)

        return {"ok": False, "bot": bot, "error": "local_timeout"}
    finally:
        await asyncio.to_thread(ip_rotator.release_bot_lock, bot)


async def handle_command(msg):
    request_id = msg.get("id")
    bot = msg.get("bot")
    command = msg.get("command")
    args = msg.get("args", [])

    if bot not in BOTS:
        result = {"ok": False, "bot": bot, "error": "unknown_bot"}
    elif not (STATE_DIR / f"{bot}.json").exists():
        result = {"ok": False, "bot": bot, "error": "bot_offline"}
    else:
        result = await run_local(bot, command, args)

    reason = should_rotate(result)
    if reason:
        ip_rotator.request_rotation(bot, reason)

    return result, request_id, bot


def handle_rotate(msg):
    bot = msg.get("bot")
    reason = msg.get("reason", "bot_timeout")
    if bot in BOTS:
        applied = ip_rotator.request_rotation(bot, reason)
        print(f"[bridge] rotate {bot} ({reason}) aplicado={applied}", flush=True)
        return applied
    return False


async def connect_once():
    send_lock = asyncio.Lock()
    tasks = set()

    async with websockets.connect(
        CONTROLLER_URL,
        ping_interval=20,
        ping_timeout=20,
        close_timeout=5,
        max_size=2_000_000,
    ) as ws:
        async def send_json(payload):
            async with send_lock:
                await ws.send(json.dumps(payload))

        async def process_command(msg):
            result, request_id, bot = await handle_command(msg)
            await send_json({
                "type": "result",
                "id": request_id,
                "bot": bot,
                "result": result,
            })

        await send_json({
            "type": "auth",
            "token": CONTROLLER_TOKEN,
            "container": CONTAINER_NAME,
            "bots": BOTS,
        })

        auth = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        if not auth.get("ok"):
            raise RuntimeError("controller recusou autenticacao")

        print(f"[bridge] {CONTAINER_NAME} conectado • {len(BOTS)} bots registrados • concorrente", flush=True)

        try:
            async for raw in ws:
                msg = json.loads(raw)
                msg_type = msg.get("type")

                if msg_type == "rotate":
                    applied = handle_rotate(msg)
                    await send_json({
                        "type": "rotate_ack",
                        "bot": msg.get("bot"),
                        "applied": applied,
                    })
                    continue

                if msg_type != "command":
                    continue

                task = asyncio.create_task(process_command(msg))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)


async def main():
    delay = 2
    while True:
        try:
            await connect_once()
            delay = 2
        except Exception as exc:  # noqa: BLE001
            print(f"[bridge] desconectado: {safe_error(exc)} • retry {delay}s", flush=True)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)


if __name__ == "__main__":
    asyncio.run(main())
