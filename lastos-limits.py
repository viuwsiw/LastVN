#!/usr/bin/env python3
"""Per-nickname download limits for LastOS's VLESS Direct service."""

import asyncio
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

CONFIG = Path("/usr/local/etc/xray/config.json")
XRAY = "/usr/local/bin/xray"
SETTINGS = Path("/etc/lastos-limits.json")
GATEWAY = Path("/etc/lastos-limits-egress.json")
UNIT = Path("/etc/systemd/system/lastos-limits.service")
DB = Path("/var/lib/lastos-limits/usage.db")
SERVICE = "lastos-limits.service"
PREFIX = "lastos-limit-"
GATEWAY_PORT = 16099
PORT_BASE = 16100
NICK = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def run(*args):
    subprocess.run(args, check=True)


def world():
    return json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {}


def saved_bytes(name):
    if not DB.exists():
        return 0
    with sqlite3.connect(f"file:{DB}?mode=ro", uri=True) as db:
        row = db.execute("SELECT bytes FROM usage WHERE nick = ?", (name,)).fetchone()
        return row[0] if row else 0


def write(path, content, mode=0o600):
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            os.fchmod(handle.fileno(), mode)
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def as_json(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()


def checked_config(data):
    with tempfile.NamedTemporaryFile(suffix=".json") as draft:
        draft.write(data)
        draft.flush()
        run(XRAY, "run", "-test", "-c", draft.name)


def install():
    write(UNIT, b"""[Unit]
Description=LastOS VLESS download limits
After=network.target
Before=xray.service

[Service]
DynamicUser=true
StateDirectory=lastos-limits
LoadCredential=settings.json:/etc/lastos-limits.json
LoadCredential=egress.json:/etc/lastos-limits-egress.json
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray
ExecStart=/usr/local/sbin/lastos-limits serve
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
""", 0o644)
    run("systemctl", "daemon-reload")


def compile_configs(config, limits):
    current_inbound = config["inbounds"][0]
    clients = {client.get("email") for client in current_inbound["settings"]["clients"]}
    applied = {name: item for name, item in limits.items() if name in clients}
    old_routing = config.setdefault("routing", {}).setdefault("rules", [])
    old_routing[:] = [
        rule for rule in old_routing if not rule.get("outboundTag", "").startswith(PREFIX)
    ]
    outbounds = config["outbounds"]
    outbounds[:] = [item for item in outbounds if not item.get("tag", "").startswith(PREFIX)]
    local_id = str(uuid.uuid4())
    add_rules = []
    for name, item in applied.items():
        tag = PREFIX + name
        outbounds.append({
            "tag": tag, "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1", "port": item["port"],
                "users": [{"id": local_id, "encryption": "none"}],
            }]},
        })
        add_rules.append({
            "type": "field", "user": [name], "inboundTag": [current_inbound["tag"]],
            "outboundTag": tag,
        })
    old_routing[:0] = add_rules
    block_rules = [rule for rule in old_routing if rule.get("outboundTag") == "block"
                   and not any(key in rule for key in ("inboundTag", "user"))]
    gateway = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": GATEWAY_PORT, "protocol": "vless",
            "tag": "lastos-limits-egress",
            "settings": {"clients": [{"id": local_id}], "decryption": "none"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom"},
                      {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPOnDemand", "rules": block_rules},
    }
    return as_json(config), as_json(gateway), as_json(applied)


def active():
    return subprocess.run(("systemctl", "is-active", "--quiet", SERVICE)).returncode == 0


def local_ports():
    with open("/proc/net/tcp", encoding="ascii") as table:
        return {int(fields[1].split(":")[1], 16) for row in table.readlines()[1:]
                if (fields := row.split())[3] == "0A"}


def reserved_ports(limits):
    return {GATEWAY_PORT, *(item["port"] for item in limits.values())} if limits else set()


def ready_settings(expected):
    run("systemctl", "is-active", "--quiet", SERVICE)
    if not reserved_ports(expected) <= local_ports():
        raise ValueError("Локальный ограничитель не открыл все слушатели")


def set_limit(name, quota, mbps):
    quota, mbps = int(quota), int(mbps)
    if not NICK.fullmatch(name) or not 0 <= quota <= 1_000_000 or not 0 <= mbps <= 10000:
        raise ValueError("Лимиты: 0–1000000 ГиБ и 0–10000 Мбит/с. Ноль означает безлимит.")
    config = json.loads(CONFIG.read_text())
    if name not in {client.get("email") for client in config["inbounds"][0]["settings"]["clients"]}:
        raise ValueError("Ник не найден в VLESS Direct")
    limits = world()
    was_active = active()
    existing_ports = reserved_ports(limits) if was_active else set()
    if not quota and not mbps:
        if name not in limits:
            report(name)
            return
        del limits[name]
    else:
        assigned = limits.get(name)
        if assigned:
            port = assigned["port"]
        else:
            used = {item["port"] for item in limits.values()}
            port = next((port for port in range(PORT_BASE, PORT_BASE + 1000) if port not in used), None)
            if port is None:
                raise ValueError("Нет свободных внутренних портов для нового лимита")
        limits[name] = {"quota": quota * 1024**3, "mbps": mbps, "port": port}
    if not UNIT.exists():
        raise ValueError("Сначала установи компонент лимитов: lastos-limits install")

    main, gateway, applied = compile_configs(config, limits)
    checked_config(main)
    if limits:
        checked_config(gateway)
    before = {path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
              for path in (CONFIG, SETTINGS, GATEWAY)}
    if (reserved_ports(json.loads(applied)) - existing_ports) & local_ports():
        raise ValueError("Один из внутренних портов ограничителя уже занят")
    restarted_xray = False
    try:
        write(SETTINGS, applied)
        write(GATEWAY, gateway)
        if limits:
            run("systemctl", "enable", SERVICE)
            run("systemctl", "restart", SERVICE)
            for _ in range(30):
                try:
                    ready_settings(json.loads(applied))
                    break
                except (subprocess.CalledProcessError, ValueError):
                    time.sleep(0.1)
            else:
                raise ValueError("Локальный ограничитель не готов")
        write(CONFIG, main, before[CONFIG][1])
        restarted_xray = True
        run("systemctl", "restart", "xray")
        run("systemctl", "is-active", "--quiet", "xray")
        if not limits and was_active:
            run("systemctl", "disable", "--now", SERVICE)
    except BaseException:
        for path, old in before.items():
            if old is None:
                path.unlink(missing_ok=True)
            else:
                write(path, *old)
        subprocess.run(("systemctl", "restart", SERVICE) if was_active
                       else ("systemctl", "disable", "--now", SERVICE), check=False)
        if restarted_xray:
            subprocess.run(("systemctl", "restart", "xray"), check=False)
        raise
    report(name)


def report(name):
    limit = world().get(name, {})
    quota = limit.get("quota", 0)
    rate = limit.get("mbps", 0)
    print(f"Ник: {name}")
    print(f"Квота скачивания: {quota // 1024**3} ГиБ" if quota else "Квота: безлимит")
    print(f"Скорость скачивания: {rate} Мбит/с" if rate else "Скорость: безлимит")
    print(f"Учтено скачивания: {saved_bytes(name) / 1024**3:.3f} ГиБ")


class Meter:
    def __init__(self, name, settings, db):
        self.name = name
        self.quota = settings["quota"]
        self.rate = settings["mbps"] * 1_000_000 / 8
        self.db = db
        row = db.execute("SELECT bytes FROM usage WHERE nick = ?", (name,)).fetchone()
        self.used = row[0] if row else 0
        self.lock = asyncio.Lock()

    async def download(self, reader, writer):
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            async with self.lock:
                if self.quota:
                    chunk = chunk[:max(0, self.quota - self.used)]
                if not chunk:
                    return
                if self.rate:
                    await asyncio.sleep(len(chunk) / self.rate)
                self.used += len(chunk)
                self.db.execute(
                    "INSERT INTO usage VALUES (?, ?) ON CONFLICT(nick) DO UPDATE SET bytes=excluded.bytes",
                    (self.name, self.used),
                )
                self.db.commit()
                writer.write(chunk)
            await writer.drain()
            if self.quota and self.used >= self.quota:
                return

    async def connection(self, reader, writer):
        remote_writer = None
        tasks = []
        try:
            if self.quota and self.used >= self.quota:
                return
            remote_reader, remote_writer = await asyncio.open_connection("127.0.0.1", GATEWAY_PORT)
            tasks = [
                asyncio.create_task(self.download(remote_reader, writer)),
                asyncio.create_task(copy_upload(reader, remote_writer)),
            ]
            # A client may finish sending before the remote finishes replying.
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            if tasks[0] not in done:
                await tasks[0]
        except (ConnectionError, OSError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            for stream in (remote_writer, writer):
                if stream:
                    stream.close()
            await asyncio.gather(*tasks, return_exceptions=True)


async def copy_upload(reader, writer):
    while chunk := await reader.read(65536):
        writer.write(chunk)
        await writer.drain()
    writer.write_eof()


async def serve():
    folder = Path(os.environ["CREDENTIALS_DIRECTORY"])
    limits = json.loads((folder / "settings.json").read_text())
    db_path = Path(os.environ["STATE_DIRECTORY"]) / "usage.db"
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS usage (nick TEXT PRIMARY KEY, bytes INTEGER NOT NULL)")
        gateway = await asyncio.create_subprocess_exec(XRAY, "run", "-c", str(folder / "egress.json"))
        listeners = []
        try:
            for name, item in limits.items():
                meter = Meter(name, item, db)
                listeners.append(await asyncio.start_server(meter.connection, "127.0.0.1", item["port"]))
            status = await gateway.wait()
            raise RuntimeError(f"Внутренний Xray завершился с кодом {status}")
        finally:
            for listener in listeners:
                listener.close()
                await listener.wait_closed()
            if gateway.returncode is None:
                gateway.terminate()
                await gateway.wait()


def main():
    arguments = sys.argv[1:]
    if arguments == ["serve"]:
        asyncio.run(serve())
    elif os.geteuid():
        sys.exit("Запусти lastos-limits от root")
    elif arguments == ["install"]:
        install()
    elif len(arguments) == 2 and arguments[0] == "show":
        report(arguments[1])
    elif len(arguments) == 4 and arguments[0] == "set":
        with open("/run/lock/lastos-admin.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            set_limit(*arguments[1:])
    else:
        sys.exit("Использование: lastos-limits show НИК | set НИК ГиБ Мбит/с")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.CalledProcessError) as error:
        sys.exit(f"Ошибка лимитов LastOS: {error}")
