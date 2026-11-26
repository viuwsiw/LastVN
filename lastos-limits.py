#!/usr/bin/env python3
"""Per-nickname download limits for LastOS's VLESS Direct service."""

import asyncio
import fcntl
import json
import os
from pathlib import Path
import re
import socket
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
LIVE = Path("/etc/lastos-limits-live")
CONTROL = Path("/run/lastos-limits/control.sock")
PREFIX = "lastos-limit-"
GATEWAY_PORT = 16099
PORT_BASE = 16100
NICK = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def run(*args):
    subprocess.run(args, check=True)


def world():
    return json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {}


def open_db(path, *, uri=False):
    db = sqlite3.connect(path, uri=uri)
    db.execute("PRAGMA trusted_schema=OFF")
    return db


def validate_nick(name):
    if not NICK.fullmatch(name):
        raise ValueError("Некорректный ник")


def saved_bytes(name):
    if not DB.exists():
        return 0
    with open_db(f"file:{DB}?mode=ro", uri=True) as db:
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
RuntimeDirectory=lastos-limits
RuntimeDirectoryMode=0700
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


def compile_configs(config, limits, local_id=None):
    current_inbound = config["inbounds"][0]
    profile_inbounds = [item["tag"] for item in config["inbounds"] if item.get("tag") in {
        current_inbound["tag"], "lastvn-tcp", "lastvn-tls-ws", "lastvn-tls-grpc", "lastvn-hysteria",
    }]
    old_routing = config.setdefault("routing", {}).setdefault("rules", [])
    old_routing[:] = [
        rule for rule in old_routing if not rule.get("outboundTag", "").startswith(PREFIX)
    ]
    outbounds = config["outbounds"]
    outbounds[:] = [item for item in outbounds if not item.get("tag", "").startswith(PREFIX)]
    local_id = local_id or str(uuid.uuid4())
    add_rules = []
    for name, item in limits.items():
        tag = PREFIX + name
        outbounds.append({
            "tag": tag, "protocol": "vless",
            "settings": {"vnext": [{
                "address": "127.0.0.1", "port": item["port"],
                "users": [{"id": local_id, "encryption": "none"}],
            }]},
        })
        add_rules.append({
            "type": "field", "user": [name], "inboundTag": profile_inbounds,
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
    return as_json(config), as_json(gateway), as_json(limits)


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
    if not CONTROL.exists() or not reserved_ports(expected) <= local_ports():
        raise ValueError("Локальный ограничитель не открыл все слушатели")


def next_port(limits):
    used = {item["port"] for item in limits.values()} | local_ports()
    port = next((port for port in range(PORT_BASE, PORT_BASE + 1000) if port not in used), None)
    if port is None:
        raise ValueError("Нет свободных внутренних портов для нового пользователя")
    return port


def prepare():
    config = json.loads(CONFIG.read_text())
    limits = world()
    clients = config["inbounds"][0]["settings"]["clients"]
    enrolled = {client["email"] for client in clients if client.get("email")}
    if len(enrolled) != len(clients):
        raise ValueError("Для учёта нужны уникальные ники у всех пользователей")
    for name in enrolled:
        validate_nick(name)
        if name not in limits:
            limits[name] = {"quota": 0, "mbps": 0, "port": next_port(limits)}
        limits[name]["blocked"] = False
    for name in set(limits) - enrolled:
        limits[name]["blocked"] = True
    if not limits:
        raise ValueError("Сначала создай пользователя VLESS Direct")
    routes = {rule.get("outboundTag") for rule in config.get("routing", {}).get("rules", [])}
    if LIVE.exists() and CONTROL.exists() and active() and all(
        PREFIX + name in routes for name in enrolled
    ):
        save_live(limits)
        print("Режим реального времени уже включён.")
        return
    deploy_runtime(config, limits)
    write(LIVE, b"1\n")
    print("Режим реального времени включён.")


def deploy_runtime(config, limits):
    if not UNIT.exists():
        raise ValueError("Сначала установи компонент лимитов: lastos-limits install")

    was_active = active()
    existing_ports = reserved_ports(world()) if was_active else set()
    main, gateway, applied = compile_configs(config, limits)
    checked_config(main)
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



def push_settings(limits):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as pipe:
        pipe.settimeout(12)
        pipe.connect(str(CONTROL))
        pipe.sendall(as_json(limits) + b"\x00")
        pipe.shutdown(socket.SHUT_WR)
        with pipe.makefile("rb") as response:
            status = response.readline().decode(errors="replace").strip()
        if status != "OK":
            raise ValueError(status or "Нет ответа от ограничителя")


def save_live(limits):
    if not LIVE.exists():
        raise ValueError("Сначала включи режим реального времени: lastos-limits prepare")
    undo = SETTINGS.read_bytes()
    write(SETTINGS, as_json(limits))
    try:
        push_settings(limits)
    except BaseException:
        write(SETTINGS, undo)
        try:
            push_settings(json.loads(undo))
        except (OSError, ValueError):
            pass
        raise


def set_limit(name, quota, mbps):
    validate_nick(name)
    quota, mbps = int(quota), int(mbps)
    if not 0 <= quota <= 1_000_000 or not 0 <= mbps <= 10000:
        raise ValueError("Лимиты: 0–1000000 ГиБ и 0–10000 Мбит/с. Ноль означает безлимит.")
    limits = world()
    if name not in limits or limits[name].get("blocked"):
        raise ValueError("Ник не активирован в режиме реального времени")
    limits[name].update(quota=quota * 1024**3, mbps=mbps)
    save_live(limits)
    report(name)


def block_user(name, blocked):
    limits = world()
    if name not in limits:
        raise ValueError("Ник не активирован в режиме реального времени")
    limits[name]["blocked"] = blocked
    save_live(limits)


def enroll(name):
    if not LIVE.exists():
        return
    limits = world()
    if name not in limits:
        limits[name] = {"quota": 0, "mbps": 0, "port": next_port(limits), "blocked": True}
    gateway = json.loads(GATEWAY.read_text())
    key = gateway["inbounds"][0]["settings"]["clients"][0]["id"]
    config = json.loads(CONFIG.read_text())
    main, _, _ = compile_configs(config, limits, key)
    checked_config(main)
    previous = CONFIG.read_bytes()
    mode = CONFIG.stat().st_mode & 0o777
    write(CONFIG, main, mode)
    try:
        save_live(limits)
    except BaseException:
        write(CONFIG, previous, mode)
        raise

def report(name):
    limit = world().get(name, {})
    quota = limit.get("quota", 0)
    rate = limit.get("mbps", 0)
    print(f"Ник: {name}")
    print(f"Квота скачивания: {quota // 1024**3} ГиБ" if quota else "Квота: безлимит")
    print(f"Скорость скачивания: {rate} Мбит/с" if rate else "Скорость: безлимит")
    print(f"Учтено скачивания: {saved_bytes(name) / 1024**3:.3f} ГиБ")


def forget_deleted(name):
    validate_nick(name)
    config = json.loads(CONFIG.read_text())
    if any(client.get("email") == name for inbound in config["inbounds"]
           for client in inbound.get("settings", {}).get("clients", [])):
        raise ValueError("Сначала удали пользователя из Xray")
    limits = world()
    if name in limits and LIVE.exists():
        # The live Xray may still refer to this port. Never reuse it before a restart.
        limits[name].update(quota=0, mbps=0, blocked=True, reset_usage=True)
        save_live(limits)
        limits[name].pop("reset_usage")
        write(SETTINGS, as_json(limits))
    else:
        if name in limits:
            del limits[name]
            write(SETTINGS, as_json(limits))
            if active():
                if limits:
                    run("systemctl", "restart", SERVICE)
                else:
                    run("systemctl", "disable", "--now", SERVICE)
    if DB.exists() and (not LIVE.exists() or name not in limits):
        with open_db(DB) as db:
            db.execute("DELETE FROM usage WHERE nick = ?", (name,))


class Meter:
    def __init__(self, name, settings, db):
        self.name = name
        self.connections = set()
        self.policy_changed = asyncio.Event()
        self.db = db
        row = db.execute("SELECT bytes FROM usage WHERE nick = ?", (name,)).fetchone()
        self.used = row[0] if row else 0
        self.saved = self.used
        self.lock = asyncio.Lock()
        self.apply(settings)

    def apply(self, settings):
        self.quota = settings["quota"]
        self.rate = settings["mbps"] * 1_000_000 / 8
        self.blocked = settings.get("blocked", False)
        self.policy_changed.set()
        if self.blocked:
            for task in self.connections:
                task.cancel()
        if settings.get("reset_usage"):
            self.used = self.saved = 0
            self.db.execute("DELETE FROM usage WHERE nick = ?", (self.name,))
            self.db.commit()

    def flush(self):
        if self.used != self.saved:
            self.db.execute(
                "INSERT INTO usage VALUES (?, ?) ON CONFLICT(nick) DO UPDATE SET bytes=excluded.bytes",
                (self.name, self.used),
            )
            self.db.commit()
            self.saved = self.used

    async def download(self, reader, writer):
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                return
            async with self.lock:
                while True:
                    if self.quota:
                        allowed = chunk[:max(0, self.quota - self.used)]
                    else:
                        allowed = chunk
                    if not allowed or self.blocked:
                        return
                    if not self.rate:
                        break
                    self.policy_changed.clear()
                    try:
                        await asyncio.wait_for(self.policy_changed.wait(), len(allowed) / self.rate)
                    except asyncio.TimeoutError:
                        break
                chunk = allowed
                self.used += len(chunk)
                if self.quota or self.used - self.saved >= 1024**2:
                    self.flush()
                writer.write(chunk)
            await writer.drain()
            if self.quota and self.used >= self.quota:
                return

    async def connection(self, reader, writer):
        remote_writer = None
        tasks = []
        task = asyncio.current_task()
        self.connections.add(task)
        try:
            if self.blocked or (self.quota and self.used >= self.quota):
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
            self.connections.discard(task)
            for pipe in tasks:
                pipe.cancel()
            for stream in (remote_writer, writer):
                if stream:
                    stream.close()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.flush()


async def copy_upload(reader, writer):
    while chunk := await reader.read(65536):
        writer.write(chunk)
        await writer.drain()
    writer.write_eof()


async def serve():
    folder = Path(os.environ["CREDENTIALS_DIRECTORY"])
    limits = json.loads((folder / "settings.json").read_text())
    db_path = Path(os.environ["STATE_DIRECTORY"]) / "usage.db"
    control_path = Path(os.environ["RUNTIME_DIRECTORY"]) / "control.sock"
    with open_db(db_path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("CREATE TABLE IF NOT EXISTS usage (nick TEXT PRIMARY KEY, bytes INTEGER NOT NULL)")
        gateway = await asyncio.create_subprocess_exec(XRAY, "run", "-c", str(folder / "egress.json"))
        listeners = {}

        async def reconcile(updated):
            new = {}
            try:
                for name, settings in updated.items():
                    validate_nick(name)
                    if name in listeners:
                        if settings["port"] != listeners[name][2]:
                            raise ValueError("Нельзя изменить активный внутренний порт")
                        continue
                    meter = Meter(name, settings, db)
                    listener = await asyncio.start_server(meter.connection, "127.0.0.1", settings["port"])
                    new[name] = (listener, meter, settings["port"])
            except BaseException:
                for listener, _, _ in new.values():
                    listener.close()
                    await listener.wait_closed()
                raise
            listeners.update(new)
            for name, (_, meter, _) in listeners.items():
                meter.apply(updated.get(name, {"quota": 0, "mbps": 0, "blocked": True}))

        async def control(reader, writer):
            try:
                raw = await asyncio.wait_for(reader.readuntil(b"\x00"), 10)
                async with lock:
                    await reconcile(json.loads(raw[:-1]))
                writer.write(b"OK\n")
            except (OSError, ValueError, KeyError, asyncio.LimitOverrunError,
                    asyncio.IncompleteReadError, TimeoutError) as error:
                writer.write((str(error) + "\n").encode())
            finally:
                try:
                    await writer.drain()
                finally:
                    writer.close()

        lock = asyncio.Lock()
        server = None
        try:
            await reconcile(limits)
            control_path.unlink(missing_ok=True)
            server = await asyncio.start_unix_server(control, str(control_path), limit=200000)
            status = await gateway.wait()
            raise RuntimeError(f"Внутренний Xray завершился с кодом {status}")
        finally:
            if server:
                server.close()
                await server.wait_closed()
            for listener, _, _ in listeners.values():
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
    elif arguments == ["prepare"]:
        with open("/run/lock/lastos-admin.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            prepare()
    elif len(arguments) == 2 and arguments[0] == "show":
        validate_nick(arguments[1])
        report(arguments[1])
    elif len(arguments) == 2 and arguments[0] in ("block", "unblock", "enroll"):
        validate_nick(arguments[1])
        if arguments[0] == "enroll":
            enroll(arguments[1])
        else:
            block_user(arguments[1], arguments[0] == "block")
    elif len(arguments) == 2 and arguments[0] == "forget-deleted":
        forget_deleted(arguments[1])
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
