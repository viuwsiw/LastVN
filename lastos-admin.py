#!/usr/bin/env python3
"""Administrative actions for LastOS on a LastVN VPS."""

import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import uuid

XRAY = Path("/usr/local/etc/xray/config.json")
TOKENS = XRAY.with_name("lastvn.tokens")
STATE = XRAY.with_name("lastvn.env")
WEB = Path("/var/www/lastvn")
WS_CONFIG = Path("/etc/lastvn-ws/config.json")
WS_PROFILE = WS_CONFIG.with_name("profile.tsv")
NGINX = Path("/etc/nginx/conf.d")
SUB_NGINX = NGINX / "lastvn.conf"
WS_NGINX = NGINX / "lastvn-ws.conf"
HTTP_NGINX = NGINX / "lastvn-http.conf"
UA_MAP = Path("/etc/nginx/lastos-users.map")
UA_LOG = Path("/var/log/nginx/lastos-subscriptions.log")
VNC_PROFILE = Path("/etc/profile.d/lastos-vnc.sh")
LEGACY_UNITS = ("mtproxy-2053.service", "mtg.service")
LEGACY_FILES = (
    Path("/etc/systemd/system/mtproxy-2053.service"),
    Path("/etc/systemd/system/mtg.service"),
    Path("/etc/mtg.toml"),
    Path("/usr/local/bin/mtg"),
    Path("/opt/mtproxy-2053/objs/bin/mtproto-proxy"),
)
LASTVN = "/usr/local/sbin/lastvn"
XRAY_BIN = "/usr/local/bin/xray"
MESSAGE = "бро, купи у тохи впн. не парься"
NICK = re.compile(r"[A-Za-z0-9_.-]{1,64}")
TOKEN = re.compile(r"[0-9a-f]{32}")


def log_directive():
    return f"access_log {UA_LOG} lastos_subscription if=$lastos_log_subscription;"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def atomic_write(path, content, mode=None):
    if isinstance(content, str):
        content = content.encode()
    if mode is None:
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def records():
    result = {}
    for line in TOKENS.read_text().splitlines():
        if not line.strip():
            continue
        name, token = line.split()
        if not NICK.fullmatch(name) or not TOKEN.fullmatch(token) or name in result:
            raise ValueError("Некорректный ник или токен в lastvn.tokens")
        result[name] = token
    return result


def write_nick_map(users):
    lines = [
        f'"/sub/{token}{suffix}" "{name}";\n'
        for name, token in users.items()
        for suffix in ("", "-split")
    ]
    atomic_write(UA_MAP, "".join(lines), 0o600)


def reload_nginx():
    run("nginx", "-t")
    run("systemctl", "reload", "nginx")


def root_response():
    return f'    location = / {{ default_type text/plain; charset utf-8; return 200 "{MESSAGE}"; }}'


def add_root_response(config):
    if MESSAGE in config:
        return config
    marker = "    location / {"
    if config.count(marker) != 1:
        raise ValueError("Не найдено однозначное место для главной страницы nginx")
    return config.replace(marker, root_response() + "\n" + marker, 1)


def restore_files(files):
    for path, content in files.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            atomic_write(path, content)


def snapshot(paths):
    return {path: path.read_bytes() if path.exists() else None for path in paths}


def install():
    users = records()
    config = SUB_NGINX.read_text()
    marker = "    location /sub/ {"
    if config.count(marker) != 1:
        raise ValueError("Не найден блок подписок LastVN в nginx")
    if log_directive() not in config:
        config = config.replace(marker, marker + "\n        " + log_directive(), 1)
    # Старые URLs диагностики включали токен первого пользователя.
    config = re.sub(r"(?m)^    location /logs/ \{[^\n]*\}$",
                    "    location /logs/ { return 404; }", config)
    changes = {
        SUB_NGINX: config,
        NGINX / "00-lastos-ua.conf": (
            'map $uri $lastos_nick {\n'
            '    default "-";\n'
            f'    include {UA_MAP};\n'
            '}\n'
            'map $status $lastos_log_subscription { default 0; 200 1; 304 1; }\n'
            "log_format lastos_subscription escape=json "
            "'{\"time\":\"$time_iso8601\",\"nick\":\"$lastos_nick\",\"ua\":\"$http_user_agent\"}';\n"
        ),
        WEB / "index.html": (
            '<!doctype html><html lang="ru"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>LastVN</title><p>{MESSAGE}</p></html>\n'
        ),
    }
    if HTTP_NGINX.exists():
        changes[HTTP_NGINX] = add_root_response(HTTP_NGINX.read_text())
    if WS_NGINX.exists():
        config = add_root_response(WS_NGINX.read_text())
        marker = "    location ^~ /sub/ {"
        if marker not in config:
            route = (
                f"{marker}\n"
                f"        root {WEB};\n"
                "        default_type text/plain;\n"
                "        add_header Cache-Control no-store always;\n"
                f"        {log_directive()}\n"
                "        try_files $uri =404;\n"
                "    }\n"
            )
            config = config.replace("    location / {", route + "    location / {", 1)
        changes[WS_NGINX] = config

    UA_LOG.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(UA_LOG, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    previous = snapshot([*changes, UA_MAP])
    try:
        write_nick_map(users)
        for path, content in changes.items():
            atomic_write(path, content, 0o644)
        reload_nginx()
    except BaseException:
        restore_files(previous)
        reload_nginx()
        raise

    atomic_write(VNC_PROFILE, """# LastOS on authenticated virtual consoles.
if [ "$(id -u)" = 0 ] && [ -t 0 ] && [ -t 1 ] && [ -x /usr/local/sbin/lastos ]; then
    case "$(tty 2>/dev/null)" in
        /dev/tty[0-9]*) /usr/local/sbin/lastos ;;
    esac
fi
""", 0o644)
    print("LastOS настроен. Для запуска сейчас введи lastos.")


def service_active(unit):
    return subprocess.run(("systemctl", "is-active", "--quiet", unit), check=False).returncode == 0


def show_link(name):
    if name not in records():
        raise ValueError("Ник не найден")
    output = run(LASTVN, "link", name, stdout=subprocess.PIPE).stdout
    for line in output.splitlines():
        if line.strip().startswith("vless://"):
            print(line.strip())
    if WS_PROFILE.exists() and WS_NGINX.exists() and log_directive() in WS_NGINX.read_text():
        host, port, *_ = WS_PROFILE.read_text().strip().split("\t")
        print(f"https://{host}:{port}/sub/{records()[name]}")


def create_user(name):
    run(LASTVN, "add", name, stdout=subprocess.DEVNULL)
    if UA_MAP.exists():
        write_nick_map(records())
        reload_nginx()
    show_link(name)


def ws_link():
    from urllib.parse import quote
    domain, port, secret, path = WS_PROFILE.read_text().strip().split("\t")
    print(f"vless://{secret}@{domain}:{port}?encryption=none&security=tls"
          f"&sni={domain}&type=ws&host={domain}&path={quote(path, safe='')}#LastVN-WS")


def retire_unused_ingress(config):
    if not WS_PROFILE.exists() or not WS_NGINX.exists() or log_directive() not in WS_NGINX.read_text():
        raise ValueError("Сначала настрой HTTPS-подписки командой lastos-admin install")
    changed = {}
    config["inbounds"] = [
        inbound for inbound in config["inbounds"]
        if inbound.get("tag") not in {"split-front", "split-xhttp", "lab", "lab2"}
    ]
    state = STATE.read_text()
    changed[STATE] = re.sub(
        r"(?m)^(?:SPLIT_[A-Z_]+|LAB2?_[A-Z_]+)=.*\n?", "", state
    )
    sub_port = re.search(r"(?m)^SUB_PORT=([0-9]+)$", state)
    if not sub_port:
        raise ValueError("Не найден порт подписок LastVN")
    port = sub_port.group(1)
    source = SUB_NGINX.read_text()
    source, count = re.subn(rf"(?m)^(\s*listen )({port}|\[::\]:{port});$",
                            lambda match: match[1] + (
                                f"[::1]:{port};" if match[2].startswith("[") else f"127.0.0.1:{port};"
                            ), source)
    if not count and f"listen 127.0.0.1:{port};" not in source:
        raise ValueError("Не найдены слушатели HTTP-подписок в nginx")
    changed[SUB_NGINX] = source
    for path in (WS_NGINX, HTTP_NGINX):
        if path.exists():
            source = path.read_text()
            source = re.sub(r"(?m)^\s*include /etc/nginx/lastvn-split-tls\.inc;\n", "", source)
            source = re.sub(
                r"(?m)^    location \^~ /[^\s]+ \{\n"
                r"(?=[ \t]*proxy_pass http://127\.0\.0\.1:10000;)[^}]*\}\n",
                "", source,
            )
            changed[path] = source
    return changed


def rotate():
    original = json.loads(XRAY.read_text())
    users = records()
    changed = retire_unused_ingress(original)
    new_ids = {}
    for inbound in original["inbounds"]:
        if inbound["protocol"] != "vless":
            continue
        for client in inbound.get("settings", {}).get("clients", []):
            current_id = client["id"]
            if current_id not in new_ids:
                new_ids[current_id] = str(uuid.uuid4())
            client["id"] = new_ids[current_id]
    if not new_ids or not users:
        raise ValueError("Нет ключей VLESS для замены")
    rotated_tokens = {name: secrets.token_hex(16) for name in users}
    changed.update({
        XRAY: json.dumps(original, ensure_ascii=False, indent=2) + "\n",
        TOKENS: "".join(f"{name} {token}\n" for name, token in rotated_tokens.items()),
    })
    if WS_CONFIG.exists():
        web_socket = json.loads(WS_CONFIG.read_text())
        domain, port, previous_id, path = WS_PROFILE.read_text().strip().split("\t")
        ws_ids = {}
        for inbound in web_socket["inbounds"]:
            if inbound["protocol"] == "vless":
                for client in inbound["settings"]["clients"]:
                    current_id = client["id"]
                    if current_id not in ws_ids:
                        ws_ids[current_id] = str(uuid.uuid4())
                    client["id"] = ws_ids[current_id]
        changed[WS_CONFIG] = json.dumps(web_socket, ensure_ascii=False, indent=2) + "\n"
        changed[WS_PROFILE] = f"{domain}\t{port}\t{ws_ids[previous_id]}\t{path}\n"

    units = ["xray"]
    if WS_CONFIG in changed and service_active("lastvn-ws"):
        units.append("lastvn-ws")
    legacy_running = [unit for unit in LEGACY_UNITS if service_active(unit)]
    before = snapshot([*changed, UA_MAP])
    sub = WEB / "sub"
    with tempfile.TemporaryDirectory(prefix=".lastos-", dir=WEB.parent) as directory:
        stage = Path(directory)
        for path, data in changed.items():
            staged = stage / ("ws.json" if path == WS_CONFIG else path.name)
            atomic_write(staged, data, 0o600)
            if path in (XRAY, WS_CONFIG):
                run(XRAY_BIN, "run", "-test", "-c", str(staged))
        render = r'''
source <(sed '/^case \${1:-} in$/,$d' /usr/local/sbin/lastvn)
CONFIG="$1/config.json"
TOKENS="$1/lastvn.tokens"
STATE="$1/lastvn.env"
WEB="$1/web"
rebuild_subs
'''
        run("bash", "-c", render, "lastos-render", str(stage))
        staged_sub = stage / "web" / "sub"
        saved_sub = stage / "old-sub"
        if not staged_sub.is_dir() or not all((staged_sub / token).is_file() for token in rotated_tokens.values()):
            raise ValueError("Не удалось подготовить новые подписки")
        try:
            for path, data in changed.items():
                atomic_write(path, data)
            sub.rename(saved_sub)
            staged_sub.rename(sub)
            if UA_MAP.exists():
                write_nick_map(rotated_tokens)
                reload_nginx()
            for service in units:
                run("systemctl", "restart", service)
                run("systemctl", "is-active", "--quiet", service)
            for service in LEGACY_UNITS:
                check = subprocess.run(("systemctl", "show", "-P", "LoadState", service),
                                       check=False, capture_output=True, text=True)
                if check.stdout.strip() == "loaded":
                    run("systemctl", "disable", "--now", service)
        except BaseException:
            restore_files(before)
            if saved_sub.exists():
                if sub.exists():
                    sub.rename(staged_sub)
                saved_sub.rename(sub)
            if UA_MAP.exists():
                reload_nginx()
            for service in units:
                subprocess.run(("systemctl", "restart", service), check=False)
            for service in legacy_running:
                subprocess.run(("systemctl", "enable", "--now", service), check=False)
            raise
    print(f"Заменено ключей Xray: {len(new_ids)}. Новых подписок: {len(users)}.")
    for path in LEGACY_FILES:
        path.unlink(missing_ok=True)
    run("systemctl", "daemon-reload")
    print("Telegram-прокси удалены, split отключён. HTTP-подписки слушают только localhost.")
    if WS_CONFIG in changed:
        print("Ключ WebSocket тоже заменён. Получить его: lastos-admin ws-link")


def observed_agents():
    if not UA_LOG.exists():
        print("Журнал пока пуст.")
        return
    lines = run("tail", "-n", "60", str(UA_LOG), stdout=subprocess.PIPE).stdout
    for line in lines.splitlines():
        try:
            item = json.loads(line)
            print(f'{item["time"]}  {item["nick"]}  {item["ua"]}')
        except (ValueError, KeyError):
            continue


def main():
    if os.geteuid() != 0:
        sys.exit("Запусти lastos-admin от root.")
    args = sys.argv[1:]
    if args and args[0] in ("add", "link"):
        if len(args) != 2 or not NICK.fullmatch(args[1]):
            sys.exit("Ник: 1–64 символа из A–Z, a–z, 0–9, _ . -")
    with open("/run/lock/lastos-admin.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args == ["install"]:
            install()
        elif args == ["users"]:
            print("\n".join(records()))
        elif args == ["agents"]:
            observed_agents()
        elif args == ["ws-link"]:
            ws_link()
        elif args == ["rotate", "--confirm"]:
            rotate()
        elif args and args[0] == "add":
            create_user(args[1])
        elif args and args[0] == "link":
            show_link(args[1])
        else:
            sys.exit("Команды: install, users, add НИК, link НИК, ws-link, agents, rotate --confirm")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"Ошибка LastOS: {error}")
