#!/usr/bin/env python3
"""LastOS console for the VPS hosting LastVN."""

import curses
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time


SERVICES = (
    ("LastVN Direct", "xray.service"),
    ("LastVN WebSocket", "lastvn-ws.service"),
    ("Nginx", "nginx.service"),
    ("LastVN Monitor", "lastvn-monitor.service"),
)
STATUS_LABELS = {
    "active": "Работает",
    "inactive": "Остановлен",
    "activating": "Запускается",
    "deactivating": "Останавливается",
    "failed": "Ошибка",
    "not-found": "Не установлен",
}
ADMIN = "/usr/local/sbin/lastos-admin"
LIMITS = "/usr/local/sbin/lastos-limits"


def command(*args, timeout=4):
    try:
        result = subprocess.run(
            args, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, check=False,
        )
        return result.returncode, result.stdout.rstrip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, str(error)


def read_system_file(path):
    try:
        return Path(path).read_text(encoding="ascii").strip()
    except OSError:
        return ""


def cpu_counters():
    lines = read_system_file("/proc/stat").splitlines()
    if not lines:
        return 0, 0
    values = [int(value) for value in lines[0].split()[1:9]]
    return sum(values), sum(values[3:5])


def memory_usage():
    fields = {}
    for line in read_system_file("/proc/meminfo").splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.split()
    if "MemTotal" not in fields or "MemAvailable" not in fields:
        return "—"
    total = int(fields["MemTotal"][0]) / 1024**2
    available = int(fields["MemAvailable"][0]) / 1024**2
    return f"{total - available:.1f}/{total:.1f} ГиБ"


def root_filesystem_usage():
    usage = shutil.disk_usage("/")
    return f"{usage.used / 1024**3:.1f}/{usage.total / 1024**3:.1f} ГиБ"


def service_state(unit):
    code, output = command("systemctl", "show", unit, "-p", "LoadState", "-p", "ActiveState")
    properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if properties.get("LoadState") == "not-found":
        return "not-found"
    return properties.get("ActiveState", "unknown") if code == 0 else "unknown"


class LastOS:
    def __init__(self, screen):
        self.screen = screen
        self.selection = 0
        self.updated_at = 0.0
        self.states = {}
        self.previous_cpu = cpu_counters()
        self.cpu = "—"
        self.memory = "—"
        self.disk = "—"
        self.cc = "—"
        self.message = ""
        self.colors = {}
        self.panel = "services"
        self.users = []
        self.user_scroll = 0
        self.user_selection = 0

    @property
    def current_service(self):
        return SERVICES[self.selection]

    def update(self):
        total, idle = cpu_counters()
        previous_total, previous_idle = self.previous_cpu
        if total > previous_total:
            load = 1 - (idle - previous_idle) / (total - previous_total)
            self.cpu = f"{max(0, min(100, load * 100)):.0f}%"
        self.previous_cpu = total, idle
        self.memory = memory_usage()
        self.disk = root_filesystem_usage()
        self.cc = read_system_file("/proc/sys/net/ipv4/tcp_congestion_control") or "—"
        self.states = {unit: service_state(unit) for _, unit in SERVICES}
        self.updated_at = time.monotonic()

    def put(self, row, column, value, style=0):
        height, width = self.screen.getmaxyx()
        if 0 <= row < height and 0 <= column < width - 1:
            self.screen.addnstr(row, column, value, width - column - 1, style)

    def draw_header(self, subtitle):
        self.screen.erase()
        self.put(1, 2, "LastOS", self.colors.get("title", 0) | curses.A_BOLD)
        self.put(2, 2, subtitle)

    def draw_dashboard(self):
        height, width = self.screen.getmaxyx()
        self.draw_header(f"{socket.gethostname()}  ·  {time.strftime('%H:%M:%S')}")
        if height < 18 or width < 44:
            self.put(4, 2, "Увеличь окно VNC. Q — выход.")
            self.screen.refresh()
            return
        self.put(4, 2, f"CPU {self.cpu}  ·  RAM {self.memory}")
        self.put(5, 2, f"Диск {self.disk}  ·  TCP {self.cc}")
        self.put(6, 2, "D Сервисы   U Пользователи   S Безопасность")
        if self.panel == "users":
            self.draw_users(height)
            return
        if self.panel == "security":
            self.draw_security(height)
            return
        self.put(7, 2, "СЕРВИС", curses.A_BOLD)
        self.put(7, 27, "СОСТОЯНИЕ", curses.A_BOLD)

        for index, (label, unit) in enumerate(SERVICES):
            state = self.states.get(unit, "unknown")
            selected = curses.A_REVERSE if index == self.selection else 0
            self.put(index + 8, 2, f"{'> ' if selected else '  '}{label:<23}", selected)
            self.put(index + 8, 27, STATUS_LABELS.get(state, "Неизвестно"),
                     selected | self.colors.get(state, 0))

        self.put(height - 4, 2, self.message)
        self.put(height - 3, 2, "↑↓ Выбор   Enter Статус   L Журнал")
        self.put(height - 2, 2, "P Порты   R Перезапуск   Q Выход")
        self.screen.refresh()

    def draw_users(self, height):
        self.put(8, 2, "ПОЛЬЗОВАТЕЛИ VLESS", curses.A_BOLD)
        capacity = height - 14
        if self.user_selection < self.user_scroll:
            self.user_scroll = self.user_selection
        if self.user_selection >= self.user_scroll + capacity:
            self.user_scroll = self.user_selection - capacity + 1
        for index, (name, status) in enumerate(self.users[self.user_scroll:self.user_scroll + capacity]):
            selected = index + self.user_scroll == self.user_selection
            suffix = " (ключ отозван)" if status == "revoked" else ""
            self.put(index + 10, 2, f"{'> ' if selected else '  '}{name}{suffix}",
                     curses.A_REVERSE if selected else 0)
        if not self.users:
            self.put(10, 2, "Список пуст или недоступен.")
        self.put(height - 4, 2, self.message)
        self.put(height - 3, 2, "Enter Ключ  K Отозвать/выпустить  X Удалить")
        self.put(height - 2, 2, "↑↓ Выбор  A Создать  T Лимиты  Q Выход")
        self.screen.refresh()

    def draw_security(self, height):
        self.put(8, 2, "БЕЗОПАСНОСТЬ", curses.A_BOLD)
        self.put(10, 2, "A  User-Agent запросов подписок")
        self.put(11, 2, "W  Показать ключ WebSocket")
        self.put(12, 2, "R  Заменить ключи и отключить старые входы")
        self.put(height - 4, 2, self.message)
        self.put(height - 2, 2, "Q Выход")
        self.screen.refresh()

    def prompt(self, title, label):
        self.draw_header(title)
        self.put(4, 2, label)
        self.screen.refresh()
        self.screen.timeout(-1)
        curses.echo()
        try:
            result = self.screen.getstr(6, 2, 64)
            return result.decode("utf-8", errors="replace")
        except curses.error:
            return ""
        finally:
            curses.noecho()
            self.screen.timeout(500)

    def refresh_users(self):
        code, output = command(ADMIN, "users", "detailed")
        self.users = [line.split("\t", 1) for line in output.splitlines()
                      if "\t" in line] if code == 0 else []
        self.user_selection = min(self.user_selection, max(0, len(self.users) - 1))
        self.message = output if code else ""

    def edit_limits(self, name):
        _, output = command(LIMITS, "show", name)
        self.show_output(f"Текущие лимиты · {name}", output)
        values = self.prompt(f"Лимиты скачивания · {name}",
                             "ГиБ Мбит/с (0 = безлимит, пусто = отмена)").split()
        if not values:
            return
        if len(values) != 2 or not all(value.isascii() and value.isdecimal() for value in values):
            self.message = "Введи два целых числа через пробел."
            return
        _, output = command(LIMITS, "set", name, *values, timeout=None)
        self.show_output(f"Лимиты · {name}", output)

    def admin_key(self, key):
        if self.panel == "users":
            if key == curses.KEY_UP:
                self.user_selection = max(0, self.user_selection - 1)
            elif key == curses.KEY_DOWN:
                self.user_selection = min(max(0, len(self.users) - 1), self.user_selection + 1)
            elif key in (10, 13, curses.KEY_ENTER) and self.users:
                name, status = self.users[self.user_selection]
                if status == "revoked":
                    self.message = "Ключ отозван. Нажми K, чтобы выпустить новый."
                    return
                _, output = command(ADMIN, "link", name)
                self.show_output(f"Ключ · {name}", output)
            elif key in (ord("t"), ord("T")) and self.users:
                name, status = self.users[self.user_selection]
                if status == "active":
                    self.edit_limits(name)
                else:
                    self.message = "Сначала выпусти новый ключ клавишей K."
            elif key in (ord("k"), ord("K"), ord("x"), ord("X")) and self.users:
                self.manage_credential(key)
            elif key in (ord("a"), ord("A")):
                name = self.prompt("Новый пользователь", "Ник (латиница, цифры, _ . -)")
                if name:
                    code, output = command(ADMIN, "add", name, timeout=None)
                    self.show_output("Результат создания пользователя", output)
                    self.refresh_users()
                    if code == 0:
                        self.edit_limits(name)
            return
        if key in (ord("a"), ord("A")):
            _, output = command(ADMIN, "agents")
            self.show_output("Устройства · User-Agent подписок", output)
        elif key in (ord("w"), ord("W")):
            _, output = command(ADMIN, "ws-link")
            self.show_output("Ключ WebSocket", output)
        elif key in (ord("r"), ord("R")):
            result = self.prompt("Старые ключи отзовутся, Telegram и split отключатся",
                                 "Для замены ключей и закрытия портов введи ROTATE")
            if result == "ROTATE":
                _, output = command(ADMIN, "rotate", "--confirm", timeout=None)
                self.show_output("Результат замены ключей", output)
            else:
                self.message = "Отменено."

    def manage_credential(self, key):
        name, status = self.users[self.user_selection]
        if key in (ord("x"), ord("X")):
            verb, token, prompt = "delete", "DELETE", "Удалить пользователя"
        elif status == "revoked":
            verb, token, prompt = "reissue", "ISSUE", "Выпустить новый ключ"
        else:
            verb, token, prompt = "revoke", "REVOKE", "Отозвать ключ"
        if self.prompt(f"{prompt} · {name}", f"Введи {token} для подтверждения") != token:
            self.message = "Отменено."
            return
        _, output = command(ADMIN, verb, name, timeout=None)
        self.show_output(f"{prompt} · {name}", output)
        self.refresh_users()

    def show_output(self, title, output):
        lines = [
            "".join(char for char in line.expandtabs(4) if char.isprintable())
            for line in output.splitlines()
        ] or ["Нет данных"]
        offset, column = 0, 0
        self.screen.timeout(-1)
        try:
            while True:
                height, width = self.screen.getmaxyx()
                page = max(1, height - 6)
                offset = min(offset, max(0, len(lines) - page))
                column = min(column, max(0, max(map(len, lines)) - width + 3))
                self.draw_header(title)
                for index, line in enumerate(lines[offset:offset + page]):
                    self.put(index + 4, 2, line[column:])
                self.put(height - 1, 2, f"←↑↓→ Прокрутка   Esc Назад   {offset + 1}/{len(lines)}")
                self.screen.refresh()
                key = self.screen.getch()
                if key in (27, ord("q"), ord("Q")):
                    return
                if key in (curses.KEY_DOWN, curses.KEY_NPAGE):
                    offset += page if key == curses.KEY_NPAGE else 1
                elif key in (curses.KEY_UP, curses.KEY_PPAGE):
                    offset = max(0, offset - (page if key == curses.KEY_PPAGE else 1))
                elif key == curses.KEY_RIGHT:
                    column += 16
                elif key == curses.KEY_LEFT:
                    column = max(0, column - 16)
        finally:
            self.screen.timeout(500)

    def restart_service(self):
        label, unit = self.current_service
        if os.geteuid() != 0:
            self.message = "Для перезапуска запусти LastOS от root."
            return
        if self.states.get(unit) == "not-found":
            self.message = "Сервис не установлен."
            return
        height, _ = self.screen.getmaxyx()
        self.put(height - 4, 2, f"Перезапустить {label}? Y — да, любая другая клавиша — отмена.")
        self.screen.clrtoeol()
        self.screen.refresh()
        self.screen.timeout(-1)
        try:
            confirmed = self.screen.getch() in (ord("y"), ord("Y"))
        finally:
            self.screen.timeout(500)
        if not confirmed:
            self.message = "Отменено."
            return
        code, output = command("systemctl", "restart", unit, timeout=25)
        self.update()
        if code:
            self.show_output(f"Ошибка перезапуска {label}", output)
        self.message = f"{label}: перезапуск выполнен." if code == 0 else "Ошибка перезапуска."

    def run(self):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        if curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
            self.colors = {"title": curses.color_pair(1), "active": curses.color_pair(2),
                           "failed": curses.color_pair(3)}
        self.screen.keypad(True)
        self.screen.timeout(500)
        while True:
            if time.monotonic() - self.updated_at >= 3:
                self.update()
            self.draw_dashboard()
            key = self.screen.getch()
            label, unit = self.current_service
            if key in (ord("q"), ord("Q"), 27):
                return
            height, width = self.screen.getmaxyx()
            if height < 18 or width < 44:
                continue
            if key in (ord("d"), ord("D"), ord("u"), ord("U"), ord("s"), ord("S")):
                self.panel = {"d": "services", "u": "users", "s": "security"}[chr(key).lower()]
                self.message = ""
                if self.panel == "users":
                    self.refresh_users()
                continue
            if self.panel != "services":
                self.admin_key(key)
                continue
            if key == curses.KEY_UP:
                self.selection = (self.selection - 1) % len(SERVICES)
            elif key == curses.KEY_DOWN:
                self.selection = (self.selection + 1) % len(SERVICES)
            elif key in (10, 13, curses.KEY_ENTER):
                _, output = command("systemctl", "status", unit, "--no-pager", "-l", "-n", "0")
                self.show_output(label, output)
            elif key in (ord("l"), ord("L")):
                _, output = command("journalctl", "-u", unit, "-n", "80", "--no-pager")
                self.show_output(f"Журнал · {label}", output)
            elif key in (ord("p"), ord("P")):
                _, output = command("ss", "-ltnp")
                self.show_output("Открытые TCP-порты", output)
            elif key in (ord("r"), ord("R")):
                self.restart_service()


def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        sys.exit("Запусти LastOS из интерактивной консоли VNC или SSH.")
    try:
        curses.wrapper(lambda screen: LastOS(screen).run())
    except KeyboardInterrupt:
        pass
    except curses.error as error:
        sys.exit(f"Не удалось открыть терминал: {error}")


if __name__ == "__main__":
    main()
