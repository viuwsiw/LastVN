# LastVN

Установщик своего VPN на **VLESS + XHTTP + Reality** (Xray-core) для VPS.

- **Домен не нужен.** Reality выдаёт себя за TLS-соединение к настоящему сайту (по умолчанию `www.microsoft.com`), сертификат не требуется.
- **XHTTP** — новый транспорт Xray, пришёл на смену WebSocket: обычные HTTP-запросы, сложнее распознать по DPI.
- Ссылка `vless://` и QR-код для клиента, добавление и удаление пользователей, BBR.

## Установка на сервер

Подключаемся к серверу (Ubuntu/Debian, root):

```bash
ssh root@IP_СЕРВЕРА
```

Скачиваем и запускаем:

```bash
curl -fsSL -o lastvn.sh https://raw.githubusercontent.com/viuwsiw/LastVN/main/lastvn.sh && sudo bash lastvn.sh install
```

В конце будет ссылка `vless://...` и QR-код. Импортируй её в клиент.

Параметры (необязательные):

```bash
sudo bash lastvn.sh install --port 443 --sni www.microsoft.com --name phone
```

## Управление

| Команда | Что делает |
|---|---|
| `lastvn.sh add <имя>` | новый пользователь, выводит ссылку и QR |
| `lastvn.sh del <имя>` | удалить пользователя |
| `lastvn.sh list` | список пользователей |
| `lastvn.sh link <имя>` | снова показать ссылку и QR |
| `lastvn.sh status` | статус сервиса |
| `lastvn.sh uninstall` | удалить всё |

## Клиенты (с поддержкой XHTTP)

- **Android:** v2rayNG, Hiddify
- **iOS / macOS:** v2RayTun, Streisand, Hiddify
- **Windows / Linux:** v2rayN, Hiddify, Nekoray (с ядром Xray)

Клиент должен работать на свежем Xray-core: на старых версиях нет транспорта XHTTP.

## Где что лежит на сервере

- `/usr/local/etc/xray/config.json` — конфиг Xray
- `/usr/local/etc/xray/lastvn.env` — параметры сервера (IP, публичный ключ, SNI, path)
- логи: `journalctl -u xray -f`
