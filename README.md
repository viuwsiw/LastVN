# LastVN

Установщик своего VPN на **VLESS + Reality** (Xray-core) для VPS. На одном порту 443 работают два режима:

- **⚡ Быстрый — TCP + Vision.** Максимальная скорость в обе стороны, данные идут через ядро (splice), минимум нагрузки на CPU.
- **Запасной — XHTTP.** Принимается через fallback того же порта. Включай, если быстрый режим начнут резать.

- **Домен не нужен.** Reality выдаёт себя за TLS-соединение к настоящему сайту (по умолчанию `www.microsoft.com`), сертификат не требуется.
- **XHTTP** — новый транспорт Xray, пришёл на смену WebSocket: обычные HTTP-запросы, сложнее распознать по DPI.
- **Подписка** для Happ / INCY и других клиентов: в приложении профиль называется **«LastVN: первый, надежный»**, логотип `assets/logo.png` встроен в скрипт.
- Ссылка `vless://` и QR-код, добавление и удаление пользователей, BBR.

## Установка на сервер

Подключаемся к серверу (Ubuntu/Debian, root):

```bash
ssh root@IP_СЕРВЕРА
```

Скачиваем и запускаем:

```bash
curl -fsSL -o lastvn.sh https://raw.githubusercontent.com/viuwsiw/LastVN/main/lastvn.sh && sudo bash lastvn.sh install
```

Лучше ставить на **чистую** систему: если порты 443 или 2096 заняты, установщик остановится и покажет, кем именно.

В конце будет **ссылка-подписка** `http://IP:2096/sub/<токен>` и её QR-код. В Happ/INCY: «+» → добавить из буфера или сканировать QR.

Параметры (необязательные):

```bash
sudo bash lastvn.sh install --port 443 --sub-port 2096 --sni www.microsoft.com --name phone --support-url https://t.me/твой_контакт
```

## Подписка и брендинг

Подписку раздаёт nginx на порту `2096`. В ответ он добавляет заголовки, которые читают Happ, INCY, Hiddify и другие клиенты:

| Заголовок | Значение |
|---|---|
| `profile-title` | `LastVN: первый, надежный` (base64; лимит Happ — 25 символов) |
| `profile-update-interval` | 12 часов |
| `profile-web-page-url` | `http://IP:2096/` — страница с логотипом |
| `support-url` | если передан `--support-url` |

Название меняется в переменной `TITLE` в начале `lastvn.sh`.

**Про логотип.** Своя иконка провайдера в Happ и INCY подключается не через подписку, а через регистрацию провайдера в самих приложениях (Happ — provider ID, INCY — Premium API, поле `logoUrl`). Логотип уже лежит на сервере по адресу `http://IP:2096/logo.png`, эту ссылку можно указать при регистрации.

## Управление

| Команда | Что делает |
|---|---|
| `lastvn.sh add <имя>` | новый пользователь, выводит ссылку и QR |
| `lastvn.sh del <имя>` | удалить пользователя |
| `lastvn.sh list` | список пользователей |
| `lastvn.sh link <имя>` | снова показать подписку, ссылку и QR |
| `lastvn.sh status` | статус сервисов |
| `lastvn.sh upgrade` | обновить старую установку: добавить Vision, ключи и ссылки сохраняются |
| `lastvn.sh tune` | ускорение сети: BBR, TCP-буферы до 64 МБ, Fast Open |
| `lastvn.sh mtproto` | MTProto-прокси для Telegram |
| `lastvn.sh mtproto-remove` | удалить прокси для Telegram |
| `lastvn.sh uninstall` | удалить всё |

## Прокси для Telegram (MTProto)

```bash
sudo bash lastvn.sh mtproto
```

Ставит [mtg](https://github.com/9seconds/mtg) в режиме FakeTLS: для DPI трафик выглядит как HTTPS к `www.google.com`. По умолчанию работает на порту `8443` (443 занят VPN). Выводит ссылку `https://t.me/proxy?...`: открой её на устройстве с Telegram, и прокси добавится в один клик.

Параметры: `--port 8443 --domain www.google.com`.

## Клиенты (с поддержкой XHTTP)

- **Android:** v2rayNG, Hiddify
- **iOS / macOS:** v2RayTun, Streisand, Hiddify
- **Windows / Linux:** v2rayN, Hiddify, Nekoray (с ядром Xray)

Клиент должен работать на свежем Xray-core: на старых версиях нет транспорта XHTTP.

## Где что лежит на сервере

- `/usr/local/etc/xray/config.json` — конфиг Xray
- `/usr/local/etc/xray/lastvn.env` — параметры сервера (IP, публичный ключ, SNI, path)
- `/usr/local/etc/xray/lastvn.tokens` — токены подписок пользователей
- `/var/www/lastvn/` и `/etc/nginx/conf.d/lastvn.conf` — сервер подписок
- `/etc/mtg.toml` — конфиг MTProto-прокси
- логи: `journalctl -u xray -f`, `journalctl -u mtg -f`
