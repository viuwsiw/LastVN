#!/usr/bin/env bash
# LastVN — VPN (VLESS + XHTTP + Reality, Xray-core) и прокси для Telegram (MTProto, mtg).
# Домен и сертификат не нужны: Reality маскирует трафик под TLS чужого сайта.
#
# Использование:
#   sudo bash lastvn.sh install [--port 443] [--sub-port 2096] [--sni www.microsoft.com] [--name user1] [--support-url URL]
#   sudo bash lastvn.sh add <имя>        — добавить пользователя
#   sudo bash lastvn.sh del <имя>        — удалить пользователя
#   sudo bash lastvn.sh list             — список пользователей
#   sudo bash lastvn.sh link <имя>       — подписка и ключ для клиента
#   sudo bash lastvn.sh status           — статус сервисов
#   sudo bash lastvn.sh tune             — ускорение сети (BBR, TCP-буферы)
#   sudo bash lastvn.sh logs             — ссылки на логи тестов и состояния сервера
#   sudo bash lastvn.sh split [порт|off] — выгрузка через Cloudflare Worker, скачивание напрямую
#   sudo bash lastvn.sh selftest         — самопроверка входов клиентом Xray на сервере
#   sudo bash lastvn.sh selfsteal [домен] — маскировка под свой сайт (против шейпинга DPI)
#   sudo bash lastvn.sh speed            — проверить канал сервера и нагрузку CPU
#   sudo bash lastvn.sh upgrade          — пересобрать конфиг по последней версии скрипта (ключи сохраняются)
#   sudo bash lastvn.sh mtproto [--port 8443] [--domain IP.sslip.io] — прокси для Telegram
#   sudo bash lastvn.sh mtproto-remove   — удалить прокси для Telegram
#   sudo bash lastvn.sh uninstall        — удалить всё

set -euo pipefail

TITLE="LastVN: первый, надежный"   # название в клиентах (Happ/INCY: до 25 символов)

XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/etc/xray"
CONFIG="$XRAY_DIR/config.json"
STATE="$XRAY_DIR/lastvn.env"      # параметры сервера
TOKENS="$XRAY_DIR/lastvn.tokens"  # "имя токен_подписки" по строке
WEB="/var/www/lastvn"
NGINX_CONF="/etc/nginx/conf.d/lastvn.conf"

DEFAULT_PORT=443
DEFAULT_SUB_PORT=2096
DEFAULT_SNI="www.microsoft.com"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
die()   { red "Ошибка: $*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "запусти через sudo/root"; }
installed() { [[ -f "$CONFIG" && -f "$STATE" ]]; }
need_installed() { installed || die "LastVN не установлен. Сначала: $0 install"; }
valid_port() { [[ $1 =~ ^[0-9]+$ && $1 -ge 1 && $1 -le 65535 ]]; }

port_free() {
  local port=$1 who
  who=$(ss -Hltnp "sport = :$port" 2>/dev/null || true)
  [[ -z $who ]] || die "порт $port занят: $who
Освободи его (или переустанови ОС на сервере) и запусти снова."
}

# ---------- зависимости ----------
install_deps() {
  if command -v apt-get >/dev/null; then
    # Без интерактивных вопросов (needrestart, замена конфигов dpkg и т.п.)
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
    apt-get update -qq
    apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
      curl jq openssl unzip nginx ca-certificates iproute2 >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q curl jq openssl unzip nginx ca-certificates iproute
  else
    die "поддерживаются Ubuntu/Debian и RHEL-подобные системы"
  fi
}

install_xray() {
  yellow "Устанавливаю Xray-core (официальный скрипт XTLS/Xray-install)..."
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  [[ -x "$XRAY_BIN" ]] || die "xray не установился"
}

# Ускорение сети: BBR + большие TCP-буферы (важны для гигабита и высокого пинга).
tune_network() {
  rm -f /etc/sysctl.d/99-lastvn-bbr.conf
  cat > /etc/sysctl.d/99-lastvn.conf <<'SYSCTL'
# LastVN: ускорение сети
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.ipv4.tcp_rmem = 4096 1048576 67108864
net.ipv4.tcp_wmem = 4096 1048576 67108864
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
SYSCTL
  modprobe tcp_bbr 2>/dev/null || true
  sysctl --system >/dev/null 2>&1 || true
  # Лимит открытых файлов для xray (много соединений).
  mkdir -p /etc/systemd/system/xray.service.d
  printf '[Service]\nLimitNOFILE=1048576\n' > /etc/systemd/system/xray.service.d/99-lastvn.conf
  systemctl daemon-reload
}

open_port() {
  local port=$1
  if command -v ufw >/dev/null && ufw status | grep -q active; then
    ufw allow "$port"/tcp >/dev/null
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port="$port"/tcp && firewall-cmd -q --reload
  fi
}

# ---------- генерация параметров ----------
server_ip() {
  local ip url
  for url in https://api.ipify.org https://ifconfig.me https://icanhazip.com; do
    ip=$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]') && [[ -n $ip ]] && { echo "$ip"; return; }
  done
  die "не удалось определить внешний IP сервера"
}

# Совместимо со всеми форматами xray x25519: "Private key/Public key", "PrivateKey/Password", "PrivateKey/Password (PublicKey)".
gen_keys() {
  # Во всех версиях xray x25519 первая строка — приватный ключ, вторая — публичный
  # ("Public key" / "Password" / "Password (PublicKey)"). Берём значение после последнего ": ".
  local out priv pub
  out=$("$XRAY_BIN" x25519 | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g')
  priv=$(sed -n '1s/.*:[[:space:]]*//p' <<<"$out")
  pub=$(sed -n '2s/.*:[[:space:]]*//p' <<<"$out")
  [[ $priv =~ ^[A-Za-z0-9_-]{43}$ && $pub =~ ^[A-Za-z0-9_-]{43}$ ]] \
    || die "не удалось распарсить вывод xray x25519: $out"
  echo "$priv $pub"
}

check_sni() {
  # Цель Reality должна поддерживать TLS 1.3 и HTTP/2.
  curl -sS -o /dev/null --max-time 8 --tlsv1.3 --http2 "https://$1" 2>/dev/null \
    || yellow "Внимание: $1 не ответил по TLS 1.3/HTTP2 с этого сервера — лучше выбрать другой SNI (--sni)."
}

# ---------- конфиг Xray ----------
# Канал VPN: VLESS + XHTTP + Reality на внешнем порту (443).
write_config() {
  local port=$1 sni=$2 priv=$3 sid=$4 path=$5 clients=$6 target=${7:-"$2:443"}
  mkdir -p "$XRAY_DIR"
  jq -n \
    --argjson port "$port" --arg sni "$sni" --arg priv "$priv" --arg sid "$sid" \
    --arg path "$path" --argjson clients "$clients" --arg target "$target" \
    --arg loglevel "${LOGLEVEL:-warning}" '
  {
    log: { loglevel: $loglevel },
    inbounds: [{
      tag: "vless-xhttp-reality",
      listen: "0.0.0.0",
      port: $port,
      protocol: "vless",
      settings: {
        clients: [ $clients[] | { id, email } ],
        decryption: "none"
      },
      streamSettings: {
        network: "xhttp",
        xhttpSettings: { path: $path, mode: "auto" },
        security: "reality",
        realitySettings: {
          show: false,
          target: $target,
          xver: 0,
          serverNames: [$sni],
          privateKey: $priv,
          shortIds: [$sid]
        },
        sockopt: { tcpFastOpen: true, tcpNoDelay: true }
      },
      sniffing: { enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true }
    }],
    outbounds: [
      { tag: "direct", protocol: "freedom", streamSettings: { sockopt: { tcpFastOpen: true, tcpNoDelay: true } } },
      { tag: "block",  protocol: "blackhole" }
    ],
    routing: {
      domainStrategy: "AsIs",
      rules: [
        { type: "field", ip: ["geoip:private"], outboundTag: "block" },
        { type: "field", protocol: ["bittorrent"], outboundTag: "block" }
      ]
    }
  }' > "$CONFIG"
  if [[ -n ${SPLIT_PORT:-} ]]; then
    # Фронт: VLESS raw + Reality на SPLIT_PORT. XHTTP-клиенты (HTTP/2 внутри Reality) не проходят
    # проверку VLESS и уходят fallback'ом в локальный XHTTP-инбаунд — туда же nginx (порт 80)
    # шлёт выгрузку от Cloudflare. Обе половины сессии встречаются в одном инбаунде.
    local tmp; tmp=$(mktemp)
    jq --argjson sp "$SPLIT_PORT" --argjson lp "$SPLIT_LOCAL_PORT" '
      .inbounds[0] as $m |
      .inbounds += [
        { tag: "split-front", listen: "0.0.0.0", port: $sp, protocol: "vless",
          settings: { clients: $m.settings.clients, decryption: "none",
                      fallbacks: [ { dest: ("127.0.0.1:" + ($lp|tostring)) } ] },
          streamSettings: { network: "raw", security: "reality",
                            realitySettings: $m.streamSettings.realitySettings,
                            sockopt: { tcpFastOpen: true, tcpNoDelay: true } },
          sniffing: $m.sniffing },
        { tag: "split-xhttp", listen: "127.0.0.1", port: $lp, protocol: "vless",
          settings: { clients: $m.settings.clients, decryption: "none" },
          streamSettings: { network: "xhttp", xhttpSettings: { path: $m.streamSettings.xhttpSettings.path, mode: "auto" } },
          sniffing: $m.sniffing }
      ]' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
  fi
  local lab_spec lab_tag lab_port lab_sni
  for lab_spec in "lab:${LAB_PORT:-}:${LAB_SNI:-}" "lab2:${LAB2_PORT:-}:${LAB2_SNI:-}"; do
    IFS=: read -r lab_tag lab_port lab_sni <<<"$lab_spec"
    [[ -n $lab_port ]] || continue
    local tmp; tmp=$(mktemp)
    jq --arg tag "$lab_tag" --argjson lp "$lab_port" --arg ls "$lab_sni" '.inbounds += [.inbounds[0] | .tag = $tag | .port = $lp
        | if $ls != "" then .streamSettings.realitySettings.target = ($ls + ":443")
                           | .streamSettings.realitySettings.serverNames = [$ls] else . end]' "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
  done
  chmod 644 "$CONFIG"
}

# Пользователи из текущего конфига: [{id, email}] (работает и со старой схемой «только XHTTP»).
config_clients() {
  jq -c '[.inbounds[0].settings.clients[] | {id, email}]' "$CONFIG"
}

test_and_restart() {
  "$XRAY_BIN" run -test -c "$CONFIG" >/dev/null || die "конфиг невалиден: $XRAY_BIN run -test -c $CONFIG"
  systemctl restart xray
  sleep 1
  systemctl is-active --quiet xray || die "xray не запустился: journalctl -u xray -n 50"
}

# Атомарно правим конфиг через jq-фильтр.
edit_config() {
  local tmp; tmp=$(mktemp)
  jq "$@" "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
  chmod 644 "$CONFIG"
}

user_uuid() {
  jq -r --arg n "$1" '[.inbounds[].settings.clients[]? | select(.email==$n) | .id][0] // empty' "$CONFIG"
}

# ---------- ссылки и подписка ----------
urlencode() { jq -rn --arg s "$1" '$s|@uri'; }

make_link() {
  local uuid; uuid=$(user_uuid "$1")
  [[ -n $uuid ]] || die "пользователь '$1' не найден"
  # shellcheck disable=SC1090
  source "$STATE"
  # xmux: клиент держит до 8 параллельных TCP-соединений вместо одного — так скорость
  # не упирается в одно соединение (потери/пинг) ни на скачивании, ни на выгрузке.
  # stream-up: выгрузка одним длинным потоком на соединение — по замерам лучше всего
  # переживает потери и шейпинг на маршруте (packet-up терял и пересобирал куски).
  # xmux: до 8 параллельных соединений вместо одного.
  local extra='{"xmux":{"maxConnections":8,"cMaxReuseTimes":0,"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000"}}'
  printf 'vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=xhttp&path=%s&mode=stream-up&extra=%s#%s\n' \
    "$uuid" "$SERVER_IP" "$PORT" "$SNI" "$PUBLIC_KEY" "$SHORT_ID" "$(urlencode "$XHTTP_PATH")" "$(urlencode "$extra")" "$(urlencode "$TITLE")"
}


user_token() { awk -v n="$1" '$1==n {print $2}' "$TOKENS" 2>/dev/null; }

sub_url() {
  # shellcheck disable=SC1090
  source "$STATE"
  echo "http://$SERVER_IP:$SUB_PORT/sub/$(user_token "$1")"
}

# JSON-конфиг Xray для режима split (Happ понимает JSON-подписки; downloadSettings из ссылки vless:// он игнорирует).
make_split_json() {
  local name=$1 uuid; uuid=$(user_uuid "$name")
  # shellcheck disable=SC1090
  source "$STATE"
  jq -n --arg w "$SPLIT_WORKER" --arg id "$uuid" --arg ip "$SERVER_IP" --argjson sp "$SPLIT_PORT" \
        --arg sni "$SNI" --arg pk "$PUBLIC_KEY" --arg sid "$SHORT_ID" --arg path "$XHTTP_PATH" --arg title "$TITLE" '{
    remarks: ($title + " ⚡ split"),
    log: {loglevel: "warning"},
    inbounds: [{tag: "socks", listen: "127.0.0.1", port: 10808, protocol: "socks", settings: {udp: true},
                sniffing: {enabled: true, destOverride: ["http", "tls", "quic"], routeOnly: true}}],
    outbounds: [
      {tag: "proxy", protocol: "vless",
       settings: {vnext: [{address: $w, port: 443, users: [{id: $id, encryption: "none"}]}]},
       streamSettings: {network: "xhttp", security: "tls",
         tlsSettings: {serverName: $w, fingerprint: "chrome", alpn: ["h2", "http/1.1"]},
         xhttpSettings: {host: $w, path: $path, mode: "packet-up",
           extra: {downloadSettings: {address: $ip, port: $sp, network: "xhttp", security: "reality",
             realitySettings: {serverName: $sni, fingerprint: "chrome", publicKey: $pk, shortId: $sid},
             xhttpSettings: {path: $path, mode: "stream-up"}}}}}},
      {tag: "direct", protocol: "freedom"},
      {tag: "block", protocol: "blackhole"}],
    routing: {domainStrategy: "AsIs", rules: [{type: "field", ip: ["geoip:private"], outboundTag: "direct"}]}
  }'
}

# Пересобираем файлы подписок: по одному файлу на пользователя, тело — base64 со ссылками.
rebuild_subs() {
  mkdir -p "$WEB/sub"
  rm -f "$WEB/sub/"*
  local name token
  while read -r name token; do
    [[ -n $name ]] || continue
    make_link "$name" | base64 -w0 > "$WEB/sub/$token"
    if grep -q '^SPLIT_WORKER=' "$STATE" && grep -q '^SPLIT_PORT=' "$STATE"; then
      make_split_json "$name" > "$WEB/sub/$token-split"
    fi
  done < "$TOKENS"
  chmod -R a+rX "$WEB"
}

add_token() { echo "$1 $(openssl rand -hex 16)" >> "$TOKENS"; chmod 600 "$TOKENS"; }

write_web() {
  local ip=$1 sub_port=$2 support=$3
  mkdir -p "$WEB/sub"
  write_logo "$WEB/logo.png"
  cat > "$WEB/index.html" <<EOF
<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LastVN</title><link rel="icon" href="/logo.png">
<style>body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#000;color:#9a9a9a;font:18px system-ui,sans-serif}img{width:160px;height:160px}</style>
</head><body><img src="/logo.png" alt="LastVN"><h1>LastVN</h1><p>первый, надежный</p></body></html>
EOF

  local title_b64 support_hdr=""
  title_b64=$(printf '%s' "$TITLE" | base64 -w0)
  if [[ -n $support ]]; then support_hdr="add_header support-url \"$support\" always;"; fi

  local logdir; logdir=$(log_dir)
  mkdir -p "$logdir"
  cat > "$NGINX_CONF" <<EOF
# LastVN: сервер подписок (Happ, INCY, v2rayNG, Hiddify и др.)
log_format lastvn_speed '\$time_iso8601 ip=\$remote_addr down=\$arg_d up=\$arg_u note="\$arg_n" ua="\$http_user_agent"';

server {
    listen $sub_port;
    listen [::]:$sub_port;
    server_name _;
    server_tokens off;
    root $WEB;
    access_log off;

    location = / { try_files /index.html =404; }
    location = /logo.png { }

    # Спидтест «напрямую до сервера, без VPN»: /speed — страница, /down — 100 МБ, /up — приём POST.
    location = /speed { default_type text/html; charset utf-8; try_files /speed.html =404; }
    location = /down  { add_header Cache-Control "no-store" always; try_files /down.bin =404; }
    location = /up    { client_max_body_size 0; client_body_buffer_size 1m; add_header Cache-Control "no-store" always; return 204; }
    location = /up1   { client_max_body_size 0; client_body_buffer_size 1m; keepalive_requests 1; add_header Cache-Control "no-store" always; return 204; }
    location = /log   { access_log $logdir/speed.log lastvn_speed; add_header Cache-Control "no-store" always; return 204; }

    # Логи: только по секретному пути (токен первого пользователя), без листинга.
    location /logs/ { default_type text/plain; charset utf-8; add_header Cache-Control "no-store" always; autoindex off; }

    location /sub/ {
        default_type text/plain;
        charset utf-8;
        add_header profile-title "base64:$title_b64" always;
        add_header profile-update-interval "12" always;
        add_header subscription-userinfo "upload=0; download=0; total=0; expire=0" always;
        add_header profile-web-page-url "http://$ip:$sub_port/" always;
        add_header content-disposition "attachment; filename=\"LastVN\"" always;
        $support_hdr
        try_files \$uri =404;
    }

    location / { return 404; }
}
EOF
  nginx -t >/dev/null 2>&1 || die "конфиг nginx невалиден: nginx -t"
  systemctl enable nginx >/dev/null 2>&1
  systemctl restart nginx
}

write_speedtest() {
  # 100 МБ случайных данных (не сжимаются по пути).
  [[ -s $WEB/down.bin ]] || head -c 100000000 /dev/urandom > "$WEB/down.bin"
  cat > "$WEB/speed.html" <<'HTML'
<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LastVN Speed</title><link rel="icon" href="/logo.png">
<style>
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#000;color:#bbb;font:18px system-ui,sans-serif;padding:16px;box-sizing:border-box}
img{width:96px;height:96px}.v{font-size:44px;color:#fff;font-variant-numeric:tabular-nums}
.row{display:flex;gap:40px;margin:24px 0;text-align:center}button{font:inherit;padding:12px 28px;border-radius:10px;border:0;background:#9a9a9a;color:#000;cursor:pointer}
button:disabled{opacity:.5}small{color:#777;text-align:center;max-width:420px}
</style></head><body>
<img src="/logo.png" alt=""><h2>Скорость до сервера LastVN</h2>
<small>Выключи VPN перед тестом — так видно, режет ли провайдер канал до этого сервера.</small>
<div class="row"><div>Скачивание<div class="v" id="d">—</div>Мбит/с</div><div>Выгрузка<div class="v" id="u">—</div>Мбит/с</div><div>Выгрузка*<div class="v" id="f">—</div>Мбит/с</div></div>
<small>* каждый кусок по 1 МБ — новым соединением</small><br>
<button id="b">Начать</button>
<small id="s"></small>
<script>
const P=6, T=10000, $=id=>document.getElementById(id);
function mbps(bytes,ms){return (bytes*8/ms/1000).toFixed(0)}
async function down(){
  let bytes=0, t0=performance.now(), stop=false;
  const one=async()=>{while(!stop){const r=await fetch('/down?'+Math.random(),{cache:'no-store'});const rd=r.body.getReader();
    for(;;){const {done,value}=await rd.read();if(done)break;bytes+=value.length;$('d').textContent=mbps(bytes,performance.now()-t0);
      if(performance.now()-t0>T){stop=true;rd.cancel();break}}}};
  await Promise.all(Array.from({length:P},one)); return mbps(bytes,performance.now()-t0);
}
async function up(path='/up', mb=8, out='u'){
  const chunk=new Uint8Array(1<<20); for(let i=0;i<chunk.length;i+=65536)crypto.getRandomValues(chunk.subarray(i,i+65536));
  const blob=new Blob(Array(mb).fill(chunk));
  let bytes=0, t0=performance.now();
  const one=async()=>{while(performance.now()-t0<T){await fetch(path+'?'+Math.random(),{method:'POST',body:blob,cache:'no-store'});
    bytes+=blob.size;$(out).textContent=mbps(bytes,performance.now()-t0)}};
  await Promise.all(Array.from({length:P},one)); return mbps(bytes,performance.now()-t0);
}
$('b').onclick=async()=>{$('b').disabled=true;$('d').textContent=$('u').textContent=$('f').textContent='…';
  try{$('s').textContent='Скачивание…';$('d').textContent=await down();
      $('s').textContent='Выгрузка…';$('u').textContent=await up();
      fetch('/log?d='+$('d').textContent+'&u='+$('u').textContent+'&n=direct-keepalive',{cache:'no-store'});
      await new Promise(r=>setTimeout(r,3000));
      $('s').textContent='Выгрузка новыми соединениями…';$('f').textContent=await up('/up1',1,'f');
      fetch('/log?d=-&u='+$('f').textContent+'&n=direct-fresh-conn',{cache:'no-store'});
      $('s').textContent='Готово — результат записан в лог';}
  catch(e){$('s').textContent='Ошибка: '+e}
  $('b').disabled=false};
</script></body></html>
HTML
  chmod -R a+rX "$WEB"
}

show_user() {
  local name=$1 sub
  sub=$(sub_url "$name")
  echo
  green "Пользователь: $name"
  echo
  echo "Подписка (Happ / INCY — с названием LastVN):"
  echo "  $sub"
  echo
  echo "Ключ VLESS:"
  echo "  $(make_link "$name")"
  echo
}

# ---------- команды ----------
cmd_install() {
  need_root
  local port=$DEFAULT_PORT sub_port=$DEFAULT_SUB_PORT sni=$DEFAULT_SNI name="user1" support=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --port)        port=$2;     shift 2 ;;
      --sub-port)    sub_port=$2; shift 2 ;;
      --sni)         sni=$2;      shift 2 ;;
      --name)        name=$2;     shift 2 ;;
      --support-url) support=$2;  shift 2 ;;
      *) die "неизвестный параметр: $1" ;;
    esac
  done
  valid_port "$port" || die "неверный порт: $port"
  valid_port "$sub_port" || die "неверный порт подписки: $sub_port"
  [[ $port != "$sub_port" ]] || die "порт VPN и порт подписки должны отличаться"
  [[ $name =~ ^[A-Za-z0-9_.-]+$ ]] || die "имя: только латиница, цифры, _ . -"
  installed && die "LastVN уже установлен. Для переустановки сначала: $0 uninstall"

  install_deps
  port_free "$port"
  port_free "$sub_port"
  install_xray
  tune_network

  local ip priv pub sid path uuid
  ip=$(server_ip)
  read -r priv pub < <(gen_keys)
  sid=$(openssl rand -hex 8)
  path="/$(openssl rand -hex 6)"
  uuid=$("$XRAY_BIN" uuid)
  check_sni "$sni"

  write_config "$port" "$sni" "$priv" "$sid" "$path" \
    "$(jq -nc --arg id "$uuid" --arg n "$name" '[{id:$id, email:$n}]')"
  cat > "$STATE" <<EOF
SERVER_IP=$ip
PORT=$port
SUB_PORT=$sub_port
SNI=$sni
PUBLIC_KEY=$pub
SHORT_ID=$sid
XHTTP_PATH=$path
EOF
  chmod 600 "$STATE"
  : > "$TOKENS"
  add_token "$name"

  open_port "$port"
  open_port "$sub_port"
  systemctl enable xray >/dev/null 2>&1
  test_and_restart
  write_web "$ip" "$sub_port" "$support"
  write_speedtest
  rebuild_subs
  install_monitor

  green "Готово! VLESS + XHTTP + Reality работает на $ip:$port (маскировка под $sni)"
  show_user "$name"
}

cmd_add() {
  need_root; need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 add <имя>"
  [[ $name =~ ^[A-Za-z0-9_.-]+$ ]] || die "имя: только латиница, цифры, _ . -"
  [[ -z $(user_uuid "$name") ]] || die "пользователь '$name' уже есть"
  local uuid; uuid=$("$XRAY_BIN" uuid)
  edit_config --arg n "$name" --arg id "$uuid" '
    .inbounds |= map(
      if .settings.clients then .settings.clients += [{id:$id, email:$n}]
      else . end)'
  test_and_restart
  add_token "$name"
  rebuild_subs
  show_user "$name"
}

cmd_del() {
  need_root; need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 del <имя>"
  [[ -n $(user_uuid "$name") ]] || die "пользователь '$name' не найден"
  [[ $(jq '.inbounds[0].settings.clients | length' "$CONFIG") -gt 1 ]] || die "нельзя удалить последнего пользователя"
  edit_config --arg n "$name" '
    .inbounds |= map(if .settings.clients then .settings.clients |= map(select(.email != $n)) else . end)'
  test_and_restart
  local tmp; tmp=$(mktemp)
  awk -v n="$name" '$1!=n' "$TOKENS" > "$tmp" && mv "$tmp" "$TOKENS" && chmod 600 "$TOKENS"
  rebuild_subs
  green "Пользователь '$name' удалён"
}

cmd_list() {
  need_installed
  local name
  for name in $(jq -r '.inbounds[0].settings.clients[].email' "$CONFIG"); do
    printf '%-16s %s\n' "$name" "$(sub_url "$name")"
  done
}

cmd_link() {
  need_installed
  local name=${1:-}; [[ -n $name ]] || die "укажи имя: $0 link <имя>"
  show_user "$name"
}

cmd_status() {
  need_installed
  # shellcheck disable=SC1090
  source "$STATE"
  echo "Сервер:   $SERVER_IP:$PORT   SNI: $SNI   path: $XHTTP_PATH"
  echo "Подписки: http://$SERVER_IP:$SUB_PORT/sub/..."
  echo "Xray:     $("$XRAY_BIN" version | head -1)"
  echo "xray:     $(systemctl is-active xray)"
  echo "nginx:    $(systemctl is-active nginx)"
  if [[ -f $MTG_CONF ]]; then echo "mtg:      $(systemctl is-active mtg)   $(mtg_link)"; fi
}

# ---------- MTProto-прокси для Telegram (mtg, FakeTLS) ----------
MTG_BIN="/usr/local/bin/mtg"
MTG_CONF="/etc/mtg.toml"
MTG_UNIT="/etc/systemd/system/mtg.service"

install_mtg_bin() {
  local arch url tmp
  case $(uname -m) in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "архитектура $(uname -m) не поддерживается для mtg" ;;
  esac
  url=$(curl -fsSL https://api.github.com/repos/9seconds/mtg/releases/latest 2>/dev/null \
        | jq -r --arg a "linux-$arch.tar.gz" '.assets[] | select(.name | endswith($a)) | .browser_download_url' 2>/dev/null | head -1 || true)
  if [[ -z $url ]]; then
    # Запасной путь без API: версия из редиректа /releases/latest -> /releases/tag/vX.Y.Z
    local tag
    tag=$(curl -fsSI https://github.com/9seconds/mtg/releases/latest | tr -d '\r' | sed -n 's#^[Ll]ocation:.*/tag/##p')
    [[ -n $tag ]] || die "не нашёл релиз mtg на GitHub"
    url="https://github.com/9seconds/mtg/releases/download/$tag/mtg-${tag#v}-linux-$arch.tar.gz"
  fi
  tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/mtg.tar.gz"
  tar -xzf "$tmp/mtg.tar.gz" -C "$tmp"
  install -m 755 "$(find "$tmp" -type f -name mtg | head -1)" "$MTG_BIN"
  rm -rf "$tmp"
  "$MTG_BIN" --help >/dev/null 2>&1 || die "mtg не запускается"
}

mtg_link() {
  local secret port ip
  secret=$(sed -n 's/^secret *= *"\(.*\)"/\1/p' "$MTG_CONF")
  port=$(sed -n 's/^bind-to *= *".*:\([0-9]*\)"/\1/p' "$MTG_CONF")
  ip=$(sed -n 's/^SERVER_IP=//p' "$STATE" 2>/dev/null || true)
  [[ -n $ip ]] || ip=$(server_ip)
  echo "https://t.me/proxy?server=$ip&port=$port&secret=$secret"
}

show_mtg() {
  local link; link=$(mtg_link)
  echo
  green "MTProto-прокси для Telegram:"
  echo "  $link"
  echo
}

cmd_mtproto() {
  need_root
  # Домен маскировки должен указывать на IP этого сервера (иначе DPI видит
  # несоответствие SNI и IP и режет соединение). Без своего домена берём sslip.io:
  # 1-2-3-4.sslip.io всегда резолвится в 1.2.3.4.
  local port=8443 domain=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --port)   port=$2;   shift 2 ;;
      --domain) domain=$2; shift 2 ;;
      *) die "неизвестный параметр: $1" ;;
    esac
  done
  if [[ -f $MTG_CONF ]]; then
    show_mtg
    yellow "Прокси уже установлен. Пересоздать: $0 mtproto-remove, затем $0 mtproto"
    return
  fi
  valid_port "$port" || die "неверный порт: $port"
  command -v jq >/dev/null || install_deps
  if [[ -z $domain ]]; then
    local ip; ip=$(sed -n 's/^SERVER_IP=//p' "$STATE" 2>/dev/null || true)
    [[ -n $ip ]] || ip=$(server_ip)
    domain="${ip//./-}.sslip.io"
  fi
  port_free "$port"

  yellow "Устанавливаю mtg (MTProto-прокси)..."
  install_mtg_bin
  local secret; secret=$("$MTG_BIN" generate-secret --hex "$domain")
  [[ $secret == ee* ]] || die "не удалось сгенерировать секрет: $secret"

  cat > "$MTG_CONF" <<CONF
# LastVN: MTProto-прокси (FakeTLS под $domain)
secret = "$secret"
bind-to = "0.0.0.0:$port"
CONF
  chmod 644 "$MTG_CONF"   # mtg работает под DynamicUser; секрет всё равно уходит клиентам в ссылке

  cat > "$MTG_UNIT" <<UNIT
[Unit]
Description=LastVN MTProto proxy (mtg)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$MTG_BIN run $MTG_CONF
Restart=always
RestartSec=3
DynamicUser=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  open_port "$port"
  systemctl daemon-reload
  systemctl enable --now mtg >/dev/null 2>&1
  sleep 1
  systemctl is-active --quiet mtg || die "mtg не запустился: journalctl -u mtg -n 50"

  green "Готово! MTProto-прокси работает на порту $port (маскировка под $domain)"
  show_mtg
}

cmd_mtproto_remove() {
  need_root
  systemctl disable --now mtg 2>/dev/null || true
  rm -f "$MTG_UNIT" "$MTG_CONF" "$MTG_BIN"
  systemctl daemon-reload
  green "MTProto-прокси удалён"
}

cmd_upgrade() {
  need_root; need_installed
  local r priv sid sni path port clients target
  r=$(jq -c '[.inbounds[] | .streamSettings.realitySettings? // empty][0]' "$CONFIG")
  priv=$(jq -r '.privateKey' <<<"$r")
  sid=$(jq -r '.shortIds[0]' <<<"$r")
  sni=$(jq -r '.serverNames[0]' <<<"$r")
  target=$(jq -r '.target // .dest' <<<"$r")
  path=$(jq -r '[.inbounds[] | .streamSettings.xhttpSettings.path? // empty][0]' "$CONFIG")
  port=$(jq -r '[.inbounds[] | .port? // empty][0]' "$CONFIG")
  clients=$(config_clients)
  [[ -n $priv && $priv != null && -n $path && $path != null ]] || die "не удалось прочитать текущий конфиг"
  local LAB_PORT LAB_SNI LAB2_PORT LAB2_SNI
  LAB_PORT=$(sed -n 's/^LAB_PORT=//p' "$STATE" 2>/dev/null || true)
  LAB_SNI=$(sed -n 's/^LAB_SNI=//p' "$STATE" 2>/dev/null || true)
  LAB2_PORT=$(sed -n 's/^LAB2_PORT=//p' "$STATE" 2>/dev/null || true)
  LAB2_SNI=$(sed -n 's/^LAB2_SNI=//p' "$STATE" 2>/dev/null || true)
  local SPLIT_PORT; SPLIT_PORT=$(sed -n 's/^SPLIT_PORT=//p' "$STATE" 2>/dev/null || true)
  local LOGLEVEL; LOGLEVEL=$(sed -n 's/^LOGLEVEL=//p' "$STATE" 2>/dev/null || true)
  cp "$CONFIG" "$CONFIG.bak"
  write_config "$port" "$sni" "$priv" "$sid" "$path" "$clients" "$target"
  if ! "$XRAY_BIN" run -test -c "$CONFIG" >/dev/null; then
    cp "$CONFIG.bak" "$CONFIG"
    die "новый конфиг не прошёл проверку, вернул старый ($CONFIG.bak)"
  fi
  tune_network
  test_and_restart
  local support; support=$(sed -n 's/.*add_header support-url "\([^"]*\)".*/\1/p' "$NGINX_CONF" 2>/dev/null || true)
  # shellcheck disable=SC1090
  source "$STATE"
  write_web "$SERVER_IP" "$SUB_PORT" "$support"
  write_speedtest
  rebuild_subs
  install_monitor
  echo "Спидтест до сервера (без VPN): http://$SERVER_IP:$SUB_PORT/speed"
  cmd_logs
  green "Конфиг обновлён (VLESS + XHTTP + Reality). Ключи, ссылки и подписки прежние."
  local name
  for name in $(jq -r '.[].email' <<<"$clients"); do show_user "$name"; done
}

# Диагностика скорости: канал самого сервера + нагрузка CPU.
cmd_speed() {
  echo "Ядер CPU: $(nproc)   RAM: $(free -m | awk '/Mem:/ {print $2}') МБ"
  echo "Загрузка: $(cut -d' ' -f1-3 /proc/loadavg)"
  echo "Congestion control: $(sysctl -n net.ipv4.tcp_congestion_control)"
  echo
  echo "Скачивание сервером:"
  local bps url
  for url in 'https://speed.cloudflare.com/__down?bytes=25000000' \
             'https://proof.ovh.net/files/100Mb.dat' \
             'https://ash-speed.hetzner.com/100MB.bin'; do
    bps=$(curl -sf -o /dev/null --max-time 20 -w '%{speed_download}' "$url" || echo 0)
    awk -v b="$bps" -v u="${url#https://}" 'BEGIN {printf "  ↓ %4.0f Мбит/с   %s\n", b*8/1000000, u}'
  done
  echo "Выгрузка сервером (Cloudflare, 25 МБ):"
  bps=$(head -c 25000000 /dev/zero | curl -s -o /dev/null --max-time 30 -w '%{speed_upload}' --data-binary @- 'https://speed.cloudflare.com/__up' || echo 0)
  awk -v b="$bps" 'BEGIN {printf "  ↑ %.0f Мбит/с\n", b*8/1000000}'
  echo
  echo "CPU процессов (во время спидтеста на телефоне запусти: top):"
  ps -eo comm,%cpu,rss --sort=-%cpu | awk 'NR==1 || /xray|mtg|nginx/' | head -6
}

# ---------- Reality self-steal: маскировка под собственный сайт на этом же IP ----------
# DPI сверяет SNI с IP: «www.microsoft.com» на чужом IP = подозрительно, такие соединения шейпят.
# Здесь SNI = домен, который указывает на этот сервер (IP.sslip.io), а за ним — настоящий
# HTTPS-сайт (nginx на 127.0.0.1:9443). Reality «одалживает» TLS-рукопожатие у него.
SELFSTEAL_PORT=9443
SELFSTEAL_CONF="/etc/nginx/conf.d/lastvn-selfsteal.conf"
CERT_DIR="/etc/lastvn/cert"

# Порт 80: ACME-проверка Let's Encrypt, редирект на https и (в режиме split)
# приём XHTTP-выгрузки от Cloudflare Worker -> локальный XHTTP-инбаунд Xray.
SPLIT_LOCAL_PORT=10000
write_http80() {
  local domain=$1 split_loc=""
  local xpath; xpath=$(sed -n 's/^XHTTP_PATH=//p' "$STATE" 2>/dev/null || true)
  if [[ -n $(sed -n 's/^SPLIT_PORT=//p' "$STATE" 2>/dev/null || true) && -n $xpath ]]; then
    split_loc="location ^~ $xpath {
        proxy_pass http://127.0.0.1:$SPLIT_LOCAL_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header Connection \"\";
        proxy_request_buffering off;
        proxy_buffering off;
        client_max_body_size 0;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }"
  fi
  mkdir -p /var/www/lastvn-acme
  cat > /etc/nginx/conf.d/lastvn-http.conf <<NGX
server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    server_tokens off;
    access_log off;
    location /.well-known/acme-challenge/ { root /var/www/lastvn-acme; }
    $split_loc
    location / { return 301 https://\$host\$request_uri; }
}
NGX
  rm -f /etc/nginx/sites-enabled/default
  nginx -t >/dev/null 2>&1 || die "конфиг nginx невалиден: nginx -t"
  systemctl reload nginx
}

get_cert() {
  local domain=$1
  mkdir -p "$CERT_DIR" /var/www/lastvn-acme
  write_http80 "$domain"
  open_port 80

  if ! command -v certbot >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null 2>&1 || true
  fi
  if command -v certbot >/dev/null && certbot certonly --webroot -w /var/www/lastvn-acme -d "$domain" \
       --agree-tos --register-unsafely-without-email -n --quiet \
       --deploy-hook "systemctl reload nginx" >/dev/null 2>&1; then
    ln -sf "/etc/letsencrypt/live/$domain/fullchain.pem" "$CERT_DIR/fullchain.pem"
    ln -sf "/etc/letsencrypt/live/$domain/privkey.pem"   "$CERT_DIR/privkey.pem"
    green "Сертификат Let's Encrypt для $domain получен"
  else
    yellow "Let's Encrypt не выдал сертификат — ставлю самоподписанный (для обхода шейпера этого достаточно)."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
      -subj "/CN=$domain" -addext "subjectAltName=DNS:$domain" >/dev/null 2>&1
  fi
}

write_selfsteal_site() {
  local domain=$1
  cat > "$SELFSTEAL_CONF" <<NGX
# LastVN: сайт-маска для Reality (доступен только локально, снаружи — через Xray на 443)
server {
    listen 127.0.0.1:$SELFSTEAL_PORT ssl;
    http2 on;
    server_name $domain;
    server_tokens off;
    ssl_certificate     $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:lastvn:10m;
    root $WEB;
    location = / { try_files /index.html =404; }
    location = /logo.png { }
    location / { return 404; }
}
NGX
  nginx -t >/dev/null 2>&1 || die "конфиг nginx невалиден: nginx -t"
  systemctl reload nginx
}

cmd_selfsteal() {
  need_root; need_installed
  local domain=${1:-}
  # shellcheck disable=SC1090
  source "$STATE"
  [[ -n $domain ]] || domain="${SERVER_IP//./-}.sslip.io"
  local who; who=$(ss -Hltnp 'sport = :80' 2>/dev/null || true)
  [[ -z $who || $who == *nginx* ]] || die "порт 80 занят: $who"

  yellow "Настраиваю маскировку под $domain (self-steal)..."
  get_cert "$domain"
  write_selfsteal_site "$domain"

  local r priv sid path port clients
  r=$(jq -c '[.inbounds[] | .streamSettings.realitySettings? // empty][0]' "$CONFIG")
  priv=$(jq -r '.privateKey' <<<"$r")
  sid=$(jq -r '.shortIds[0]' <<<"$r")
  path=$(jq -r '[.inbounds[] | .streamSettings.xhttpSettings.path? // empty][0]' "$CONFIG")
  port=$(jq -r '[.inbounds[] | .port? // empty][0]' "$CONFIG")
  clients=$(config_clients)
  local LAB_PORT LAB_SNI LAB2_PORT LAB2_SNI
  LAB_PORT=$(sed -n 's/^LAB_PORT=//p' "$STATE" 2>/dev/null || true)
  LAB_SNI=$(sed -n 's/^LAB_SNI=//p' "$STATE" 2>/dev/null || true)
  LAB2_PORT=$(sed -n 's/^LAB2_PORT=//p' "$STATE" 2>/dev/null || true)
  LAB2_SNI=$(sed -n 's/^LAB2_SNI=//p' "$STATE" 2>/dev/null || true)
  local SPLIT_PORT; SPLIT_PORT=$(sed -n 's/^SPLIT_PORT=//p' "$STATE" 2>/dev/null || true)
  local LOGLEVEL; LOGLEVEL=$(sed -n 's/^LOGLEVEL=//p' "$STATE" 2>/dev/null || true)
  cp "$CONFIG" "$CONFIG.bak"
  write_config "$port" "$domain" "$priv" "$sid" "$path" "$clients" "127.0.0.1:$SELFSTEAL_PORT"
  if ! "$XRAY_BIN" run -test -c "$CONFIG" >/dev/null; then
    cp "$CONFIG.bak" "$CONFIG"
    die "новый конфиг не прошёл проверку, вернул старый"
  fi
  sed -i "s/^SNI=.*/SNI=$domain/" "$STATE"
  test_and_restart
  rebuild_subs
  green "Готово: VPN маскируется под $domain (SNI совпадает с IP сервера)."
  yellow "В Happ обнови подписку — в ключе поменялся SNI."
  local name
  for name in $(jq -r '.[].email' <<<"$clients"); do show_user "$name"; done
}

# ---------- логи для диагностики ----------
SELF="/usr/local/sbin/lastvn"
MON_UNIT="/etc/systemd/system/lastvn-monitor.service"

log_dir() {
  local tok; tok=$(awk 'NR==1 {print $2}' "$TOKENS" 2>/dev/null || true)
  [[ -n $tok ]] || tok=nologs
  echo "$WEB/logs/$tok"
}

logs_url() {
  # shellcheck disable=SC1090
  source "$STATE"
  echo "http://$SERVER_IP:$SUB_PORT/logs/$(basename "$(log_dir)")/"
}

install_self() {
  # Копия скрипта в системный путь — для службы мониторинга и удобного вызова «lastvn ...».
  [[ "$(readlink -f "$0")" == "$SELF" ]] || install -m 755 "$0" "$SELF"
}

# Раз в секунду: трафик интерфейса (Мбит/с) и CPU. Пишем строку, если есть заметный трафик,
# и раз в минуту — снимок состояния (status.txt). Так видно, что происходит во время каждого теста.
# rx tx (байты) интерфейса; формат /proc/net/dev бывает «eth0: 123» и «eth0:123».
net_bytes() {
  awk -v i="$1" '{l=$0; sub(/^ +/, "", l); n=index(l, ":"); if (substr(l, 1, n-1) == i) {split(substr(l, n+1), f, " "); print f[1], f[9]; found=1}}
                 END {if (!found) print 0, 0}' /proc/net/dev
}

cmd_monitor_loop() {
  local dir iface prx ptx pidle ptotal n=0
  dir=$(log_dir); mkdir -p "$dir"
  iface=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
  [[ -n $iface ]] || iface=$(awk -F'\t' '$2=="00000000" {print $1; exit}' /proc/net/route 2>/dev/null || true)
  [[ -n $iface ]] || iface=eth0
  read -r prx ptx < <(net_bytes "$iface")
  read -r pidle ptotal < <(awk '/^cpu / {t=0; for(i=2;i<=NF;i++) t+=$i; print $5+$6, t}' /proc/stat)
  while sleep 1; do
    local rx tx idle total drx dtx cpu
    read -r rx tx < <(net_bytes "$iface")
    read -r idle total < <(awk '/^cpu / {t=0; for(i=2;i<=NF;i++) t+=$i; print $5+$6, t}' /proc/stat)
    drx=$(( (rx - prx) * 8 / 1000000 )); dtx=$(( (tx - ptx) * 8 / 1000000 ))
    cpu=$(( total > ptotal ? 100 - 100 * (idle - pidle) / (total - ptotal) : 0 ))
    prx=$rx; ptx=$tx; pidle=$idle; ptotal=$total
    if (( drx >= 2 || dtx >= 2 )); then
      local lp lp2; lp=$(sed -n 's/^LAB_PORT=//p; s/^SPLIT_PORT=//p' "$STATE" 2>/dev/null | head -1 || true); lp2=$(sed -n 's/^LAB2_PORT=//p' "$STATE" 2>/dev/null || true)
      printf '%s rx(от клиентов)=%sMbit tx(к клиентам)=%sMbit cpu=%s%% conn443=%s%s\n' \
        "$(date '+%F %T')" "$drx" "$dtx" "$cpu" \
        "$(ss -Htn state established '( sport = :443 )' 2>/dev/null | wc -l)" \
        "${lp:+ conn$lp=$(ss -Htn state established "( sport = :$lp )" 2>/dev/null | wc -l)}${lp2:+ conn$lp2=$(ss -Htn state established "( sport = :$lp2 )" 2>/dev/null | wc -l)}" >> "$dir/net.log"
    fi
    if (( n++ % 60 == 0 )); then
      write_status "$dir" > "$dir/status.txt.tmp" 2>&1 && mv "$dir/status.txt.tmp" "$dir/status.txt"
      if [[ $(stat -c %s "$dir/net.log" 2>/dev/null || echo 0) -gt 5000000 ]]; then
        tail -n 20000 "$dir/net.log" > "$dir/net.log.tmp" && mv "$dir/net.log.tmp" "$dir/net.log"
      fi
    fi
  done
}

write_status() {
  echo "== $(date '+%F %T %Z')   $(uptime -p)   load: $(cut -d' ' -f1-3 /proc/loadavg)"
  echo "CPU: $(nproc)   RAM: $(free -m | awk '/Mem:/ {print $3"/"$2" МБ"}')   kernel: $(uname -r)"
  echo "xray: $(systemctl is-active xray) ($("$XRAY_BIN" version 2>/dev/null | head -1 | awk '{print $2}'))   nginx: $(systemctl is-active nginx)   mtg: $(systemctl is-active mtg 2>/dev/null)"
  echo "cc: $(sysctl -n net.ipv4.tcp_congestion_control)  qdisc: $(sysctl -n net.core.default_qdisc)  rmem_max: $(sysctl -n net.core.rmem_max)  tfo: $(sysctl -n net.ipv4.tcp_fastopen)"
  echo "соединений на 443: $(ss -Htn state established '( sport = :443 )' | wc -l)   на 8443: $(ss -Htn state established '( sport = :8443 )' | wc -l)"
  echo "TCP: $(ss -s | sed -n 's/^TCP: *//p')"
  echo "retrans: $(nstat -az TcpRetransSegs 2>/dev/null | awk '/TcpRetransSegs/ {print $2}')"
  echo
  echo "== процессы по CPU"
  ps -eo pid,comm,%cpu,%mem,etime --sort=-%cpu 2>/dev/null | head -8
  echo
  echo "== конфиг Xray (без приватного ключа)"
  jq -c '.inbounds[] | {tag, port, net: .streamSettings.network, xhttp: .streamSettings.xhttpSettings,
          sni: .streamSettings.realitySettings.serverNames, target: .streamSettings.realitySettings.target,
          users: (.settings.clients | length)}' "$CONFIG" 2>/dev/null
  echo
  echo "== журнал xray (последние 40)"
  journalctl -u xray -n 40 --no-pager -o short-iso 2>/dev/null | sed -E 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/<uuid>/g'
  echo
  if grep -q '^SPLIT_PORT=' "$STATE" 2>/dev/null; then
    echo "== split: события за 5 минут"
    { journalctl -u xray --since "-5min" --no-pager -o cat 2>/dev/null \
        | grep -iE 'split|fallback|reality|xhttp|splithttp|failed|error|invalid|:2083|session' \
        | grep -v 'X-Forwarded-For' | sed -E 's/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/<uuid>/g' | tail -120; } || true
    echo
  fi
  echo "== журнал mtg (последние 20)"
  journalctl -u mtg -n 20 --no-pager -o short-iso 2>/dev/null
}

install_monitor() {
  install_self
  cat > "$MON_UNIT" <<UNIT
[Unit]
Description=LastVN monitor (логи трафика и состояния)
After=network-online.target

[Service]
ExecStart=$SELF monitor-loop
Restart=always
RestartSec=5
Nice=10

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable lastvn-monitor >/dev/null 2>&1
  systemctl restart lastvn-monitor
}

cmd_logs() {
  need_installed
  echo "Логи (открываются в браузере):"
  echo "  $(logs_url)status.txt  — состояние сервера, журналы xray и mtg"
  echo "  $(logs_url)net.log     — трафик по секундам во время тестов"
  echo "  $(logs_url)speed.log   — результаты спидтеста http://IP:$SUB_PORT/speed"
}

# Лаборатория: копия VPN-входа на втором порту, чтобы сравнивать по логам (порт/режим).
cmd_lab() { lab_generic LAB "$@"; }
cmd_lab2() { lab_generic LAB2 "$@"; }

lab_generic() {
  need_root; need_installed
  local V=$1; shift
  local arg=${1:-on} lsni=""
  [[ ${2:-} == --sni ]] && lsni=${3:-}
  [[ $arg == --sni ]] && { lsni=${2:-}; arg=on; }
  sed -i "/^${V}_PORT=/d; /^${V}_SNI=/d" "$STATE"
  if [[ $arg == off ]]; then
    green "Лаборатория выключена"
  else
    local lp=2083; [[ $V == LAB2 ]] && lp=2087; [[ $arg =~ ^[0-9]+$ ]] && lp=$arg
    port_free "$lp"
    echo "${V}_PORT=$lp" >> "$STATE"
    if [[ -n $lsni ]]; then
      echo "${V}_SNI=$lsni" >> "$STATE"
      check_sni "$lsni"
    fi
    open_port "$lp"
    green "Лаборатория: копия VPN на порту $lp${lsni:+, маска $lsni}"
  fi
  cmd_upgrade >/dev/null
  green "Конфиг применён"
}

# Split: выгрузка через Cloudflare Worker (её ТСПУ не режет), скачивание — напрямую через Reality.
cmd_split() {
  need_root; need_installed
  local arg=${1:-on}
  if [[ $arg == worker ]]; then
    local w=${2:-}; w=${w#https://}; w=${w%%/*}
    [[ $w == *.* ]] || die "укажи адрес воркера: $0 split worker имя.workers.dev"
    sed -i '/^SPLIT_WORKER=/d' "$STATE"; echo "SPLIT_WORKER=$w" >> "$STATE"
    rebuild_subs
    # shellcheck disable=SC1090
    source "$STATE"
    green "Подписка split (JSON для Happ):"
    echo "  http://$SERVER_IP:$SUB_PORT/sub/$(awk 'NR==1 {print $2}' "$TOKENS")-split"
    return
  fi
  # shellcheck disable=SC1090
  source "$STATE"
  sed -i '/^SPLIT_PORT=/d' "$STATE"
  if [[ $arg == off ]]; then
    cmd_upgrade >/dev/null
    write_http80 "$SNI"
    green "Split выключен"; return
  fi
  [[ $(jq -r '.inbounds[0].streamSettings.realitySettings.target' "$CONFIG") == 127.0.0.1:* ]] \
    || die "сначала включи маскировку под свой сайт: $0 selfsteal"
  local sp=2083; [[ $arg =~ ^[0-9]+$ ]] && sp=$arg
  # Лаборатории занимают порты — выключаем.
  sed -i '/^LAB_PORT=/d; /^LAB_SNI=/d; /^LAB2_PORT=/d; /^LAB2_SNI=/d' "$STATE"
  echo "SPLIT_PORT=$sp" >> "$STATE"
  open_port "$sp"; open_port 80
  cmd_upgrade >/dev/null
  write_http80 "$SNI"
  green "Split включён: скачивание — Reality на порту $sp, выгрузка — через Cloudflare Worker -> порт 80."
  echo "Origin для воркера: http://$SNI$XHTTP_PATH"
}

# Самопроверка: клиент Xray на самом сервере ходит в свои же входы (без ТСПУ и чужих прокси)
# и пишет результат в лог. Сценарии: основной 443, Reality на SPLIT_PORT, split (выгрузка через :80).
cmd_selftest() {
  need_root; need_installed
  # shellcheck disable=SC1090
  source "$STATE"
  local dir uuid out tmp
  dir=$(log_dir); mkdir -p "$dir"; out="$dir/selftest.txt"
  uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$CONFIG")
  tmp=$(mktemp -d)
  local reality
  reality=$(jq -nc --arg sn "$SNI" --arg pk "$PUBLIC_KEY" --arg sid "$SHORT_ID" \
    '{serverName:$sn, fingerprint:"chrome", publicKey:$pk, shortId:$sid}')

  run_case() { # имя порт_socks адрес порт streamSettings
    local name=$1 sp=$2 addr=$3 port=$4 ss=$5 code
    jq -n --argjson sp "$sp" --arg a "$addr" --argjson p "$port" --arg id "$uuid" --argjson ss "$ss" '
      { log: {loglevel: "debug"},
        inbounds: [{listen: "127.0.0.1", port: $sp, protocol: "socks", settings: {udp: false}}],
        outbounds: [{protocol: "vless", settings: {vnext: [{address: $a, port: $p, users: [{id: $id, encryption: "none"}]}]},
                     streamSettings: $ss}] }' > "$tmp/$name.json"
    "$XRAY_BIN" run -c "$tmp/$name.json" > "$tmp/$name.log" 2>&1 &
    local pid=$!
    sleep 1
    code=$(curl -s -o /dev/null --max-time 15 -w '%{http_code} %{time_total}s' \
           --socks5-hostname "127.0.0.1:$sp" https://www.google.com/generate_204 || true)
    local up
    up=$(head -c 3000000 /dev/urandom | curl -s -o /dev/null --max-time 20 -w '%{speed_upload}' \
           --socks5-hostname "127.0.0.1:$sp" --data-binary @- https://speed.cloudflare.com/__up || echo 0)
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    printf '== %s: generate_204=%s  upload3MB=%s B/s\n' "$name" "$code" "$up"
    { grep -iE 'error|fail|reality|fallback|invalid' "$tmp/$name.log" | grep -v 'Penetrates' | head -12; } || true
    echo
  }

  {
    echo "selftest $(date '+%F %T')"
    run_case main 10901 127.0.0.1 "$PORT" "$(jq -nc --argjson r "$reality" --arg path "$XHTTP_PATH" \
      '{network:"xhttp", security:"reality", realitySettings:$r, xhttpSettings:{path:$path, mode:"stream-one"}}')"
    if [[ -n ${SPLIT_PORT:-} ]]; then
      run_case split-reality 10902 127.0.0.1 "$SPLIT_PORT" "$(jq -nc --argjson r "$reality" --arg path "$XHTTP_PATH" \
        '{network:"xhttp", security:"reality", realitySettings:$r, xhttpSettings:{path:$path, mode:"stream-one"}}')"
      run_case split-http80 10903 127.0.0.1 80 "$(jq -nc --arg host "$SNI" --arg path "$XHTTP_PATH" \
        '{network:"xhttp", security:"none", xhttpSettings:{host:$host, path:$path, mode:"packet-up"}}')"
      run_case split-full 10904 127.0.0.1 80 "$(jq -nc --argjson r "$reality" --arg host "$SNI" --arg path "$XHTTP_PATH" --argjson sp "$SPLIT_PORT" \
        '{network:"xhttp", security:"none", xhttpSettings:{host:$host, path:$path, mode:"packet-up",
          extra:{downloadSettings:{address:"127.0.0.1", port:$sp, network:"xhttp", security:"reality",
                                   realitySettings:$r, xhttpSettings:{path:$path}}}}}')"
    fi
    echo "== журнал сервера xray (последние 25)"
    { journalctl -u xray -n 25 --no-pager -o cat 2>/dev/null | grep -v accepted; } || true
  } > "$out" 2>&1
  rm -rf "$tmp"
  cat "$out"
}

# Подробный журнал Xray для диагностики: debug on|off
cmd_debug() {
  need_root; need_installed
  sed -i '/^LOGLEVEL=/d' "$STATE"
  [[ ${1:-on} == off ]] || echo "LOGLEVEL=debug" >> "$STATE"
  cmd_upgrade >/dev/null
  green "Журнал Xray: ${1:-on}"
}

cmd_tune() {
  need_root
  tune_network
  systemctl restart xray 2>/dev/null || true
  green "Сеть настроена: $(sysctl -n net.ipv4.tcp_congestion_control), TCP-буферы до 64 МБ"
}

cmd_uninstall() {
  need_root
  read -r -p "Удалить Xray, подписки и все ключи пользователей? [y/N] " ans
  [[ $ans =~ ^[Yy]$ ]] || exit 0
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge || true
  if [[ -f $MTG_CONF ]]; then cmd_mtproto_remove; fi
  systemctl disable --now lastvn-monitor 2>/dev/null || true
  rm -f "$MON_UNIT" "$SELF"
  rm -rf "$XRAY_DIR" "$WEB" "$NGINX_CONF" "$SELFSTEAL_CONF" /etc/nginx/conf.d/lastvn-http.conf /etc/lastvn /etc/sysctl.d/99-lastvn.conf /etc/sysctl.d/99-lastvn-bbr.conf /etc/systemd/system/xray.service.d/99-lastvn.conf
  systemctl reload nginx 2>/dev/null || true
  green "LastVN удалён (nginx оставлен как пакет)"
}

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------- логотип (assets/logo.png, встроен в base64) ----------
write_logo() {
  base64 -d > "$1" <<'LOGO'
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
LOGO
}

case ${1:-} in
  install)   shift; cmd_install "$@" ;;
  add)       shift; cmd_add "$@" ;;
  del)       shift; cmd_del "$@" ;;
  list)      cmd_list ;;
  link)      shift; cmd_link "$@" ;;
  status)    cmd_status ;;
  tune)      cmd_tune ;;
  lab)       shift; cmd_lab "$@" ;;
  lab2)      shift; cmd_lab2 "$@" ;;
  split)     shift; cmd_split "$@" ;;
  selftest)  cmd_selftest ;;
  debug)     shift; cmd_debug "$@" ;;
  logs)      cmd_logs ;;
  monitor-loop) cmd_monitor_loop ;;
  selfsteal) shift; cmd_selfsteal "$@" ;;
  speed)     cmd_speed ;;
  upgrade)   cmd_upgrade ;;
  mtproto)   shift; cmd_mtproto "$@" ;;
  mtproto-remove) cmd_mtproto_remove ;;
  uninstall) cmd_uninstall ;;
  *)         usage ;;
esac
