#!/usr/bin/env bash
# Apply to an existing LastOS NL host or Aéza RU relay.
set -euo pipefail
cd -- "$(dirname -- "$0")"

fail() { echo "$*" >&2; exit 1; }
[[ $EUID == 0 ]] || fail "Запусти от root."
[[ -f /sys/fs/cgroup/cgroup.controllers ]] && grep -qw cpu /sys/fs/cgroup/cgroup.controllers ||
  fail "Для настройки веса CPU нужен контроллер cpu в cgroup v2."

if systemctl is-active --quiet lastvn-ru-relay.service; then
  units=(lastvn-ru-relay.service)
else
  units=(xray.service lastos-limits.service nginx.service)
  for unit in "${units[@]}" lastvn-subscription.service; do
    systemctl is-active --quiet "$unit" || fail "Служба $unit не активна."
  done

  # Stage all components before touching the running installation.
  sbin=/usr/local/sbin
  stage=$(mktemp -d "$sbin/.lastvn-update.XXXXXXXX")
  trap 'rm -rf -- "$stage"' EXIT
  exec 9>/run/lock/lastvn-performance.lock
  flock -x 9
  sources=(lastos-limits.py lastos-subscriptions.py lastvn-aeza-split.py lastos-admin.py)
  names=(lastos-limits lastos-subscriptions lastvn_aeza_split.py lastos-admin)
  changed=()
  restart_meter=0
  restart_sub=0
  for i in "${!names[@]}"; do
    name=${names[i]}
    if ! cmp -s "${sources[i]}" "$sbin/$name"; then
      changed+=("$name")
      if [[ -e $sbin/$name ]]; then cp -p -- "$sbin/$name" "$stage/$name.old"; fi
      install -m 755 -- "${sources[i]}" "$stage/$name"
      python3 -m py_compile "$stage/$name"
      case "$name" in
        lastos-limits) restart_meter=1 ;;
        lastos-subscriptions|lastvn_aeza_split.py) restart_sub=1 ;;
      esac
    fi
  done

  refresh() {
    if ((restart_meter)); then systemctl restart lastos-limits.service || return 1; fi
    if ((restart_sub)); then systemctl restart lastvn-subscription.service || return 1; fi
    for _ in {1..50}; do
      if [[ -S /run/lastos-limits/control.sock ]] &&
         ss -xlH | grep -F /run/lastos-limits/control.sock >/dev/null &&
         [[ $(curl -s --max-time 1 --unix-socket /run/lastvn-subscription/http.sock -o /dev/null -w '%{http_code}' http://localhost/) == 404 ]]; then return 0; fi
      sleep .1
    done
    return 1
  }
  rollback() {
    for name in "${changed[@]}"; do
      if [[ -e $stage/$name.old ]]; then mv -f -- "$stage/$name.old" "$sbin/$name"; else rm -f -- "$sbin/$name"; fi
    done
    refresh || echo "Проверь журнал служб LastVN." >&2
    fail "Обновление не применено, прежние файлы восстановлены."
  }
  for name in "${changed[@]}"; do mv -f -- "$stage/$name" "$sbin/$name" || rollback; done
  refresh || rollback
  "$sbin/lastos-limits" unlimit-speed || rollback
fi

for unit in "${units[@]}"; do
  weight=$(systemctl show "$unit" --property=CPUWeight --value)
  if [[ ! $weight =~ ^[0-9]+$ ]] || ((weight < 1000)); then weight=1000; fi
  systemctl set-property "$unit" CPUWeight="$weight" CPUQuota=
  systemctl show "$unit" -p Id -p ActiveState -p CPUWeight -p CPUQuotaPerSecUSec
done
