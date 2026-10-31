#!/bin/sh
# One-command management for docker-scout-scanner.
#
#   ./scanner.sh install     build + start, wait until healthy, print URLs and login
#   ./scanner.sh status      show containers and URLs
#   ./scanner.sh password    reset the admin password and print the new one
#   ./scanner.sh logs        follow the logs
#   ./scanner.sh update      git pull, rebuild, restart (keeps your data)
#   ./scanner.sh stop        stop the stack (keeps your data)
#   ./scanner.sh reinstall   DELETE all data (scans, users, certs) and install fresh
#   ./scanner.sh uninstall   DELETE containers, data volumes and built images
set -eu
cd "$(dirname "$0")"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not installed"

dc() { docker compose "$@"; }

envval() { # read KEY from .env (falls back to $2)
  v=$(sed -n "s/^$1=\([^ #]*\).*/\1/p" .env 2>/dev/null | tail -1)
  [ -n "$v" ] && echo "$v" || echo "$2"
}

lan_ip() {
  ip=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
  [ -n "$ip" ] || ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  [ -n "$ip" ] || ip=localhost
  echo "$ip"
}

ensure_env() {
  [ -f .env ] && return
  cp .env.example .env
  ip=$(lan_ip)
  # Put the LAN IP into the self-signed certificate.
  [ "$ip" != localhost ] && sed -i "s/^TLS_SANS=.*/TLS_SANS=$ip/" .env
  info "created .env (TLS name: $ip)"
}

wait_healthy() {
  printf '  waiting for the stack to come up'
  i=0
  while [ $i -lt 90 ]; do
    web=$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q web 2>/dev/null)" 2>/dev/null || true)
    [ "$web" = healthy ] && { echo " ok"; return 0; }
    printf '.'; sleep 2; i=$((i+1))
  done
  echo
  dc ps
  echo
  dc logs --tail 30 web scanner
  die "the stack did not become healthy (logs above)"
}

show_urls() {
  ip=$(lan_ip); port=$(envval DASHBOARD_PORT 8443); aport=$(envval ADMIN_PORT 8444)
  echo
  bold "Dashboard:   https://$ip:$port"
  info "(self-signed certificate: accept the browser warning once)"
  bold "Admin panel: https://127.0.0.1:$aport   (on this machine only)"
  info "from another PC: ssh -L $aport:127.0.0.1:$aport $(id -un)@$ip   then open https://127.0.0.1:$aport"
}

show_login() {
  user=$(envval ADMIN_USER admin)
  pw=$(dc logs scanner 2>/dev/null | sed -n 's/.*msg="created admin account".* password=\([^ ]*\).*/\1/p' | tail -1)
  echo
  if [ -n "$pw" ]; then
    bold "Login:       $user / $pw"
    info "(you'll be asked to choose a new password on first sign-in)"
  elif [ -n "$(envval ADMIN_PASSWORD '')" ]; then
    bold "Login:       $user / the ADMIN_PASSWORD from .env"
  else
    bold "Login:       $user / (existing account from an earlier install)"
    info "forgot it? run: ./scanner.sh password"
  fi
}

confirm() {
  printf '%s Type "yes" to continue: ' "$1"
  read -r a
  [ "$a" = yes ] || die "aborted"
}

cmd=${1:-install}
case "$cmd" in
  install|up|start)
    bold "Installing docker-scout-scanner"
    ensure_env
    dc up -d --build
    wait_healthy
    show_urls
    show_login
    ;;
  status)
    dc ps
    show_urls
    ;;
  password)
    user=${2:-$(envval ADMIN_USER admin)}
    dc exec scanner scanner reset-password "$user"
    ;;
  logs)
    dc logs -f --tail 100
    ;;
  update)
    git pull --ff-only
    dc up -d --build
    wait_healthy
    show_urls
    ;;
  stop|down)
    dc down
    ;;
  reinstall|reset)
    confirm "This deletes ALL scan data, users and certificates."
    dc down -v --remove-orphans
    "$0" install
    ;;
  uninstall)
    confirm "This deletes the containers, ALL data volumes and the built images."
    dc down -v --remove-orphans --rmi all
    info "removed. Delete this folder to finish."
    ;;
  *)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
