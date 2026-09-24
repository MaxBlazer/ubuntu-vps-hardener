#!/usr/bin/env bash
# Prepare a fresh Ubuntu VPS: user, SSH keys, Docker, firewall, fail2ban.
# SSH: keys only, root login disabled, non-default port.
# The provider web console still accepts the local root password.
set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export APT_LISTCHANGES_FRONTEND=none
export LC_ALL=C

PORT_FILE_ROOT=/root/.vps_preparer_ssh_port
SUMMARY_FILE=/root/vps-preparer-summary.txt
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-vps-preparer.conf

USER_NAME=""
GITHUB_USER=""
SSH_PORT_OPT=""
KEYS=()

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: bootstrap.sh --user NAME (--ssh-key 'ssh-ed25519 AAAA... comment')... [options]

Required:
  --user NAME              Linux username to create (sudo + docker)
  --ssh-key 'KEY'          Public key (repeatable). ed25519, ecdsa, or security-key.
                           ssh-rsa and ssh-dss are rejected.

Options:
  --github-user LOGIN      Also import keys from https://github.com/LOGIN.keys
                           RSA/DSA lines from GitHub are skipped.
  --ssh-port PORT          Use this SSH port instead of a saved or random one.
  -h, --help               Show this help.

The SSH port is chosen once and reused on later runs (see
/root/.vps_preparer_ssh_port). Pass --ssh-port to change it.

Example:
  bash bootstrap.sh --user maxblazer --ssh-key 'ssh-ed25519 AAAA... laptop'
EOF
}

valid_username() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

valid_github_login() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]
}

# OpenSSH security keys (passkeys) are accepted on purpose.
key_is_accepted() {
  local key="$1"
  [[ "$key" =~ ^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]]
}

key_is_rejected_type() {
  local key="$1"
  [[ "$key" =~ ^(ssh-rsa|ssh-dss)[[:space:]] ]]
}

add_key() {
  local key="$1" source="${2:-argument}"
  key="${key#"${key%%[![:space:]]*}"}"
  key="${key%"${key##*[![:space:]]}"}"
  [[ -z "$key" || "$key" == \#* ]] && return 0
  if key_is_rejected_type "$key"; then
    if [[ "$source" == github ]]; then
      printf 'warning: skipping RSA/DSA key from GitHub\n' >&2
      return 0
    fi
    die "refusing RSA/DSA key (${source}). Use ed25519 or ecdsa."
  fi
  if ! key_is_accepted "$key"; then
    die "unsupported public key from ${source}: ${key%% *}"
  fi
  local existing
  for existing in "${KEYS[@]+"${KEYS[@]}"}"; do
    [[ "$existing" == "$key" ]] && return 0
  done
  KEYS+=("$key")
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user)
        [[ $# -ge 2 ]] || die "--user needs a value"
        USER_NAME="$2"
        shift 2
        ;;
      --ssh-key)
        [[ $# -ge 2 ]] || die "--ssh-key needs a value"
        add_key "$2" "argument"
        shift 2
        ;;
      --github-user)
        [[ $# -ge 2 ]] || die "--github-user needs a value"
        GITHUB_USER="$2"
        shift 2
        ;;
      --ssh-port)
        [[ $# -ge 2 ]] || die "--ssh-port needs a value"
        SSH_PORT_OPT="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1 (try --help)"
        ;;
    esac
  done

  [[ -n "$USER_NAME" ]] || die "--user is required"
  valid_username "$USER_NAME" || die "invalid username: $USER_NAME"
  if [[ -n "$GITHUB_USER" ]]; then
    valid_github_login "$GITHUB_USER" || die "invalid GitHub login: $GITHUB_USER"
  fi
  if [[ -n "$SSH_PORT_OPT" ]]; then
    [[ "$SSH_PORT_OPT" =~ ^[0-9]+$ ]] || die "--ssh-port must be a number"
    (( SSH_PORT_OPT >= 1 && SSH_PORT_OPT <= 65535 )) || die "--ssh-port out of range"
    (( SSH_PORT_OPT >= 1024 )) || die "--ssh-port must be >= 1024"
  fi
}

fetch_github_keys() {
  [[ -n "$GITHUB_USER" ]] || return 0
  log "Fetching GitHub keys for ${GITHUB_USER}"
  local tmp line
  tmp=$(mktemp)
  if ! curl -fsSL --retry 3 --max-time 30 \
      "https://github.com/${GITHUB_USER}.keys" -o "$tmp"; then
    rm -f "$tmp"
    die "failed to download GitHub keys for ${GITHUB_USER}"
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    add_key "$line" github
  done < "$tmp"
  rm -f "$tmp"
}

require_root_ubuntu() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run this script as root"
  [[ -r /etc/os-release ]] || die "missing /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "this script supports Ubuntu only (found ${ID:-unknown})"
  log "Ubuntu ${VERSION_ID:-unknown} (${VERSION_CODENAME:-unknown})"
}

ensure_swap() {
  if swapon --show --noheadings | grep -q .; then
    log "Swap already present, skipping"
    return 0
  fi
  log "Creating 512M swapfile"
  if [[ ! -f /swapfile ]]; then
    # dd, not fallocate: a sparse swapfile is rejected by mkswap.
    dd if=/dev/zero of=/swapfile bs=1M count=512 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
  fi
  swapon /swapfile
  if ! grep -qE '^[[:space:]]*/swapfile[[:space:]]' /etc/fstab; then
    printf '/swapfile none swap sw 0 0\n' >> /etc/fstab
  fi
}

apt_base() {
  log "Updating packages"
  apt-get update
  apt-get upgrade -y
  apt-get install -y \
    apt-listchanges \
    ca-certificates \
    curl \
    fail2ban \
    git \
    gnupg \
    iproute2 \
    jq \
    lsb-release \
    ufw \
    unattended-upgrades \
    zsh
}

create_user() {
  log "Configuring user ${USER_NAME}"
  if ! id "$USER_NAME" >/dev/null 2>&1; then
    adduser --gecos "" --disabled-password "$USER_NAME"
  fi
  usermod -aG sudo "$USER_NAME"
  local zsh_path
  zsh_path=$(command -v zsh)
  [[ -n "$zsh_path" ]] || die "zsh was not installed"
  chsh -s "$zsh_path" "$USER_NAME"
}

install_omz() {
  local home zshrc
  home=$(getent passwd "$USER_NAME" | cut -d: -f6)
  [[ -n "$home" && -d "$home" ]] || die "home directory for ${USER_NAME} not found"
  if [[ ! -d "$home/.oh-my-zsh" ]]; then
    log "Installing Oh My Zsh"
    sudo -u "$USER_NAME" -H env RUNZSH=no CHSH=no \
      bash -c 'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended'
  else
    log "Oh My Zsh already installed"
  fi
  zshrc="$home/.zshrc"
  if [[ -f "$zshrc" ]] && grep -q '^plugins=' "$zshrc"; then
    sed -i 's/^plugins=.*/plugins=(git docker docker-compose)/' "$zshrc"
  else
    printf '\nplugins=(git docker docker-compose)\n' >> "$zshrc"
  fi
  chown "$USER_NAME:$USER_NAME" "$zshrc"
}

install_authorized_keys() {
  local home ssh_dir auth
  home=$(getent passwd "$USER_NAME" | cut -d: -f6)
  ssh_dir="$home/.ssh"
  auth="$ssh_dir/authorized_keys"
  log "Installing SSH public keys"
  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  touch "$auth"
  chmod 600 "$auth"
  local key
  for key in "${KEYS[@]}"; do
    if ! grep -qxF "$key" "$auth"; then
      printf '%s\n' "$key" >> "$auth"
    fi
  done
  if ! grep -Eq '^(ssh-ed25519|ecdsa-sha2-|sk-ssh-ed25519@|sk-ecdsa-sha2-)' "$auth"; then
    die "no accepted keys in ${auth}; refusing to continue"
  fi
  chown -R "$USER_NAME:$USER_NAME" "$ssh_dir"
}

install_sudoers() {
  local file="/etc/sudoers.d/${USER_NAME}"
  log "Passwordless sudo for ${USER_NAME}"
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$USER_NAME" > "$file"
  chmod 440 "$file"
  visudo -cf "$file" >/dev/null
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    log "Docker already installed"
  else
    log "Installing Docker Engine"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    local codename arch
    codename=$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
    arch=$(dpkg --print-architecture)
    cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable
EOF
    if ! apt-get update || ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin; then
      log "Docker apt repo failed for ${codename}; using Ubuntu docker.io"
      rm -f /etc/apt/sources.list.d/docker.list
      apt-get update
      apt-get install -y docker.io docker-compose-v2
    fi
  fi
  usermod -aG docker "$USER_NAME"
  systemctl enable --now docker
}

configure_dns() {
  log "Setting DNS resolvers"
  if [[ ! -f /etc/systemd/resolved.conf.bak ]]; then
    cp -a /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bak
  fi
  cat > /etc/systemd/resolved.conf <<'EOF'
[Resolve]
DNS=9.9.9.9 1.1.1.1 8.8.8.8
FallbackDNS=
EOF
  systemctl restart systemd-resolved
}

configure_journald() {
  log "Limiting journald to 100M"
  if grep -qE '^#?SystemMaxUse=' /etc/systemd/journald.conf; then
    sed -i -E 's/^#?SystemMaxUse=.*/SystemMaxUse=100M/' /etc/systemd/journald.conf
  else
    printf '\nSystemMaxUse=100M\n' >> /etc/systemd/journald.conf
  fi
  systemctl restart systemd-journald
  journalctl --vacuum-size=100M >/dev/null || true
}

configure_unattended_upgrades() {
  log "Enabling unattended security upgrades (no automatic reboot)"
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  cat > /etc/apt/apt.conf.d/52vps-preparer-unattended <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  systemctl enable unattended-upgrades >/dev/null 2>&1 || true
}

port_in_use() {
  local port="$1"
  ss -lntH "sport = :${port}" | grep -q .
}

choose_ssh_port() {
  if [[ -n "$SSH_PORT_OPT" ]]; then
    if port_in_use "$SSH_PORT_OPT"; then
      # Re-runs listen on this port already; that is fine.
      if ! ss -lntpH "sport = :${SSH_PORT_OPT}" | grep -q 'sshd'; then
        die "port ${SSH_PORT_OPT} is already in use by another process"
      fi
    fi
    SSH_PORT="$SSH_PORT_OPT"
    return 0
  fi
  if [[ -f "$PORT_FILE_ROOT" ]]; then
    local saved
    saved=$(tr -d '[:space:]' < "$PORT_FILE_ROOT")
    if [[ "$saved" =~ ^[0-9]+$ ]] && (( saved >= 1024 && saved <= 65535 )); then
      SSH_PORT="$saved"
      log "Reusing saved SSH port ${SSH_PORT}"
      return 0
    fi
  fi
  local attempt rand
  for attempt in $(seq 1 50); do
    rand=$(od -An -N2 -tu2 /dev/urandom | tr -d '[:space:]')
    SSH_PORT=$((49152 + rand % 16384))
    if ! port_in_use "$SSH_PORT"; then
      log "Selected SSH port ${SSH_PORT}"
      return 0
    fi
  done
  die "could not find a free SSH port"
}

save_ssh_port() {
  local home
  home=$(getent passwd "$USER_NAME" | cut -d: -f6)
  printf '%s\n' "$SSH_PORT" > "$PORT_FILE_ROOT"
  chmod 600 "$PORT_FILE_ROOT"
  printf '%s\n' "$SSH_PORT" > "${home}/.vps_preparer_ssh_port"
  chown "$USER_NAME:$USER_NAME" "${home}/.vps_preparer_ssh_port"
  chmod 600 "${home}/.vps_preparer_ssh_port"
}

configure_ufw() {
  log "Configuring UFW (SSH port ${SSH_PORT} only)"
  ufw default deny incoming
  ufw default allow outgoing
  ufw --force delete allow 22/tcp >/dev/null 2>&1 || true
  ufw --force delete allow OpenSSH >/dev/null 2>&1 || true
  ufw allow "${SSH_PORT}/tcp" comment 'ssh'
  ufw --force enable
}

configure_fail2ban() {
  log "Configuring fail2ban"
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
banaction = ufw
maxretry = 5
findtime = 3600
bantime = 86400

[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
EOF
  systemctl enable fail2ban
  systemctl restart fail2ban
}

# OpenSSH uses the first value it sees. Ubuntu includes sshd_config.d before
# the main file, and earlier drop-ins beat later ones. Force the same safe
# values everywhere so a provider file cannot turn passwords or port 22 back on.
rewrite_sshd_keywords() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  local tmp
  tmp=$(mktemp)
  awk -v port="$SSH_PORT" '
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*Port[[:space:]]+/ { print "Port " port; seen_port=1; next }
    /^[[:space:]]*PermitRootLogin[[:space:]]+/ { print "PermitRootLogin no"; next }
    /^[[:space:]]*PasswordAuthentication[[:space:]]+/ { print "PasswordAuthentication no"; next }
    /^[[:space:]]*KbdInteractiveAuthentication[[:space:]]+/ { print "KbdInteractiveAuthentication no"; next }
    /^[[:space:]]*ChallengeResponseAuthentication[[:space:]]+/ { print "ChallengeResponseAuthentication no"; next }
    /^[[:space:]]*PubkeyAuthentication[[:space:]]+/ { print "PubkeyAuthentication yes"; next }
    { print }
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

configure_sshd() {
  log "Hardening sshd"
  mkdir -p /etc/ssh/sshd_config.d
  cat > "$SSHD_DROPIN" <<EOF
# Managed by vps_preparer. First drop-in so these values win.
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
EOF
  local conf
  shopt -s nullglob
  for conf in /etc/ssh/sshd_config.d/*.conf; do
    [[ "$conf" == "$SSHD_DROPIN" ]] && continue
    rewrite_sshd_keywords "$conf"
  done
  shopt -u nullglob
  rewrite_sshd_keywords /etc/ssh/sshd_config

  if ! sshd -t; then
    die "sshd config test failed. This session is still open. Do not disconnect. UFW may already allow only port ${SSH_PORT}."
  fi

  # Ubuntu cloud images often listen via ssh.socket on port 22 and ignore Port.
  if systemctl list-unit-files ssh.socket --no-legend >/dev/null 2>&1 \
      && systemctl list-unit-files ssh.socket --no-legend | grep -q .; then
    systemctl disable --now ssh.socket || true
  fi
  systemctl enable ssh.service
  systemctl restart ssh.service
}

primary_ipv4() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

print_summary() {
  local ip
  ip=$(primary_ipv4 || true)
  [[ -n "$ip" ]] || ip="<SERVER_IP>"
  cat <<EOF | tee "$SUMMARY_FILE"

============================================================
Сервер подготовлен. Текущую root-сессию НЕ закрывайте,
пока вторая сессия не войдёт успешно.

  ssh -p ${SSH_PORT} ${USER_NAME}@${ip}

Порт SSH: ${SSH_PORT}
Записан в: ${PORT_FILE_ROOT}
и в домашнем каталоге пользователя: ~/.vps_preparer_ssh_port

Root по SSH отключён. Вход по паролю по SSH отключён.
Пароль root в системе сохранён: веб-консоль провайдера
(VNC) по-прежнему принимает его.

Группа docker применится после нового входа.
Повторный запуск скрипта сохраняет этот порт.
============================================================
EOF
  chmod 600 "$SUMMARY_FILE"
}

main() {
  parse_args "$@"
  fetch_github_keys
  ((${#KEYS[@]} > 0)) || die "no accepted SSH keys. Pass --ssh-key and/or --github-user."
  require_root_ubuntu
  ensure_swap
  apt_base
  create_user
  install_omz
  install_authorized_keys
  install_sudoers
  install_docker
  configure_dns
  configure_journald
  configure_unattended_upgrades
  choose_ssh_port
  save_ssh_port
  configure_ufw
  configure_fail2ban
  configure_sshd
  print_summary
}

main "$@"
