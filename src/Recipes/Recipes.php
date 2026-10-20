<?php

declare(strict_types=1);

namespace Kongpda\ServerConnect\Recipes;

/**
 * The closed set of server recipes (Debian/Ubuntu, apt). They detect
 * before acting, wait for first-boot package jobs instead of failing, keep
 * existing config files, validate before reloading and roll back on failure.
 */
final class Recipes
{
    /**
     * @var array<string, Recipe>|null
     */
    private static ?array $all = null;

    /**
     * @return array<string, Recipe>
     */
    public static function all(): array
    {
        return self::$all ??= self::define();
    }

    public static function find(string $id): ?Recipe
    {
        return self::all()[$id] ?? null;
    }

    /**
     * The "prepare this server" sequence, in order.
     *
     * @return list<Recipe>
     */
    public static function prepareSequence(): array
    {
        $recipes = array_values(array_filter(self::all(), fn (Recipe $recipe): bool => $recipe->prepareOrder !== null));
        usort($recipes, fn (Recipe $a, Recipe $b): int => $a->prepareOrder <=> $b->prepareOrder);

        return $recipes;
    }

    /**
     * @return array<string, Recipe>
     */
    private static function define(): array
    {
        $recipes = [
            new Recipe(
                id: 'essentials',
                label: 'Install essentials',
                summary: 'Finishes any interrupted package setup and installs curl, git, jq and CA certificates. Waits for first-boot updates instead of failing.',
                group: RecipeGroup::Prepare,
                safety: SafetyLevel::Mutating,
                prepareOrder: 1,
                params: [],
                body: <<<'SH'
command -v apt-get >/dev/null 2>&1 || { echo 'This recipe needs a Debian or Ubuntu server (apt-get).'; exit 1; }
sc_wait_dpkg
$SUDO env DEBIAN_FRONTEND=noninteractive dpkg --force-confdef --force-confold --configure -a && $APT update && $APT install curl git jq ca-certificates || exit 1
echo '--- Essentials ready:'; curl --version | head -n 1; git --version
SH,
            ),
            new Recipe(
                id: 'docker',
                label: 'Install Docker',
                summary: 'Installs Docker Engine with the official get.docker.com script, unless Docker is already there, and enables it at boot.',
                group: RecipeGroup::Prepare,
                safety: SafetyLevel::Mutating,
                prepareOrder: 2,
                params: [],
                body: <<<'SH'
if command -v docker >/dev/null 2>&1; then echo 'Docker is already installed.'
else
  command -v curl >/dev/null 2>&1 || { $APT update && $APT install curl ca-certificates; } || exit 1
  sc_wait_dpkg
  T=$(mktemp) && curl -fsSL https://get.docker.com -o "$T" && $SUDO sh "$T" || exit 1
  rm -f "$T"
fi
$SUDO systemctl enable --now docker >/dev/null 2>&1 || true
$SUDO docker --version || exit 1
SH,
            ),
            new Recipe(
                id: 'swap',
                label: 'Add a swap file',
                summary: 'Creates (or resizes) /swapfile so a memory spike slows a job down instead of killing it. Checks free disk first and leaves other swap alone. Sets swappiness to 10.',
                group: RecipeGroup::Prepare,
                safety: SafetyLevel::Mutating,
                prepareOrder: 3,
                params: [new RecipeParam('SWAP_SIZE', 'Swap size (MB)', '2048', false, '/^[1-9]\d{2,4}$/', '2048')],
                body: <<<'SH'
SIZE="${SWAP_SIZE:-2048}"
if [ "$SIZE" -lt 256 ] || [ "$SIZE" -gt 65536 ]; then echo 'Swap size must be between 256 and 65536 MB.'; exit 1; fi
CUR=$(awk '$1=="/swapfile"{print int($3/1024)}' /proc/swaps 2>/dev/null)
OTHER=$(awk 'NR>1 && $1!="/swapfile"{print $1}' /proc/swaps 2>/dev/null)
room(){ FREE=$(df -Pm / | awk 'NR==2{print $4}'); if [ $(( ${FREE:-0} + ${1:-0} )) -lt $((SIZE + 512)) ]; then echo "Not enough free disk for a ${SIZE} MB swap file (${FREE:-?} MB free)."; return 1; fi; }
mk(){ $SUDO rm -f /swapfile && { $SUDO fallocate -l "${SIZE}M" /swapfile || $SUDO dd if=/dev/zero of=/swapfile bs=1M count="$SIZE" status=none; } && $SUDO chmod 600 /swapfile && $SUDO mkswap /swapfile >/dev/null && $SUDO swapon /swapfile && { grep -qE '^/swapfile[[:space:]]' /etc/fstab || echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab >/dev/null; } && echo "Swap file ready (${SIZE} MB)."; }
if [ -n "$CUR" ]; then
  D=$((CUR - SIZE)); [ "$D" -lt 0 ] && D=$((0 - D))
  if [ "$D" -le 8 ]; then echo "Swap file already ${CUR} MB, nothing to change."
  else
    USED=$(awk '$1=="/swapfile"{print int($4/1024)}' /proc/swaps); AVAIL=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
    if [ "${USED:-0}" -ge $(( ${AVAIL:-0} - 256 )) ]; then echo "Can't resize safely now: ${USED} MB is in swap and only ${AVAIL} MB of RAM is free to take it back."; exit 1; fi
    room "$CUR" || exit 1
    echo "Resizing the swap file ${CUR} MB -> ${SIZE} MB…"
    # mk replaces the file; if the new size fails, put the old size back rather than leave no swap.
    $SUDO swapoff /swapfile || exit 1
    mk || { echo "Resize failed: restoring the ${CUR} MB swap file."; SIZE=$CUR; mk; exit 1; }
  fi
elif [ -n "$OTHER" ]; then echo 'Existing swap (not /swapfile) left as it is:'
else room 0 && mk || exit 1
fi
swapon --show
$SUDO sysctl -w vm.swappiness=10 >/dev/null 2>&1 || true
echo 'vm.swappiness=10' | $SUDO tee /etc/sysctl.d/99-swap.conf >/dev/null && echo 'swappiness=10 persisted.'
SH,
            ),
            new Recipe(
                id: 'ufw',
                label: 'Enable the firewall (UFW)',
                summary: 'Denies all inbound traffic except SSH on the ports sshd listens on and the port this connection uses (plus any extra ports you list). Outbound traffic is not limited.',
                group: RecipeGroup::Prepare,
                safety: SafetyLevel::HighRisk,
                prepareOrder: 4,
                params: [new RecipeParam('EXTRA_PORTS', 'Extra inbound ports', '443 8080/tcp', false, '/^(?:\d{1,5}(?:\/(?:tcp|udp))?|\d{1,5}:\d{1,5}\/(?:tcp|udp))(?: (?:\d{1,5}(?:\/(?:tcp|udp))?|\d{1,5}:\d{1,5}\/(?:tcp|udp)))*$/')],
                body: <<<'SH'
if ! command -v ufw >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 || { echo 'ufw is not installed, and this server has no apt-get to install it with.'; exit 1; }
  { $APT update && $APT install ufw; } || exit 1
fi
# SSH first, before any deny: sshd's own ports plus the port this connection reached on this
# server ($SSH_CONNECTION). Behind NAT that differs from $SSH_PORT; with socket activation
# (ssh.socket) it can differ from what sshd -T reports.
P=$( { $SUDO sshd -T 2>/dev/null | awk '$1=="port"{print $2}'; echo "${SSH_CONNECTION:-}" | awk '{print $4}'; } | grep -E '^[0-9]+$' | sort -un); [ -n "$P" ] || P=$SSH_PORT
for p in $P; do $SUDO ufw allow "${p}/tcp" || exit 1; done
for p in $EXTRA_PORTS; do $SUDO ufw allow "$p" || echo "skipped invalid port: $p"; done
$SUDO ufw default deny incoming >/dev/null && $SUDO ufw default allow outgoing >/dev/null || exit 1
$SUDO ufw --force enable && $SUDO ufw status verbose
SH,
            ),
            new Recipe(
                id: 'fail2ban',
                label: 'Install fail2ban',
                summary: 'Bans IPs that keep failing SSH logins, watching the ports sshd listens on.',
                group: RecipeGroup::Prepare,
                safety: SafetyLevel::Mutating,
                prepareOrder: 5,
                params: [],
                body: <<<'SH'
command -v apt-get >/dev/null 2>&1 || { echo 'This recipe needs a Debian or Ubuntu server (apt-get).'; exit 1; }
$APT update && $APT install fail2ban || exit 1
if [ -f /var/log/auth.log ]; then B=auto; else B=systemd; $APT install python3-systemd >/dev/null 2>&1 || true; fi
P=$( { $SUDO sshd -T 2>/dev/null | awk '$1=="port"{print $2}'; echo "${SSH_CONNECTION:-}" | awk '{print $4}'; } | grep -E '^[0-9]+$' | sort -un | paste -sd, -); [ -n "$P" ] || P=$SSH_PORT
printf '[sshd]\nenabled = true\nport = %s\nbackend = %s\n' "$P" "$B" | $SUDO tee /etc/fail2ban/jail.d/server-connect.conf >/dev/null || exit 1
$SUDO systemctl enable fail2ban >/dev/null 2>&1; $SUDO systemctl restart fail2ban && $SUDO systemctl --no-pager status fail2ban | head -n 5
SH,
            ),
            new Recipe(
                id: 'unattended-upgrades',
                label: 'Automatic security updates',
                summary: 'Installs and enables unattended-upgrades for security patches (no automatic reboots).',
                group: RecipeGroup::Prepare,
                safety: SafetyLevel::Mutating,
                prepareOrder: 6,
                params: [],
                body: <<<'SH'
command -v apt-get >/dev/null 2>&1 || { echo 'This recipe needs a Debian or Ubuntu server (apt-get).'; exit 1; }
$APT update && $APT install unattended-upgrades || exit 1
echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' | $SUDO debconf-set-selections
$SUDO env DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive unattended-upgrades && echo 'Automatic security updates enabled.'
SH,
            ),
            new Recipe(
                id: 'harden-ssh',
                label: 'Harden SSH (key-only logins)',
                summary: 'Turns off SSH password logins (root keys still work; a stricter PermitRootLogin is kept) with a drop-in file, validated with sshd -t before a reload (open sessions stay up) and rolled back if it does not take effect. Refuses to run until the login user has an SSH key set up.',
                group: RecipeGroup::Prepare,
                safety: SafetyLevel::HighRisk,
                prepareOrder: 7,
                params: [],
                body: <<<'SH'
if ! $SUDO grep -qiE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' /etc/ssh/sshd_config; then echo "/etc/ssh/sshd_config doesn't include /etc/ssh/sshd_config.d, so nothing was changed. Harden it by hand."; exit 1; fi
# Turning off passwords without a working key locks the user out for good: require a key line
# in one of the login user's authorized keys files (skipped when AuthorizedKeysCommand is set).
U=$(id -un); KC=$($SUDO sshd -T 2>/dev/null | awk '$1=="authorizedkeyscommand"{print $2}')
if [ -z "$KC" ] || [ "$KC" = none ]; then
  FOUND=''
  for f in $($SUDO sshd -T 2>/dev/null | awk '$1=="authorizedkeysfile"{for(i=2;i<=NF;i++)print $i}') .ssh/authorized_keys; do
    f=$(printf '%s' "$f" | sed "s|%h|$HOME|g; s|%u|$U|g; s|%%|%|g"); case "$f" in /*) ;; *) f="$HOME/$f" ;; esac
    if $SUDO grep -qE '(^|[[:space:]])(ssh-(ed25519|rsa)|ecdsa-sha2-nistp[0-9]+|sk-[a-z0-9@.-]+)[[:space:]]+AAAA' "$f" 2>/dev/null; then FOUND=1; break; fi
  done
  if [ -z "$FOUND" ]; then echo "No SSH key is set up for $U, so turning off passwords would lock you out. Nothing was changed: add a key first."; exit 1; fi
fi
F=/etc/ssh/sshd_config.d/00-server-connect.conf
# Only tighten PermitRootLogin: this file is read first, so it would override a stricter "no".
R=''; if [ "$($SUDO sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')" = yes ]; then R='PermitRootLogin prohibit-password\n'; fi
printf "# Managed by server-connect: key-only SSH logins.\n${R}PasswordAuthentication no\nKbdInteractiveAuthentication no\n" | $SUDO tee "$F" >/dev/null && $SUDO chmod 644 "$F" || { $SUDO rm -f "$F"; exit 1; }
if ! $SUDO sshd -t; then echo 'sshd rejected the new config: rolled back, nothing changed.'; $SUDO rm -f "$F"; exit 1; fi
if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
  if $SUDO systemctl reload ssh 2>/dev/null || $SUDO systemctl reload sshd 2>/dev/null; then echo 'sshd reloaded (open sessions stay connected).'; else echo 'Could not reload sshd: rolled back.'; $SUDO rm -f "$F"; exit 1; fi
else echo 'sshd applies this on its next start (socket-activated).'; fi
if ! $SUDO sshd -T 2>/dev/null | grep -qix 'passwordauthentication no'; then echo 'sshd_config sets PasswordAuthentication before the drop-in directory; edit it by hand. Rolled back.'; $SUDO rm -f "$F"; $SUDO systemctl reload ssh 2>/dev/null || $SUDO systemctl reload sshd 2>/dev/null || true; exit 1; fi
echo '--- Effective settings:'
$SUDO sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication) '
SH,
            ),
            new Recipe(
                id: 'apt-upgrade',
                label: 'Update system packages',
                summary: 'Runs apt update and upgrade (non-interactive, existing config files kept) and reports whether a reboot is required.',
                group: RecipeGroup::Update,
                safety: SafetyLevel::Mutating,
                prepareOrder: null,
                params: [],
                body: <<<'SH'
command -v apt-get >/dev/null 2>&1 || { echo 'This recipe needs a Debian or Ubuntu server (apt-get).'; exit 1; }
sc_wait_dpkg
$APT update && $APT upgrade || exit 1
echo '--- Done. Reboot required:'; test -f /var/run/reboot-required && echo yes || echo no
SH,
            ),
            new Recipe(
                id: 'reboot',
                label: 'Reboot',
                summary: 'Reboots the server now. Running jobs are interrupted; the connection drops.',
                group: RecipeGroup::Update,
                safety: SafetyLevel::HighRisk,
                prepareOrder: null,
                params: [],
                body: <<<'SH'
echo 'Rebooting now: the connection will drop.'
$SUDO systemctl reboot || $SUDO reboot
SH,
            ),
        ];

        $byId = [];

        foreach ($recipes as $recipe) {
            $byId[$recipe->id] = $recipe;
        }

        return $byId;
    }
}
