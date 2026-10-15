#!/bin/bash
# isolate-host.sh — Wazuh Active Response: isolate THIS host from the network.
#
# Deployed to the agent's /var/ossec/active-response/bin/ (root-owned) and invoked
# two ways:
#   * by wazuh-execd with the AR JSON message on stdin — command "add"/"enable"
#     isolates, "delete"/"disable" reverts when the stateful timeout expires;
#   * directly with --undo, by the self-expiry timer this script arms on isolate.
#
# WHY THE GUARDRAILS LIVE HERE AND NOT IN THE SOAR
# The allowlist and the TTL are in this file, on the endpoint, owned by root. The SOAR
# asks Wazuh to run it; it cannot pass a different allowlist, cannot remove the TTL, and
# cannot isolate any host but the one the manager targets. So a compromised or
# misconfigured SOAR still cannot lock an operator out of a machine.
#
# Isolation policy: allow loopback, the management addresses, and established
# connections; DROP everything else in both directions.
#
# Tunables — read from the site file below, never from the caller:
#   /var/ossec/etc/minisoar-isolate.conf  ->  MINISOAR_ISOLATE_ALLOW, MINISOAR_ISOLATE_TTL

set -u

LOG=/var/ossec/logs/active-responses.log
CHAIN=MINISOAR_ISOLATE
UNIT=minisoar-unisolate

# Site values live OUTSIDE this script. The allowlist is site-specific and it goes STALE:
# the first dry run of this test found the management host's DHCP address had already moved
# (10.194.156.73 -> 10.194.157.19), so a hard-coded control IP would have cut the only way
# back in. Keep literals out of the deployed file.
CONF=/var/ossec/etc/minisoar-isolate.conf
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"

TTL=${MINISOAR_ISOLATE_TTL:-1800}
# The manager MUST be in the allowlist, or the host can never be un-isolated and its own
# telemetry stops. Everything else is cut — that is the point.
ALLOW_IPS=${MINISOAR_ISOLATE_ALLOW:-"10.10.221.18"}
SELF=$(readlink -f "$0")

log() { echo "$(date -Is) isolate-host: $*" >> "$LOG"; }

if [ -z "${ALLOW_IPS// /}" ]; then
    log "REFUSING: empty allowlist — isolation would be unrecoverable"
    exit 1
fi

isolated() { iptables -C INPUT -j "$CHAIN" >/dev/null 2>&1; }

# arm_self_expiry schedules the revert ON THIS HOST, so recovery does not depend on the
# manager ever calling back. The unit name is UNIQUE per run: with a fixed name a second run
# collides with the previous transient unit and systemd-run refuses — which is exactly how
# end-host2 ended up isolated with NO TTL and only a WARN in the log.
arm_self_expiry() {
    EXPIRY_UNIT="minisoar-unisolate-$(date +%s)-$$"
    systemd-run --on-active="${TTL}s" --collect --unit="$EXPIRY_UNIT" "$SELF" --undo \
        >/dev/null 2>&1 || return 1
    # Arming is a claim until verified: confirm systemd really scheduled it.
    systemctl is-active --quiet "$EXPIRY_UNIT.timer" || return 1
    return 0
}

do_isolate() {
    if isolated; then log "already isolated, nothing to do"; return 0; fi
    # FAIL SAFE. A host that cannot be un-isolated is worse than a host left un-isolated, so
    # the expiry is armed AND verified BEFORE any rule is applied. If it cannot be armed we
    # refuse and say so, rather than cutting a machine off with no way back.
    if ! arm_self_expiry; then
        log "REFUSING to isolate: self-expiry could not be armed (host would be unrecoverable)"
        echo "isolate-host: refusing to isolate - self-expiry could not be armed" >&2
        exit 1
    fi
    iptables -N "$CHAIN" 2>/dev/null
    iptables -F "$CHAIN"
    iptables -A "$CHAIN" -i lo -j ACCEPT
    iptables -A "$CHAIN" -o lo -j ACCEPT
    for ip in $ALLOW_IPS; do
        iptables -A "$CHAIN" -s "$ip" -j ACCEPT
        iptables -A "$CHAIN" -d "$ip" -j ACCEPT
    done
    iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$CHAIN" -j DROP
    iptables -I INPUT   1 -j "$CHAIN"
    iptables -I OUTPUT  1 -j "$CHAIN"
    iptables -I FORWARD 1 -j "$CHAIN"
    log "ISOLATED — allow=[$ALLOW_IPS] ttl=${TTL}s expiry=$EXPIRY_UNIT"
}

do_undo() {
    if ! isolated; then log "not isolated, nothing to undo"; return 0; fi
    iptables -D INPUT   -j "$CHAIN" 2>/dev/null
    iptables -D OUTPUT  -j "$CHAIN" 2>/dev/null
    iptables -D FORWARD -j "$CHAIN" 2>/dev/null
    iptables -F "$CHAIN" 2>/dev/null
    iptables -X "$CHAIN" 2>/dev/null
    # Cancel any expiry timer still armed for this host. Names carry the run's timestamp, so
    # match by prefix rather than by one fixed name.
    systemctl list-units --all --plain --no-legend --type=timer 'minisoar-unisolate*' 2>/dev/null \
        | awk '{print $1}' | while read -r u; do systemctl stop "$u" >/dev/null 2>&1; done
    log "ISOLATION LIFTED"
}

# ---------------------------------------------------------------- entry points
if [ "${1:-}" = "--undo" ]; then
    do_undo
    exit 0
fi

MSG=$(cat)
CMD=$(printf '%s' "$MSG" | tr -d ' \n' | grep -oE '"command":"[a-z]+"' | head -1 | cut -d'"' -f4)
case "$CMD" in
    add | enable)    do_isolate ;;
    delete | disable) do_undo ;;
    *) log "unknown command '${CMD:-<none>}' — message: $(printf '%s' "$MSG" | head -c 200)"
       exit 1 ;;
esac
