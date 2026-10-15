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
# Tunables (env, set by the AR config or systemd, not by the caller):
#   MINISOAR_ISOLATE_ALLOW  space-separated allowlist
#   MINISOAR_ISOLATE_TTL    seconds before the self-expiry lifts it (default 1800)

set -u

LOG=/var/ossec/logs/active-responses.log
CHAIN=MINISOAR_ISOLATE
UNIT=minisoar-unisolate
TTL=${MINISOAR_ISOLATE_TTL:-1800}
# The manager MUST be here or the host can never be un-isolated and its own telemetry
# stops. The control host is here so an operator can still reach it deliberately.
ALLOW_IPS=${MINISOAR_ISOLATE_ALLOW:-"10.10.221.18 10.194.156.73"}
SELF=$(readlink -f "$0")

log() { echo "$(date -Is) isolate-host: $*" >> "$LOG"; }

if [ -z "${ALLOW_IPS// /}" ]; then
    log "REFUSING: empty allowlist — isolation would be unrecoverable"
    exit 1
fi

isolated() { iptables -C INPUT -j "$CHAIN" >/dev/null 2>&1; }

do_isolate() {
    if isolated; then log "already isolated, nothing to do"; return 0; fi
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
    log "ISOLATED — allow=[$ALLOW_IPS] ttl=${TTL}s"
    # Self-expiry, independent of the manager. If the revert call never arrives the
    # host must not stay cut off; systemd-run outlives this script.
    systemd-run --on-active="${TTL}s" --collect --unit="$UNIT" "$SELF" --undo \
        >/dev/null 2>&1 || log "WARN: could not arm the self-expiry timer"
}

do_undo() {
    if ! isolated; then log "not isolated, nothing to undo"; return 0; fi
    iptables -D INPUT   -j "$CHAIN" 2>/dev/null
    iptables -D OUTPUT  -j "$CHAIN" 2>/dev/null
    iptables -D FORWARD -j "$CHAIN" 2>/dev/null
    iptables -F "$CHAIN" 2>/dev/null
    iptables -X "$CHAIN" 2>/dev/null
    systemctl stop "$UNIT.timer" 2>/dev/null
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
