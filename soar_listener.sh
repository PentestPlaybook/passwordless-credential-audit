#!/bin/sh
#
# soar_listener.sh — WiFi Pineapple Pager
#
# Receives security alert messages from the Aurora SOAR pipeline over a plain
# TCP connection (port 9999) and triggers a DuckyScript ALERT + VIBRATE.
#
# No SSH required. The Aurora sends a single-line message via TCP. This script
# pipes it to syslog via logger, and a logread -f watcher triggers the alert.
#
# Layer stack (inbound):
#   Aurora PowerShell TcpClient (L7) → TCP (L4) → IP/Tailscale (L3) → L1/2
#   → this script → logger → syslog → logread → DuckyScript ALERT
#
# USAGE:
#   Copy to /root/scripts/soar_listener.sh
#   chmod +x /root/scripts/soar_listener.sh
#   Add to /etc/rc.local or run as a background service
#
# DEPENDENCIES:
#   nc (busybox netcat), logger, logread — all present on OpenWrt by default

PORT=9999
LOG_TAG="SOAR-ALERT"

# ── Resolve DuckyScript runtime ───────────────────────────────────────────────
# Try known command names for the Pager's DuckyScript runtime.
# Run `which pager-run` or check /usr/bin on your device to confirm.
find_runtime() {
    for cmd in pager-run pager_run ducky-run alert; do
        if command -v "$cmd" > /dev/null 2>&1; then
            echo "$cmd"
            return
        fi
    done
    echo ""
}

RUNTIME=$(find_runtime)
PAYLOAD_DIR="/root/payloads/alerts"

trigger_alert() {
    MSG="$1"

    # ── Route by message prefix to the appropriate payload ────────────────────
    # EXCLUSION_ADDED messages use the dedicated exclusion alert payload,
    # which prompts the operator to verify the exclusion was intentional.
    case "$MSG" in
        EXCLUSION_ADDED:*)
            FILENAME=$(echo "$MSG" | sed 's/EXCLUSION_ADDED: //' | cut -d'|' -f1 | xargs)
            if [ -n "$RUNTIME" ] && [ -f "$PAYLOAD_DIR/exclusion/payload.ds" ]; then
                $RUNTIME "$PAYLOAD_DIR/exclusion/payload.ds" 2>/dev/null && return
            fi
            # Fallback: inline DuckyScript if payload file not found
            if [ -n "$RUNTIME" ]; then
                printf 'ALERT "DEFENDER EXCLUSION ADDED"\nDELAY 1500\nALERT "%s"\nDELAY 1500\nALERT "Verify this was intentional"\nVIBRATE 2\n' \
                    "$FILENAME" | $RUNTIME --stdin 2>/dev/null && return
            fi
            ;;
        *)
            # All other alerts: generic inline DuckyScript
            if [ -n "$RUNTIME" ]; then
                printf 'ALERT "%s"\nVIBRATE 3\n' "$MSG" | $RUNTIME --stdin 2>/dev/null && return
            fi
            ;;
    esac

    # Final fallback: log only
    logger -t "$LOG_TAG" "DISPLAY UNAVAILABLE: $MSG"
}

# ── Start syslog watcher ──────────────────────────────────────────────────────
# Watches syslog for lines tagged SOAR-ALERT and triggers the Pager display.
logread -f | grep --line-buffered "$LOG_TAG" | while IFS= read -r line; do
    MSG=$(echo "$line" | sed "s/.*$LOG_TAG: //")
    trigger_alert "$MSG"
done &

WATCHER_PID=$!
logger -t "$LOG_TAG" "Syslog watcher started (PID $WATCHER_PID)"

# ── Start TCP listener ────────────────────────────────────────────────────────
# Listens on port 9999. Each received line is written to syslog,
# which the watcher above picks up and routes to the Pager display.
logger -t "$LOG_TAG" "TCP listener starting on port $PORT"

while true; do
    nc -l -p $PORT | while IFS= read -r line; do
        [ -z "$line" ] && continue
        logger -t "$LOG_TAG" "$line"
    done
done
