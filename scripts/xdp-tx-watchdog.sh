#!/bin/bash
# XDP_TX Flag Watchdog - ensures flag is always set
# Runs as a persistent service, checks every 60s

CHECK_INTERVAL=60

while true; do
    STATS_ID=$(bpftool map list 2>/dev/null | grep -A1 'name STATS' | grep hash | tail -1 | awk '{print $1}' | tr -d ':')
    if [ -n "$STATS_ID" ]; then
        CURRENT=$(bpftool map lookup id $STATS_ID key 0x01 0x00 0x00 0x00 2>/dev/null | grep -c 'value: 01')
        if [ "$CURRENT" -eq 0 ] 2>/dev/null; then
            bpftool map update id $STATS_ID key 0x01 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) XDP_TX flag restored on STATS map $STATS_ID"
        fi
    fi
    sleep $CHECK_INTERVAL
done
