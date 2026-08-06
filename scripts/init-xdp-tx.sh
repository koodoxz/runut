#!/bin/bash
# Auto-set XDP_TX flag on external XDP loader startup
# Retry up to 10 times with 2s intervals (20s total window)
# NEVER exit non-zero - don't kill the XDP loader over this

MAX_ATTEMPTS=10
WAIT_SEC=2

for i in $(seq 1 $MAX_ATTEMPTS); do
    STATS_ID=$(bpftool map list 2>/dev/null | grep -A1 'name STATS' | grep hash | tail -1 | awk '{print $1}' | tr -d ':')
    if [ -n "$STATS_ID" ]; then
        bpftool map update id $STATS_ID key 0x01 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        if [ $? -eq 0 ]; then
            echo "XDP_TX flag enabled on STATS map ID $STATS_ID (attempt $i)"
            exit 0
        fi
    fi
    echo "STATS map not ready, waiting ${WAIT_SEC}s... (attempt $i/$MAX_ATTEMPTS)"
    sleep $WAIT_SEC
done

echo "WARNING: Could not set XDP_TX flag after $MAX_ATTEMPTS attempts"
exit 0
