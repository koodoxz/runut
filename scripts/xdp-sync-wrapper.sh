#!/bin/bash
# Dynamic XDP Sync wrapper - auto-detects DNS_CACHE map ID
# Prevents hardcoded map ID issues after service restarts

CACHE_ID=$(bpftool map list 2>/dev/null | grep DNS_CACHE | tail -1 | awk '{print $1}' | tr -d ':')

if [ -z "$CACHE_ID" ]; then
    echo "❌ ERROR: DNS_CACHE map not found"
    echo "Waiting 5s for maps to be created..."
    sleep 5
    CACHE_ID=$(bpftool map list 2>/dev/null | grep DNS_CACHE | tail -1 | awk '{print $1}' | tr -d ':')
    if [ -z "$CACHE_ID" ]; then
        echo "❌ ERROR: DNS_CACHE map still not found after retry"
        exit 1
    fi
fi

echo "✅ Starting XDP Sync with DNS_CACHE map ID $CACHE_ID"
exec /opt/mimir-xdp/xdp-sync-v5 --map-id $CACHE_ID --sync-addr 127.0.0.1:9154 --stats-interval 30
