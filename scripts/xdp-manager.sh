#!/bin/bash
# MIMIR XDP Autonomous Manager v1.0
# Automatically handles all XDP setup after the external XDP loader restarts
# No manual intervention needed!

LOG_TAG="XDP-MANAGER"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$LOG_TAG] $1"
}

log "Starting MIMIR XDP Autonomous Manager..."
log "Waiting for external XDP loader maps to be ready..."
sleep 5

# Auto-detect map IDs
DNS_CACHE_ID=$(bpftool map list 2>/dev/null | grep DNS_CACHE | tail -1 | awk '{print $1}' | tr -d ':')
STATS_ID=$(bpftool map list 2>/dev/null | grep -E '^[0-9]+:.*hash.*name STATS' | tail -1 | awk '{print $1}' | tr -d ':')

if [ -z "$DNS_CACHE_ID" ] || [ -z "$STATS_ID" ]; then
    log "ERROR: Could not detect map IDs! DNS_CACHE=$DNS_CACHE_ID STATS=$STATS_ID"
    log "Retrying in 5 seconds..."
    sleep 5
    DNS_CACHE_ID=$(bpftool map list 2>/dev/null | grep DNS_CACHE | tail -1 | awk '{print $1}' | tr -d ':')
    STATS_ID=$(bpftool map list 2>/dev/null | grep -E '^[0-9]+:.*hash.*name STATS' | tail -1 | awk '{print $1}' | tr -d ':')
    
    if [ -z "$DNS_CACHE_ID" ] || [ -z "$STATS_ID" ]; then
        log "FATAL: Still cannot detect map IDs after retry. Exiting."
        exit 1
    fi
fi

log "Detected map IDs: DNS_CACHE=$DNS_CACHE_ID STATS=$STATS_ID"

# Enable XDP_TX automatically
log "Enabling XDP_TX on STATS map $STATS_ID..."
bpftool map update id $STATS_ID key 0x01 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00
if [ $? -eq 0 ]; then
    log "XDP_TX enabled successfully!"
else
    log "WARNING: Failed to enable XDP_TX"
fi

# Pre-warm cache with popular domains (background)
log "Pre-warming cache with popular domains..."
(
    sleep 10
    for domain in google.com facebook.com youtube.com twitter.com instagram.com linkedin.com github.com cloudflare.com amazon.com microsoft.com apple.com netflix.com reddit.com yahoo.com wikipedia.org; do
        dig @127.0.0.1 $domain +short > /dev/null 2>&1
    done
    log "Cache pre-warm complete (15 domains)"
) &

# Start XDP sync with correct map ID
log "Starting XDP Sync Bridge with map ID $DNS_CACHE_ID..."
exec /opt/mimir-xdp/xdp-sync-v5 --map-id $DNS_CACHE_ID --sync-addr 127.0.0.1:9154 --stats-interval 30
