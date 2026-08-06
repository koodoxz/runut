#!/bin/bash
# XDP Stability Check - Prevent duplicate external XDP loader services
# Run: ./xdp-stability-check.sh
# Cron: */15 * * * * /path/to/xdp-stability-check.sh
#
# NOTE: "xdp-loader" / "xdp-loader-rs" below are placeholder service names
# for whatever separate XDP program loader you run alongside mimir (e.g. a
# firewall/DDoS XDP loader). Rename to match your actual systemd unit(s).

echo "=== XDP Stability Check - $(date) ==="

# Count running external XDP loader services
LOADER_COUNT=$(systemctl list-units --type=service --state=running | grep -c xdp-loader)

if [ $LOADER_COUNT -gt 1 ]; then
    echo "⚠️ WARNING: Multiple XDP loader services detected ($LOADER_COUNT)"

    # List all XDP loader services
    systemctl list-units --type=service --state=running | grep xdp-loader

    # Check which ones are enabled
    echo ""
    echo "Enabled status:"
    systemctl is-enabled xdp-loader xdp-loader-rs 2>&1

    # Count XDP programs
    XDP_COUNT=$(sudo bpftool prog list | grep -c -E 'xdp-loader|mimir')
    echo ""
    echo "XDP programs attached: $XDP_COUNT (expected: 2)"

    if [ $XDP_COUNT -gt 2 ]; then
        echo "❌ ERROR: Too many XDP programs!"
        echo "ACTION REQUIRED: Stop duplicate XDP loader service"

        # Auto-fix: Stop non-enabled service
        if systemctl is-enabled xdp-loader-rs &>/dev/null; then
            echo "Stopping xdp-loader.service (xdp-loader-rs is enabled)..."
            sudo systemctl stop xdp-loader
        else
            echo "Stopping xdp-loader-rs.service (xdp-loader is enabled)..."
            sudo systemctl stop xdp-loader-rs
            sudo systemctl disable xdp-loader-rs
        fi
    fi
else
    echo "✅ OK: Single XDP loader service running"
    XDP_COUNT=$(sudo bpftool prog list | grep -c -E 'xdp-loader|mimir')
    echo "✅ XDP programs: $XDP_COUNT"
fi

# Check DNS functionality
DNS_TEST=$(timeout 3 dig @127.0.0.1 google.com +short 2>/dev/null | head -1)
if [ -n "$DNS_TEST" ]; then
    echo "✅ DNS: Working ($DNS_TEST)"
else
    echo "❌ DNS: FAILED"
fi

echo ""
