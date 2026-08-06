#!/bin/bash
# MIMIR Custom Blocklist Manager
# Usage:
#   mimir-block add domain.com    - Add domain to blocklist
#   mimir-block remove domain.com - Remove domain from blocklist  
#   mimir-block list              - List all blocked domains
#   mimir-block reload            - Reload MIMIR to apply changes

BLOCKLIST=/opt/mimir/blocklist/custom.txt

case "$1" in
    add)
        if [ -z "$2" ]; then
            echo "Usage: mimir-block add domain.com"
            exit 1
        fi
        echo "$2" | sudo tee -a $BLOCKLIST
        echo "Added: $2"
        echo "Run 'mimir-block reload' to apply"
        ;;
    remove)
        if [ -z "$2" ]; then
            echo "Usage: mimir-block remove domain.com"
            exit 1
        fi
        sudo sed -i "/^$2$/d" $BLOCKLIST
        echo "Removed: $2"
        echo "Run 'mimir-block reload' to apply"
        ;;
    list)
        echo "=== Blocked Domains ==="
        grep -v '^#' $BLOCKLIST | grep -v '^$'
        ;;
    reload)
        echo "Restarting MIMIR to reload blocklist..."
        sudo systemctl restart mimir-rs
        echo "Done!"
        ;;
    *)
        echo "MIMIR Custom Blocklist Manager"
        echo "Usage: mimir-block [add|remove|list|reload] [domain]"
        ;;
esac
