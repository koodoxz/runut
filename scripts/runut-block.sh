#!/bin/bash
# RUNUT Custom Blocklist Manager
# Usage:
#   runut-block add domain.com    - Add domain to blocklist
#   runut-block remove domain.com - Remove domain from blocklist  
#   runut-block list              - List all blocked domains
#   runut-block reload            - Reload RUNUT to apply changes

BLOCKLIST=/opt/runut/blocklist/custom.txt

case "$1" in
    add)
        if [ -z "$2" ]; then
            echo "Usage: runut-block add domain.com"
            exit 1
        fi
        echo "$2" | sudo tee -a $BLOCKLIST
        echo "Added: $2"
        echo "Run 'runut-block reload' to apply"
        ;;
    remove)
        if [ -z "$2" ]; then
            echo "Usage: runut-block remove domain.com"
            exit 1
        fi
        sudo sed -i "/^$2$/d" $BLOCKLIST
        echo "Removed: $2"
        echo "Run 'runut-block reload' to apply"
        ;;
    list)
        echo "=== Blocked Domains ==="
        grep -v '^#' $BLOCKLIST | grep -v '^$'
        ;;
    reload)
        echo "Restarting RUNUT to reload blocklist..."
        sudo systemctl restart runut
        echo "Done!"
        ;;
    *)
        echo "RUNUT Custom Blocklist Manager"
        echo "Usage: runut-block [add|remove|list|reload] [domain]"
        ;;
esac
