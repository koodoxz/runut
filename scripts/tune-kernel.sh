#!/bin/bash
# MIMIR-RS Linux Kernel Tuning Script
# Optimizes network stack for ultra-fast DNS performance
#
# Run as root: sudo ./tune-kernel.sh

echo "🔥 MIMIR-RS Kernel Tuning Script"
echo "================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo ""
echo ">>> Tuning Network Stack..."

# Increase UDP/TCP buffer sizes
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.rmem_default=1048576
sysctl -w net.core.wmem_max=26214400
sysctl -w net.core.wmem_default=1048576

# Increase connection backlog
sysctl -w net.core.netdev_max_backlog=30000
sysctl -w net.core.somaxconn=65535

# UDP specific tuning
sysctl -w net.ipv4.udp_rmem_min=16384
sysctl -w net.ipv4.udp_wmem_min=16384

# Increase local port range
sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# Enable TCP Fast Open
sysctl -w net.ipv4.tcp_fastopen=3

# Reduce TIME_WAIT sockets
sysctl -w net.ipv4.tcp_tw_reuse=1

echo ""
echo ">>> Tuning File Descriptors..."

# Increase file descriptors
ulimit -n 1048576

# Check current limits
echo ""
echo "Current ulimit: $(ulimit -n)"
echo ""

# Persist settings
echo ""
echo ">>> Persisting Settings..."

cat >> /etc/sysctl.conf << 'EOF'

# MIMIR-RS Performance Tuning
net.core.rmem_max=26214400
net.core.rmem_default=1048576
net.core.wmem_max=26214400
net.core.wmem_default=1048576
net.core.netdev_max_backlog=30000
net.core.somaxconn=65535
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_tw_reuse=1
EOF

# Add file descriptor limits
cat >> /etc/security/limits.conf << 'EOF'

# MIMIR-RS File Descriptor Limits
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

echo ""
echo "✅ Kernel tuning complete!"
echo ""
echo "Recommended MIMIR-RS start command:"
echo "  sudo ./mimir --workers \$(nproc) --listen 0.0.0.0:53"
echo ""
echo "For multi-core VPS:"
echo "  2 cores: ~60K QPS"
echo "  4 cores: ~100K+ QPS"
echo "  8 cores: ~200K+ QPS"
echo ""
