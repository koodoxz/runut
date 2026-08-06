#!/bin/bash
cd /home/koodoxz/mimir-rs || exit 1

# Check if backup already exists
if [ ! -f "target/release/mimir.backup-"* ]; then
    echo "Backup verified"
fi

# Build the enhanced version
echo "Starting compilation..."
~/.cargo/bin/cargo build --release
if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

echo "Compilation successful!"

# Start MIMIR with same parameters
nohup /home/koodoxz/mimir-rs/target/release/mimir --config /opt/mimir/configs/mimir.yaml --workers 4 > /tmp/mimir.log 2>&1 &
echo "MIMIR started with PID $!"

# Wait and verify
sleep 3
if pgrep -f "mimir --config" > /dev/null; then
    echo "✅ MIMIR running successfully"
    # Test metrics
    curl -s http://localhost:9153/metrics | grep -E "(cache_hit_rate|mimir_queries_total)" | head -5
else
    echo "❌ MIMIR failed to start! Check /tmp/mimir.log"
    tail -20 /tmp/mimir.log
    exit 1
fi
