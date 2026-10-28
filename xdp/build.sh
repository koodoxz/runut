#!/bin/bash
# RUNUT-XDP Build Script
# Builds both eBPF and userspace components

set -e

echo "🔥 Building RUNUT-XDP..."
echo ""

# Check for required tools
echo "Checking dependencies..."
command -v cargo >/dev/null 2>&1 || { echo "cargo not found. Install Rust first."; exit 1; }
command -v clang >/dev/null 2>&1 || { echo "clang not found. Install clang."; exit 1; }

# Install bpf-linker if not present
if ! command -v bpf-linker &> /dev/null; then
    echo "Installing bpf-linker..."
    cargo install bpf-linker
fi

# Add eBPF target if not present
echo "Adding eBPF target..."
rustup target add bpfel-unknown-none 2>/dev/null || true

echo ""
echo ">>> Building eBPF program..."
cd runut-xdp-ebpf
cargo build --release --target bpfel-unknown-none -Z build-std=core
cd ..

echo ""
echo ">>> Building userspace loader..."
cd runut-xdp
cargo build --release
cd ..

echo ""
echo "✅ Build complete!"
echo ""
echo "Binaries:"
echo "  eBPF:      target/bpfel-unknown-none/release/runut-xdp-ebpf"
echo "  Loader:    runut-xdp/target/release/runut-xdp"
echo ""
echo "Usage:"
echo "  sudo ./runut-xdp/target/release/runut-xdp --interface eth0 --mode native"
echo ""
