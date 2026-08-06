#!/usr/bin/env python3
"""MIMIR-XDP Sync Bridge - Python version with correct byte order"""
import socket
import struct
import ctypes
import os
import sys
import time

# BPF syscall constants
SYS_BPF = 321  # x86_64
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_GET_FD_BY_ID = 29
BPF_ANY = 0

libc = ctypes.CDLL('libc.so.6', use_errno=True)

class bpf_attr_get_fd(ctypes.Structure):
    _fields_ = [
        ('map_id', ctypes.c_uint32),
        ('next_id', ctypes.c_uint32),
        ('open_flags', ctypes.c_uint32),
    ]

class bpf_attr_update(ctypes.Structure):
    _fields_ = [
        ('map_fd', ctypes.c_uint32),
        ('pad0', ctypes.c_uint32),
        ('key', ctypes.c_uint64),
        ('value_or_next_key', ctypes.c_uint64),
        ('flags', ctypes.c_uint64),
    ]

def bpf_syscall(cmd, attr, size):
    return libc.syscall(SYS_BPF, cmd, ctypes.byref(attr), size)

def get_map_fd_by_id(map_id):
    attr = bpf_attr_get_fd()
    attr.map_id = map_id
    fd = bpf_syscall(BPF_MAP_GET_FD_BY_ID, attr, ctypes.sizeof(attr))
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"BPF_MAP_GET_FD_BY_ID failed: {os.strerror(errno)}")
    return fd

def get_map_fd_by_path(path):
    """Open pinned BPF map by filesystem path"""
    fd = os.open(path, os.O_RDWR)
    return fd

def map_update(map_fd, key, value):
    key_buf = (ctypes.c_uint8 * 8)(*struct.pack('<Q', key))
    val_buf = (ctypes.c_uint8 * 8)(*value)
    
    attr = bpf_attr_update()
    attr.map_fd = map_fd
    attr.key = ctypes.addressof(key_buf)
    attr.value_or_next_key = ctypes.addressof(val_buf)
    attr.flags = BPF_ANY
    
    ret = bpf_syscall(BPF_MAP_UPDATE_ELEM, attr, ctypes.sizeof(attr))
    return ret >= 0

def main():
    if len(sys.argv) < 2:
        print("Usage: xdp-sync-fix.py <map_path_or_id> [sync_addr]")
        sys.exit(1)
    
    map_arg = sys.argv[1]
    sync_addr = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1:9154"
    host, port = sync_addr.rsplit(':', 1)
    
    print(f"🚀 MIMIR-XDP Sync Bridge v1.0 (Python)")
    
    # Try path first, then ID
    if map_arg.startswith('/'):
        print(f"📦 Opening pinned map: {map_arg}")
        map_fd = get_map_fd_by_path(map_arg)
    else:
        map_id = int(map_arg)
        print(f"📦 Connecting to DNS_CACHE map ID: {map_id}")
        map_fd = get_map_fd_by_id(map_id)
    
    print(f"✅ Got map FD: {map_fd}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, int(port)))
    print(f"🔗 Listening on: {sync_addr}")
    print(f"🎯 Ready to sync DNS cache entries...\n")
    
    sync_count = 0
    last_stats = time.time()
    
    while True:
        try:
            data, addr = sock.recvfrom(64)
            if len(data) >= 16:
                # Packet: [hash:8][ip:4][ttl:4]
                hash_val = struct.unpack('<Q', data[0:8])[0]
                # CRITICAL FIX: IP in big-endian (network byte order)
                ip = struct.unpack('>I', data[8:12])[0]
                ttl = struct.unpack('<I', data[12:16])[0]
                
                # Value: [ip:4][ttl:4] - IP already in correct order
                value = struct.pack('<II', ip, ttl)
                
                if map_update(map_fd, hash_val, value):
                    sync_count += 1
        except Exception as e:
            print(f"❌ Error: {e}")
        
        if time.time() - last_stats >= 30:
            print(f"📊 Synced {sync_count} entries in last 30s")
            sync_count = 0
            last_stats = time.time()

if __name__ == '__main__':
    main()
