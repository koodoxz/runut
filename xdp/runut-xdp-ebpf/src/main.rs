//! RUNUT-XDP eBPF Program v0.4.4
//!
//! "THE MONSTER" - Fixed Pointer Syntax for XDP_TX.
//! Full raw pointer arithmetic for verifier-safe header rewrites.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_adjust_tail,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsResponse {
    pub ip_addr: u32,
    pub ttl: u32,
}

#[map]
static DNS_CACHE: HashMap<u64, DnsResponse> = HashMap::with_max_entries(65536, 0);

#[map]
static STATS: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

const STAT_PACKETS_TOTAL: u32 = 0;
const STAT_CFG_ENABLE_TX: u32 = 1;
const STAT_DNS_QUERIES: u32 = 2;
const STAT_CACHE_HITS: u32 = 3;
const STAT_XDP_TX: u32 = 5;
const STAT_LAST_HASH_LOW: u32 = 10;
const STAT_LAST_HASH_HIGH: u32 = 11;
const STAT_LAST_QNAME_LEN: u32 = 12;

#[xdp]
pub fn runut_xdp(ctx: XdpContext) -> u32 {
    match try_runut_xdp(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_runut_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    increment_stat(STAT_PACKETS_TOTAL);
    
    let data = ctx.data() as *mut u8;
    let data_end = ctx.data_end() as *mut u8;
    
    // 1. Min boundary check
    if unsafe { data.add(54) > data_end } { return Ok(xdp_action::XDP_PASS); }
    
    // 2. Identify DNS
    let ethertype = unsafe { u16::from_be(*(data.add(12) as *const u16)) };
    if ethertype != 0x0800 { return Ok(xdp_action::XDP_PASS); }
    
    let protocol = unsafe { *(data.add(23)) };
    if protocol != 17 { return Ok(xdp_action::XDP_PASS); }
    
    let port = unsafe { u16::from_be(*(data.add(36) as *const u16)) };
    if port != 53 { return Ok(xdp_action::XDP_PASS); }
    
    let flags = unsafe { u16::from_be(*(data.add(44) as *const u16)) };
    if (flags & 0x8000) != 0 { return Ok(xdp_action::XDP_PASS); }
    
    increment_stat(STAT_DNS_QUERIES);

    // 3. Hash QNAME and find length (case-insensitive for DNS)
    let mut hash: u64 = 0;
    let mut qname_len: usize = 0;
    for i in 0..64 {
        // Safety: check that we can read byte at position i
        // We verify i+1 is within bounds, meaning position i is safe to read
        if unsafe { data.add(54 + i) >= data_end } { break; }
        let mut byte = unsafe { *(data.add(54 + i)) };
        // DNS is case-insensitive: convert A-Z to a-z
        if byte >= b'A' && byte <= b'Z' {
            byte = byte + 32; // A(65) -> a(97), B(66) -> b(98), etc.
        }
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        if byte == 0 {
            qname_len = i + 1;
            break;
        }
    }
    if qname_len == 0 { return Ok(xdp_action::XDP_PASS); }
    
    // Debug: Store last hash for verification
    let _ = unsafe { STATS.insert(&STAT_LAST_HASH_LOW, &(hash & 0xFFFFFFFF), 0) };
    let _ = unsafe { STATS.insert(&STAT_LAST_HASH_HIGH, &(hash >> 32), 0) };
    let _ = unsafe { STATS.insert(&STAT_LAST_QNAME_LEN, &(qname_len as u64), 0) };

    
    let query_total = 54 + qname_len + 4;
    if unsafe { data.add(query_total) > data_end } { return Ok(xdp_action::XDP_PASS); }

    // 4. Cache Lookup
    if let Some(resp) = unsafe { DNS_CACHE.get(&hash) } {
        increment_stat(STAT_CACHE_HITS);

        let enable_tx = unsafe { STATS.get(&STAT_CFG_ENABLE_TX) };
        if enable_tx.is_none() || unsafe { *enable_tx.unwrap_unchecked() } == 0 {
            return Ok(xdp_action::XDP_PASS);
        }
        
        let ip_resp = resp.ip_addr;
        let ttl_resp = resp.ttl;

        // Calculate target length
        let target_len = query_total + 16;
        let current_len = (data_end as usize) - (data as usize);
        let adj = (target_len as i32) - (current_len as i32);

        // ADJUST LENGTH
        if unsafe { bpf_xdp_adjust_tail(ctx.ctx as *mut _, adj) } != 0 {
            return Ok(xdp_action::XDP_PASS);
        }

        // RE-VERIFY (MANDATORY)
        let d = ctx.data() as *mut u8;
        let de = ctx.data_end() as *mut u8;
        
        // Final boundary for the new answer we will write
        if unsafe { d.add(target_len) > de } { return Err(()); }

        // --- PERFORM WRITES ---
        unsafe {
            // Write Answer
            let ans = d.add(query_total);
            *(ans as *mut u16) = (0xc00cu16).to_be();
            *(ans.add(2) as *mut u16) = (1u16).to_be();
            *(ans.add(4) as *mut u16) = (1u16).to_be();
            *(ans.add(6) as *mut u32) = ttl_resp.to_be();
            *(ans.add(10) as *mut u16) = (4u16).to_be();
            // FIX: IP already in network byte order, write directly
            *(ans.add(12) as *mut u32) = ip_resp.to_be();

            // DNS HEADER - ZERO others to avoid malformed packets if query had OPT
            *(d.add(44) as *mut u16) = (0x8180u16).to_be(); // Flags
            *(d.add(48) as *mut u16) = (1u16).to_be();      // ANCount = 1
            *(d.add(50) as *mut u16) = 0;                  // NSCount = 0
            *(d.add(52) as *mut u16) = 0;                  // ARCount = 0

            // UDP
            let old_src_port = *(d.add(34) as *mut u16);
            let old_dst_port = *(d.add(36) as *mut u16);
            *(d.add(34) as *mut u16) = old_dst_port;
            *(d.add(36) as *mut u16) = old_src_port;
            *(d.add(38) as *mut u16) = (((target_len - 34) as u16).to_be());
            *(d.add(40) as *mut u16) = 0; // Checksum off

            // IP
            let saddr = *(d.add(26) as *mut u32);
            let daddr = *(d.add(30) as *mut u32);
            *(d.add(26) as *mut u32) = daddr;
            *(d.add(30) as *mut u32) = saddr;
            *(d.add(16) as *mut u16) = (((target_len - 14) as u16).to_be());
            *(d.add(22) as *mut u8) = 64;
            *(d.add(24) as *mut u16) = 0; // Temp Zero for checksum calc
            
            // Recalculate IPv4 Checksum
            let mut sum: u32 = 0;
            for i in 0..10 {
                sum += u16::from_be(*(d.add(14 + i * 2) as *const u16)) as u32;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            *(d.add(24) as *mut u16) = (!(sum as u16)).to_be();

            // Eth
            // Swap MACs (reply back to sender / gateway) instead of hardcoding.
            let d0 = *(d.add(0));
            let d1 = *(d.add(1));
            let d2 = *(d.add(2));
            let d3 = *(d.add(3));
            let d4 = *(d.add(4));
            let d5 = *(d.add(5));

            *(d.add(0)) = *(d.add(6));
            *(d.add(1)) = *(d.add(7));
            *(d.add(2)) = *(d.add(8));
            *(d.add(3)) = *(d.add(9));
            *(d.add(4)) = *(d.add(10));
            *(d.add(5)) = *(d.add(11));

            *(d.add(6)) = d0;
            *(d.add(7)) = d1;
            *(d.add(8)) = d2;
            *(d.add(9)) = d3;
            *(d.add(10)) = d4;
            *(d.add(11)) = d5;
        }

        increment_stat(STAT_XDP_TX);
        return Ok(xdp_action::XDP_TX);
    }



    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn increment_stat(key: u32) {
    unsafe {
        if let Some(val) = STATS.get(&key) {
            let new_val = *val + 1;
            let _ = STATS.insert(&key, &new_val, 0);
        } else {
            let one: u64 = 1;
            let _ = STATS.insert(&key, &one, 0);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

