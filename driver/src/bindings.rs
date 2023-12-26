use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicBool, Ordering},
};

use libc::c_int;

/*
 * HIDS driver types
 */

pub const RING_KMOD: c_int = 0x5254004B as _; /* kmod */
pub const RING_EBPF: c_int = 0x52540045 as _; /* ebpf */

/*
 * access-control for allowlist / blocklist
 */

/* allowlist filters */
pub const AL_TYPE_ARGV: c_int = 0xA1;
pub const AL_TYPE_EXE: c_int = 0xA2;
pub const AL_TYPE_PSAD: c_int = 0xA3;

/* blocklist types */
pub const BL_JSON_DNS: c_int = 0xB0;
pub const BL_JSON_EXE: c_int = 0xB1;
pub const BL_JSON_MD5: c_int = 0xB2;

pub extern "C" fn read_atomic_bool(value: *const AtomicBool) -> c_int {
    unsafe { (*value).load(Ordering::SeqCst) as c_int }
}
extern "C" {
    pub fn tb_init_ring(arg_type: c_int, arg_control: *const u8) -> c_int;
    pub fn tb_fini_ring();
    pub fn tb_pre_unload();
    pub fn tb_read_ring(
        msg: *const u8,
        len: c_int,
        cb: extern "C" fn(*const AtomicBool) -> c_int,
        ctx: *const AtomicBool,
    ) -> c_int;

    pub fn ac_init(ring_type: c_int, arg_control: *const u8) -> c_int;
    pub fn ac_fini(ring_type: c_int);

    /* 设置规则，支持list或json格式 */
    pub fn ac_setup(ac: c_int, ptr: *const u8, len: c_int) -> c_int;

    /* 清除特定类型的所有规则 */
    pub fn ac_clear(ac: c_int) -> c_int;

    /* 检测规则生效与否，仅适用于allowlist */
    pub fn ac_check(ac: c_int, ptr: *const u8, len: c_int) -> c_int;

    /* 删除特定规则，仅适用于allowlist */
    pub fn ac_erase(ac: c_int, ptr: *const u8, len: c_int) -> c_int;

    /* 读取当前所有规则，目前仅适用于allowlist */
    pub fn ac_query(ac: c_int, ptr: *const u8, len: c_int) -> c_int;
}

pub const ENABLE_PSAD_SWITHER: &[u8] = b"Y";
pub const DISABLE_PSAD_SWITHER: &[u8] = b"N";

// PSAD
pub const PSAD_FLAG_NUL: usize = 0x80;
pub const PSAD_FLAG_FIN: usize = 0x100;
pub const PSAD_FLAG_SYN: usize = 0x200;
pub const PSAD_FLAG_RST: usize = 0x400;
pub const PSAD_FLAG_PSH: usize = 0x800;
pub const PSAD_FLAG_ACK: usize = 0x1000;
pub const PSAD_FLAG_URG: usize = 0x2000;

pub fn gen_psad_flag(flags: &Vec<usize>) -> String {
    return format!(
        "0x{:x}",
        flags.iter().sum::<usize>()
            & (PSAD_FLAG_NUL
                | PSAD_FLAG_FIN
                | PSAD_FLAG_SYN
                | PSAD_FLAG_RST
                | PSAD_FLAG_PSH
                | PSAD_FLAG_ACK
                | PSAD_FLAG_URG)
    );
}

pub fn gen_psad_ipv4_allowlist(org: &Vec<String>) -> Vec<u32> {
    let t: Vec<u32> = org
        .into_iter()
        .map(|f| {
            let ip: u32 = f.parse::<Ipv4Addr>().unwrap().into();
            u32::from_le_bytes(ip.to_be_bytes())
        })
        .collect();

    let mut buffer: Vec<u32> = vec![0u32; 2 + t.len()]; //Vec::with_capacity(2 + t.len());

    buffer[0] = 4;
    buffer[1] = t.len() as u32;
    for i in 2..=t.len() + 1 {
        buffer[i] = t[i - 2]
    }
    return buffer;
}

pub fn gen_psad_ipv6_allowlist(org: &Vec<String>) -> Vec<u32> {
    let mut tmpv = Vec::new();
    let mut ips = 0;
    for each in org {
        let ip: Ipv6Addr = each.parse::<Ipv6Addr>().unwrap();
        let buf = ipv6_to_u32buf(&ip);
        tmpv.extend(buf);
        ips += 1;
    }
    let mut buffer: Vec<u32> = vec![0u32; 2 + tmpv.len()];
    buffer[0] = 10;
    buffer[1] = ips as u32;
    for i in 2..=tmpv.len() + 1 {
        buffer[i] = tmpv[i - 2]
    }
    return buffer;
}

pub fn ipv6_to_u32buf(ipv6: &Ipv6Addr) -> [u32; 4] {
    let mut raw_bufn: [u32; 4] = [0; 4];
    for i in 0..4 {
        raw_bufn[i] = (u16::from_le_bytes(ipv6.segments()[i * 2].to_be_bytes()) as u32)
            | ((u16::from_le_bytes(ipv6.segments()[i * 2 + 1].to_be_bytes()) as u32) << 16);
    }
    return raw_bufn;
}
