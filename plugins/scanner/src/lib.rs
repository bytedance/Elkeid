//#![feature(static_nobundle)]
#![allow(warnings)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::{
    ffi::{c_void, CStr, CString},
    hash::Hasher,
    io::{ErrorKind, Read, Seek, SeekFrom},
    path::Path,
    ptr, thread, time,
};

use cgroups_rs::{self, Controller};
use infer::MatcherType;


pub mod configs;
pub mod detector;
pub mod filter;
pub mod model;

pub trait ToAgentRecord {
    fn to_record(&self) -> plugins::Record;
    fn to_record_token(&self, token: &str) -> plugins::Record;
}

pub fn get_file_xhash(fpath: &str) -> String {
    let mut hasher = twox_hash::XxHash64::default();
    let mut buffer = Vec::with_capacity(32 * 1024);
    if let Ok(file) = std::fs::File::open(fpath) {
        if let Ok(metadata) = file.metadata() {
            hasher.write_u64(metadata.len());
            if let Err(err) = file.take(32 * 1024).read_to_end(&mut buffer) {
                if err.kind() != std::io::ErrorKind::UnexpectedEof {
                    return "-3".to_string();
                }
            }
            hasher.write(&buffer);
            let hash = hex::encode(hasher.finish().to_be_bytes()).to_string();
            return hash;
        }
    }
    return "-3".to_string();
}

pub fn get_file_sha256(fpath: &str) -> String {
    let mut f = match std::fs::File::open(fpath) {
        Ok(f) => f,
        Err(_) => return "".to_string(),
    };

    let mut buffer: [u8; 524288] = [0; 524288]; // 524288 = 512 * 1024

    let mut hasher = Sha256::new();
    loop {
        let s = match f.read(&mut buffer) {
            Ok(s) => s,
            Err(_) => return "".to_string(),
        };
        if s == 0 {
            break;
        } else {
            hasher.update(&buffer[..s]);
        }
        thread::sleep(std::time::Duration::from_millis(125));
    }
    return format!("{:x}", hasher.finalize());
}

pub fn get_file_md5(fpath: &str) -> String {
    let mut f = match std::fs::File::open(fpath) {
        Ok(f) => f,
        Err(_) => return "".to_string(),
    };
    let mut buffer: [u8; 524288] = [0; 524288]; // 524288 = 512 * 1024

    let mut md5_context = md5::Context::new();

    loop {
        let s = match f.read(&mut buffer) {
            Ok(s) => s,
            Err(_) => return "".to_string(),
        };
        if s == 0 {
            break;
        } else {
            md5_context.consume(&buffer[..s]);
        }
        thread::sleep(std::time::Duration::from_millis(125));
    }
    let digest = md5_context.compute();
    return format!("{:x}", digest);
}

pub fn get_file_md5_fast(fpath: &str) -> String {
    let mut f = match std::fs::File::open(fpath) {
        Ok(f) => f,
        Err(_) => return "".to_string(),
    };
    let mut buffer: [u8; 524288] = [0; 524288]; // 524288 = 512 * 1024

    let mut md5_context = md5::Context::new();

    loop {
        let s = match f.read(&mut buffer) {
            Ok(s) => s,
            Err(_) => return "".to_string(),
        };
        if s == 0 {
            break;
        } else {
            md5_context.consume(&buffer[..s]);
        }
    }
    let digest = md5_context.compute();
    return format!("{:x}", digest);
}

pub fn get_buf_sha256(buf: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(buf);
    return format!("{:x}", hasher.finalize());
}

pub fn get_file_btime(m: &std::fs::Metadata) -> (u64, u64) {
    let ct = match m.created() {
        Ok(m) => {
            let cti = match m.duration_since(time::UNIX_EPOCH) {
                Ok(mi) => mi.as_secs(),
                Err(_) => 0,
            };
            cti
        }
        Err(_) => 0,
        // create time is not supported on some filesystem
    };

    let mt = match m.modified() {
        Ok(m) => {
            let cti = match m.duration_since(time::UNIX_EPOCH) {
                Ok(mi) => mi.as_secs(),
                Err(_) => 0,
            };
            cti
        }
        Err(_) => 0,
    };
    return (ct, mt);
}

pub fn setup_cgroup(pid: u32, mem: i64, cpu: i64) {
    // unlimit : 1024 * 1024 * 500 & 200000
    // limit : 1024 * 1024 * 180 & 10000
    let hier1 = cgroups_rs::hierarchies::auto();
    let mem_cg = cgroups_rs::cgroup_builder::CgroupBuilder::new("clamav_mem")
        .memory()
        .memory_hard_limit(mem) // x MB
        .done()
        .build(hier1);

    let mems: &cgroups_rs::memory::MemController = mem_cg.controller_of().unwrap();
    mems.add_task(&cgroups_rs::CgroupPid::from(pid as u64))
        .unwrap();

    let hier = cgroups_rs::hierarchies::auto();
    let cpu_cg = cgroups_rs::cgroup_builder::CgroupBuilder::new("clamav_cpu")
        .cpu()
        .quota(cpu) //  n / MAX 100 000 = x% CPU
        .done()
        .build(hier);

    let cpus: &cgroups_rs::cpu::CpuController = cpu_cg.controller_of().unwrap();
    cpus.add_task(&cgroups_rs::CgroupPid::from(pid as u64))
        .unwrap();
}

pub fn is_filetype_filter_skipped(fpath: &str) -> Result<bool> {
    /*
        App,
        Archive, // skipped
        Audio,   // skipped
        Book,    // skipped
        Doc,     // skipped
        Font,    // skipped
        Image,   // skipped
        Text,
        Video,   // skipped
    */
    let mut f = std::fs::File::open(fpath)?;
    f.seek(SeekFrom::Start(0))?;
    let mut buffer = [0 as u8; 64];
    let _readsize = f.read(&mut buffer)?;

    if let Some(kind) = infer::get(&buffer) {
        match kind.matcher_type() {
            MatcherType::Image
            | MatcherType::Audio
            | MatcherType::Book
            | MatcherType::Doc
            | MatcherType::Font
            | MatcherType::Video
            | MatcherType::Archive => {
                return Ok(true);
            }
            _ => return Ok(false),
        }
    }
    return Ok(false);
}