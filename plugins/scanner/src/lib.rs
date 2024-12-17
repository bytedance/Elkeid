//#![feature(static_nobundle)]
#![allow(warnings)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]

use crate::config::FULLSCAN_CPU_IDLE_100PCT;
use anyhow::{anyhow, Result};
use procfs::CurrentSI;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    ffi::{c_void, CStr, CString},
    hash::Hasher,
    io::{BufWriter, ErrorKind, Read, Seek, SeekFrom},
    path::Path,
    ptr, thread, time,
};

use cgroups_rs::{self, Controller};
use delharc;
use infer::MatcherType;
use log::*;

pub mod config;
pub mod data_type;
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

lazy_static::lazy_static! {
    static ref RE_DOCKER: Regex = Regex::new(r"docker/([0-9a-f]*)\n").unwrap();
    static ref RE_KUBEPODS: Regex = Regex::new(r"kubepods/[0-9a-z-]*/([0-9a-f]*)\n").unwrap();
}

pub fn pid_to_docker_id(pid: i32) -> Option<String> {
    if let Ok(raw) = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
        if let Some(t) = RE_DOCKER.captures(&raw) {
            return t.get(1).map_or(None, |m| Some(m.as_str().to_string()));
        }
        if let Some(t) = RE_KUBEPODS.captures(&raw) {
            return t.get(1).map_or(None, |m| Some(m.as_str().to_string()));
        }
    }
    return None;
}

pub fn setup_cgroup(pid: u32, mem: i64, cpu: i64) -> Result<()> {
    // unlimit : 1024 * 1024 * 500 & 200000
    // limit : 1024 * 1024 * 180 & 10000
    let hier1 = cgroups_rs::hierarchies::auto();
    let scanner_cg = cgroups_rs::cgroup_builder::CgroupBuilder::new("elkeid_scanner")
        .memory()
        .memory_hard_limit(mem) // x MB
        .done()
        .cpu()
        .quota(cpu) //  n / MAX 100 000 = x% CPU
        .done()
        .build(hier1);

    scanner_cg.add_task(cgroups_rs::CgroupPid::from(pid as u64));
    return Ok(());
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

pub fn get_available_worker_cpu_quota(
    interval_secs: u64,
    cpu_idle: u64,
    default_cpu_min: u64,
    default_cpu_max: u64,
) -> Result<(u32, i64)> {
    let mut cpu_usage = cpu_idle;
    if cpu_idle <= 0 || cpu_idle > 100 {
        cpu_usage = *FULLSCAN_CPU_IDLE_100PCT;
    }
    let kstats = procfs::KernelStats::current()?;
    thread::sleep(std::time::Duration::from_secs(interval_secs));
    let kstate = procfs::KernelStats::current()?;

    let idle_s = kstats.total.idle_ms();
    let idle_e = kstate.total.idle_ms();
    let idle_len = ((idle_e - idle_s) as f64 / interval_secs as f64).floor() as u64;
    let mut cgroup_cpu_quota = std::cmp::max(idle_len * cpu_idle, default_cpu_min) as i64;
    // 当 空闲 quota 不足时，至少使用 0.1 U
    cgroup_cpu_quota = std::cmp::min(cgroup_cpu_quota, default_cpu_max as i64);
    // 当 空闲 quota 过多时（几百个CPU），最多使用 8 U
    let worker = (cgroup_cpu_quota as f64 / 100_000.00).ceil() as u32;
    // 向上取整 worker 数量不为 0
    return Ok((worker, cgroup_cpu_quota));
}

pub fn extract_lzh(target_lzh_file: &str, target_dir: &str) -> Result<()> {
    if !std::path::Path::new(target_lzh_file).exists() {
        return Err(anyhow!("extract_lzh target {} not exists", target_lzh_file));
    }
    if !std::path::Path::new(target_dir).exists() {
        std::fs::create_dir_all(target_dir)?;
    }
    let mut lha_reader = delharc::parse_file(target_lzh_file)?;
    let mut counter = 0;
    loop {
        let header = lha_reader.header();
        let filepath = header.parse_pathname();
        let filesize = header.original_size;
        let fileext = match filepath.extension() {
            Some(ext) => ext.to_string_lossy().to_string(),
            None => "bin".to_string(),
        };
        info!(
            "extract: {:?} into {}{}{}.{}",
            filepath,
            target_dir,
            std::path::MAIN_SEPARATOR,
            counter,
            fileext
        );
        let tmp_file = match std::fs::File::create(format!(
            "{}{}{}.{}",
            target_dir,
            std::path::MAIN_SEPARATOR,
            counter,
            fileext
        )) {
            Ok(f) => f,
            Err(e) => {
                if e.kind() == ErrorKind::AlreadyExists {}
                continue;
            }
        };
        counter += 1;
        if lha_reader.is_decoder_supported() {
            let mut writer = Box::new(BufWriter::with_capacity(128 * 1024, tmp_file));
            match std::io::copy(&mut lha_reader, &mut writer) {
                Ok(n) => {
                    if n != filesize {
                        error!("write {} with origin {}", n, filesize);
                        continue;
                    } else {
                        info!(
                            "extract: {:?} into {}{}{}.{} ok",
                            filepath,
                            target_dir,
                            std::path::MAIN_SEPARATOR,
                            counter,
                            fileext
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "extract: {:?} into {}{}{}.{} error {}",
                        filepath,
                        target_dir,
                        std::path::MAIN_SEPARATOR,
                        counter,
                        fileext,
                        e
                    );
                    continue;
                }
            };
            lha_reader.crc_check()?;
        }
        if !lha_reader.next_file()? {
            break;
        }
    }
    return Ok(());
}
