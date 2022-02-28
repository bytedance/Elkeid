//#![feature(static_nobundle)]
#![allow(warnings)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::{
    ffi::{c_void, CStr, CString},
    hash::Hasher,
    io::Read,
    path::Path,
    ptr, thread, time,
};

pub mod clamav;
pub mod configs;
pub mod cronjob;
pub mod detector;
pub mod filter;
pub mod updater;

pub trait ToAgentRecord {
    fn to_record(&self) -> plugins::Record;
}

#[repr(C)]
pub struct Clamav {
    engine: *mut clamav::cl_engine,
    pub signo: u32,
    scan_option: clamav::cl_scan_options,
}

// impl .send trait for Clamav
unsafe impl std::marker::Send for Clamav {}
unsafe impl std::marker::Sync for Clamav {}

pub fn err_str_from_code(retc: ::std::os::raw::c_int) -> String {
    unsafe {
        return format!("clamav::err {:?}", clamav::cl_strerror(retc));
    }
}

impl Clamav {
    pub fn new() -> Result<Self> {
        let pointer = unsafe {
            let retc = clamav::cl_init(clamav::CL_INIT_DEFAULT);
            if retc != 0 {
                return Err(anyhow!(
                    "clamav::cl_init {:?} err",
                    clamav::cl_strerror(retc as ::std::os::raw::c_int)
                ));
            };
            clamav::cl_engine_new()
        };
        return Ok(Clamav {
            engine: pointer,
            signo: 0,
            scan_option: clamav::cl_scan_options {
                general: 0,
                parse: clamav::CL_SCAN_PARSE_ARCHIVE | clamav::CL_SCAN_PARSE_ELF,
                heuristic: 0,
                mail: 0,
                dev: 0,
            },
        });
    }

    pub fn load_db(&mut self, db_path: &str) -> Result<u32> {
        if !Path::new(db_path).exists() {
            return Err(anyhow!("db {} is not exists!", db_path));
        }
        let mut signo: u32 = 0;
        unsafe {
            let signo_ptr = &mut signo as *mut u32;
            let default_path = CString::new(db_path.as_bytes()).unwrap();
            let retc = clamav::cl_load(
                default_path.as_ptr(),
                self.engine,
                signo_ptr,
                clamav::CL_DB_DIRECTORY,
            );
            if retc != clamav::cl_error_t_CL_SUCCESS {
                //clamav::cl_engine_free(self.engine);
                return Err(anyhow!(
                    "clamav::cl_load {:?} err",
                    clamav::cl_strerror(retc as ::std::os::raw::c_int)
                ));
            };
        }
        std::fs::remove_dir_all(db_path);
        return Ok(signo);
    }

    pub fn compile_engine(&mut self) -> Result<()> {
        unsafe {
            let retc = clamav::cl_engine_compile(self.engine);
            if retc != clamav::cl_error_t_CL_SUCCESS {
                //clamav::cl_engine_free(self.engine);
                return Err(anyhow!(
                    "clamav::cl_engine_compile {:?} err",
                    clamav::cl_strerror(retc as ::std::os::raw::c_int)
                ));
            };
        }
        return Ok(());
    }

    pub fn set_max_size(
        &mut self,
        maxfilesize: ::std::os::raw::c_longlong,
        maxscansize: ::std::os::raw::c_longlong,
    ) -> Result<()> {
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_MAX_SCANSIZE, maxscansize)?;
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_MAX_FILESIZE, maxfilesize)?;
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_MAX_SCANTIME, 9000)?; // 15s
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_PCRE_MATCH_LIMIT, 1000)?;
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_PCRE_RECMATCH_LIMIT, 500)?;

        return Ok(());
    }

    fn set_engine_filed_num(
        &mut self,
        code: clamav::cl_engine_field,
        num: ::std::os::raw::c_longlong,
    ) -> Result<()> {
        unsafe {
            //clamav::cl_engine_field_CL_ENGINE_MAX_SCANSIZE,
            let retc = clamav::cl_engine_set_num(self.engine, code, num);
            if retc != 0 {
                return Err(anyhow!("engine set {:?} = {:?} failed", code, num));
            }
        }
        return Ok(());
    }

    pub fn scan_mem(&mut self, fname: &str, buf: &[u8]) -> Result<String> {
        if buf.len() <= 5 {
            return Err(anyhow!("buf is too short"));
        }

        let filename = CString::new(fname.as_bytes()).unwrap();
        let mut virus_name: *const ::std::os::raw::c_char = ptr::null();
        let mut scann_bytes: u64 = 0;
        unsafe {
            let cfmap_t =
                clamav::cl_fmap_open_memory(buf.as_ptr() as *const c_void, buf.len() as u64);
            let nil_ctx = ptr::null_mut();

            let retc = clamav::cl_scanmap_callback(
                cfmap_t,
                filename.as_ptr(),
                &mut virus_name,
                &mut scann_bytes as *mut u64,
                self.engine,
                &mut self.scan_option,
                nil_ctx,
            );
            clamav::cl_fmap_close(cfmap_t);

            match retc {
                clamav::cl_error_t_CL_CLEAN => return Ok("OK".to_string()),
                clamav::cl_error_t_CL_VIRUS => {
                    return Ok(CStr::from_ptr(virus_name).to_str().unwrap().to_string());
                }
                tc => {
                    return Err(anyhow!(
                        "clamav::cl_scanmap_callback {:?} err",
                        clamav::cl_strerror(tc as ::std::os::raw::c_int)
                    ));
                }
            };
        }
    }

    pub fn scan_file(&mut self, fpath: &str) -> Result<String> {
        let fp = Path::new(fpath);
        if !fp.exists() {
            return Err(anyhow!("scan target {} is not exists!", fpath));
        }
        if !fp.is_file() {
            return Err(anyhow!("scan target {} is not a regular file!", fpath));
        }
        let target_path = CString::new(fpath.as_bytes()).unwrap();
        let mut virus_name: *const ::std::os::raw::c_char = ptr::null();
        let mut scann_bytes: u64 = 0;

        unsafe {
            let retc = clamav::cl_scanfile(
                target_path.as_ptr(),
                &mut virus_name,
                &mut scann_bytes as *mut u64,
                self.engine,
                &mut self.scan_option,
            );
            match retc {
                clamav::cl_error_t_CL_CLEAN => return Ok("OK".to_string()),
                clamav::cl_error_t_CL_VIRUS => {
                    return Ok(CStr::from_ptr(virus_name).to_str().unwrap().to_string());
                }
                tc => {
                    return Err(anyhow!(
                        "clamav::cl_scanfile {:?} err",
                        clamav::cl_strerror(tc as ::std::os::raw::c_int)
                    ));
                }
            };
        };
    }
}

impl Drop for Clamav {
    fn drop(&mut self) {
        unsafe {
            clamav::cl_engine_free(self.engine);
        }
    }
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
        // create time is not supported on some filesystem, like ext3, ext2...
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
