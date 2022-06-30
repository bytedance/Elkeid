#![allow(warnings)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod clamav;
pub mod config;
pub mod updater;
use anyhow::{anyhow, Result};

use self::clamav::timeval;

use super::ScanEngine;
use std::{
    ffi::{c_void, CStr, CString},
    io::Read,
    mem,
    path::Path,
    ptr,
};

use libc::{c_char, size_t};

#[repr(C)]
pub struct Clamav {
    engine: *mut clamav::cl_engine,
    scan_option: clamav::cl_scan_options,
    scan_option_php: clamav::cl_scan_options,
}

// impl .Send trait for Clamav
unsafe impl std::marker::Send for Clamav {}
unsafe impl std::marker::Sync for Clamav {}

pub fn clamav_init() -> Result<()> {
    unsafe {
        let retc = clamav::cl_init(clamav::CL_INIT_DEFAULT);
        if retc != 0 {
            return Err(anyhow!(
                "clamav::cl_init {:?} err",
                clamav::cl_strerror(retc as ::std::os::raw::c_int)
            ));
        };
    }
    return Ok(());
}

impl Clamav {
    pub fn new() -> Result<Self> {
        let pointer = unsafe { clamav::cl_engine_new() };
        return Ok(Clamav {
            engine: pointer,
            scan_option: clamav::cl_scan_options {
                general: 0,
                parse: clamav::CL_SCAN_PARSE_ELF,
                heuristic: 0,
                mail: 0,
                dev: 0,
            },
            scan_option_php: clamav::cl_scan_options {
                general: clamav::CL_SCAN_GENERAL_YARAHIT,
                parse: 0,
                heuristic: 0,
                mail: 0,
                dev: 0,
            },
        });
    }

    pub fn set_max_size(
        &mut self,
        maxfilesize: ::std::os::raw::c_longlong,
        maxscansize: ::std::os::raw::c_longlong,
        maxscantime: ::std::os::raw::c_longlong,
    ) -> Result<()> {
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_MAX_SCANSIZE, maxscansize)?;
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_MAX_FILESIZE, maxfilesize)?;
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_MAX_SCANTIME, maxscantime)?;
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_PCRE_MATCH_LIMIT, 500)?;
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_PCRE_RECMATCH_LIMIT, 250)?;
        self.set_engine_filed_num(clamav::cl_engine_field_CL_ENGINE_DISABLE_CACHE, 1)?;
        return Ok(());
    }

    pub fn set_engine_filed_num(
        &mut self,
        code: clamav::cl_engine_field,
        num: ::std::os::raw::c_longlong,
    ) -> Result<()> {
        unsafe {
            let retc = clamav::cl_engine_set_num(self.engine, code, num);
            if retc != 0 {
                return Err(anyhow!("engine set {:?} = {:?} failed", code, num));
            }
        }
        return Ok(());
    }

    pub fn load_db(&mut self, db_path: &str) -> Result<()> {
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
                return Err(anyhow!(
                    "clamav::cl_load {:?} err",
                    clamav::cl_strerror(retc as ::std::os::raw::c_int)
                ));
            };
        }
        std::fs::remove_dir_all(db_path);
        return Ok(());
    }

    pub fn compile_engine(&mut self) -> Result<()> {
        unsafe {
            let retc = clamav::cl_engine_compile(self.engine);
            if retc != clamav::cl_error_t_CL_SUCCESS {
                return Err(anyhow!(
                    "clamav::cl_engine_compile {:?} err",
                    clamav::cl_strerror(retc as ::std::os::raw::c_int)
                ));
            };
        }
        return Ok(());
    }
}

impl ScanEngine for Clamav {
    fn new(db_path: &str) -> Result<Self> {
        let mut engine = Clamav::new()?;
        engine.set_max_size(
            config::CLAMAV_MAX_FILESIZE as i64,
            config::CLAMAV_MAX_SCANSIZE,
            config::CLAMAV_MAX_SCANTIME,
        )?;
        engine.load_db(db_path)?;
        engine.compile_engine()?;
        return Ok(engine);
    }

    fn scan_mem(&mut self, fname: &str, buf: &[u8]) -> Result<String> {
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

    fn scan_file(&mut self, fpath: &str) -> Result<(String, Option<Vec<String>>)> {
        let fp = Path::new(fpath);
        if !fp.exists() {
            return Err(anyhow!("scan target {} is not exists!", fpath));
        }
        if !fp.is_file() {
            return Err(anyhow!("scan target {} is not a regular file!", fpath));
        }
        let mut php_flag = false;
        if fpath.ends_with(".php") {
            php_flag = true;
        }
        let target_path = CString::new(fpath.as_bytes()).unwrap();
        let mut virus_name: *const ::std::os::raw::c_char = ptr::null();

        let mut scann_bytes: u64 = 0;

        unsafe {
            let mut nil_ctx: *mut clamav::yr_hit_cb_ctx = ptr::null_mut();
            if php_flag {
                nil_ctx = clamav::cl_yr_hit_cb_ctx_init();
            }
            let mut retc: u32 = 0;
            let mut yr_ctx: *mut c_void = nil_ctx as _;

            if php_flag {
                retc = clamav::cl_scanfile_callback(
                    target_path.as_ptr(),
                    &mut virus_name,
                    &mut scann_bytes as *mut u64,
                    self.engine,
                    &mut self.scan_option_php,
                    yr_ctx,
                );
            } else {
                retc = clamav::cl_scanfile(
                    target_path.as_ptr(),
                    &mut virus_name,
                    &mut scann_bytes as *mut u64,
                    self.engine,
                    &mut self.scan_option,
                );
            }

            match retc {
                clamav::cl_error_t_CL_CLEAN => {
                    if php_flag {
                        clamav::cl_yr_hit_cb_ctx_free(nil_ctx);
                    }
                    return Ok(("OK".to_string(), None));
                }
                clamav::cl_error_t_CL_VIRUS => {
                    let target_virust_name =
                        CStr::from_ptr(virus_name).to_str().unwrap().to_string();
                    if php_flag {
                        if (*nil_ctx).hit_cnt != 0 {
                            let length = (*nil_ctx).hit_cnt as usize;
                            let mut hitstring: Vec<String> = Vec::new();
                            let mut v: Vec<*mut c_char> =
                                Vec::from_raw_parts((*nil_ctx).hits, length, length);
                            loop {
                                if let Some(tc) = v.pop() {
                                    hitstring
                                        .push(CStr::from_ptr(tc).to_string_lossy().to_string());
                                } else {
                                    break;
                                }
                            }
                            mem::forget(v);
                            clamav::cl_yr_hit_cb_ctx_free(nil_ctx);
                            return Ok((target_virust_name, Some(hitstring)));
                        }
                    }
                    return Ok((target_virust_name, None));
                }
                tc => {
                    let errmsg = CStr::from_ptr(clamav::cl_strerror(tc as ::std::os::raw::c_int))
                        .to_string_lossy()
                        .into_owned();
                    if php_flag {
                        clamav::cl_yr_hit_cb_ctx_free(nil_ctx);
                    }
                    return Err(anyhow!("clamav::cl_scanfile {:?} err", errmsg));
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

impl Clone for Clamav {
    fn clone(&self) -> Clamav {
        unsafe { clamav::cl_engine_addref(self.engine) };
        return Clamav {
            engine: *&self.engine,
            scan_option: clamav::cl_scan_options {
                general: 0,
                parse: clamav::CL_SCAN_PARSE_ELF,
                heuristic: 0,
                mail: 0,
                dev: 0,
            },
            scan_option_php: clamav::cl_scan_options {
                general: clamav::CL_SCAN_GENERAL_YARAHIT,
                parse: 0,
                heuristic: 0,
                mail: 0,
                dev: 0,
            },
        };
    }
}
