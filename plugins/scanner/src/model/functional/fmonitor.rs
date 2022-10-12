extern crate libc;
use libc::{__s32, __u16, __u32, __u64, __u8};

use log::*;

use cached::{Cached, TimedCache};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::{ffi::CString, process};
use std::{fs::read_link, path::Path, time::Duration};
use thread::JoinHandle;
use walkdir::WalkDir;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use procfs::sys::kernel::Version;
use std::io::Error;
use std::thread;

use crate::configs::{FAMode, FanotifyTargetConfig};
use crate::data_type::{ScanTaskFanotify, DETECT_TASK};

use crate::get_file_sha256;
use crate::model::functional::anti_ransom::HONEYPOTSSHA256;

use libc::{FAN_MARK_ADD, FAN_MARK_FLUSH};

/// report unique file id
pub const FAN_REPORT_FID: u32 = 0x0000_0200;
/// Create an event when a file or directory is accessed (read).
pub const FAN_ACCESS: u64 = 0x0000_0001;

pub const FAN_MODIFY: u64 = 0x0000_0002; /* File was modified */
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008; /* Writtable file closed */
pub const FAN_MOVED: u64 = FAN_MOVED_FROM | FAN_MOVED_TO;
pub const FAN_ONDIR: u64 = 0x4000_0000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;

// kernel 5.1
pub const FAN_MOVED_FROM: u64 = 0x00000040; /* File was moved from X */
pub const FAN_MOVED_TO: u64 = 0x00000080; /* File was moved to Y */
/// Create an event when a file created
pub const FAN_CREATE: u64 = 0x0000_0100;
/// Create an event when a file deleted
pub const FAN_DELETE: u64 = 0x0000_0200;
/// Create an event when a self was deleted
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;
/// Create an event when self was moved
pub const FAN_MOVE_SELF: u64 = 0x0000_0800;

// settings for kernel < 5.1
pub const LOW_DIR_MATCH_MASK: u64 = FAN_CLOSE_WRITE | FAN_ONDIR | FAN_EVENT_ON_CHILD;

// settings for kernel >= 5.1
pub const H51_DIRS_MATCH_MASK: u64 = FAN_ONDIR | FAN_EVENT_ON_CHILD | FAN_CLOSE_WRITE;

const METADATA_MAX_LEN: usize = 1024;

lazy_static! {
    // DEFAULT_CONFIG.0 fanotify_init code
    // DEFAULT_CONFIG.1 fanotify_mark DIR
    pub static ref FANOTIFY_DEFAULT_CONFIG: (bool, u32, u64) = {
        match Version::current() {
            Ok(t) => {
                if t >= Version::new(5, 1, 0) {
                    return (
                        true,
                        libc::FAN_CLASS_NOTIF,
                        H51_DIRS_MATCH_MASK
                    );
                } else if t >= Version::new(2, 6, 36){
                    return (
                        true,libc::FAN_CLASS_NOTIF, LOW_DIR_MATCH_MASK);
                } else {
                    return (false,0,0)
                }
            }
            _ => {
                return (false,0, 0);
            }
        };
    };
}

#[repr(align(8))]
#[derive(Debug, Clone, Copy)]
pub struct FanotifyEventMetadata {
    pub event_len: __u32,
    pub vers: __u8,
    pub reserved: __u8,
    pub metadata_len: __u16,
    pub mask: __u64,
    pub fd: __s32,
    pub pid: __s32,
}

#[derive(Debug, Clone)]
pub struct FAMEvent {
    pub pid: i32,
    pub path: String,
    pub mask: u64,
}

// FileMonitor
pub struct FileMonitor {
    pub fd: i32,
    pub pid: u32,
    pub worker_thread: Option<JoinHandle<Error>>,
    pub current_kernel_version: Version,
    pub anti_ransome: Arc<RwLock<HashMap<String, bool>>>,
    pub anti_ransome_dir: HashMap<String, bool>,
}

impl Drop for FileMonitor {
    fn drop(&mut self) {
        if FANOTIFY_DEFAULT_CONFIG.0 {
            let rcode = unsafe { libc::close(self.fd) };
            if rcode != 0 {
                error!("self close fd :{}; return:{}.", self.fd, rcode);
            } else {
                info!("self close fd :{}; success", self.fd);
            }
            for (k, v) in self.anti_ransome_dir.iter() {
                std::fs::remove_dir_all(k);
            }
        }
    }
}

impl FileMonitor {
    pub fn new(
        sender: crossbeam_channel::Sender<DETECT_TASK>,
        s_locker: crossbeam_channel::Sender<()>,
        cache_ttl_secs: u64,
        cache_size: usize,
    ) -> Result<FileMonitor> {
        let pid = process::id();

        let current_kernel_version = Version::current().unwrap();
        let anti_ransome = Arc::new(RwLock::new(HashMap::new()));
        if !FANOTIFY_DEFAULT_CONFIG.0 {
            return Ok(FileMonitor {
                fd: -3,
                pid: 0,
                worker_thread: None,
                current_kernel_version: current_kernel_version,
                anti_ransome: anti_ransome,
                anti_ransome_dir: HashMap::new(),
            });
        }
        let mut local_cache: TimedCache<(i32, u64, String), u32> =
            TimedCache::with_lifespan_and_capacity(cache_ttl_secs, cache_size);

        let anti_ransome_inner = Arc::clone(&anti_ransome);

        let fd = unsafe { libc::fanotify_init(FANOTIFY_DEFAULT_CONFIG.1, libc::O_RDONLY as u32) };
        if fd < 0 {
            error!("fanotify init error !!!!");
            return Err(anyhow!(Error::last_os_error()));
        } else {
            info!("fanotify init ok fd = {:?}", fd);
            let mut metadata =
                Vec::<libc::fanotify_event_metadata>::with_capacity(METADATA_MAX_LEN);
            let child = thread::spawn(move || {
                loop {
                    let len = unsafe {
                        libc::read(
                            fd,
                            metadata.as_mut_ptr() as *mut libc::c_void,
                            METADATA_MAX_LEN * std::mem::size_of::<libc::fanotify_event_metadata>(),
                        )
                    };
                    match len {
                        0 => {
                            continue;
                        }
                        -1 => {
                            let e = Error::last_os_error();
                            error!("get fanotify_event_metadata err:{}", e);
                            drop(sender);
                            s_locker.send(()).unwrap();
                            return e;
                        }
                        k => unsafe {
                            metadata.set_len(
                                k as usize / std::mem::size_of::<libc::fanotify_event_metadata>(),
                            );
                        },
                    };

                    for each_metadata in metadata.iter() {
                        if each_metadata.fd == -1 {
                            continue; // too many event, skip queue overflowed event
                        }
                        if each_metadata.vers != libc::FANOTIFY_METADATA_VERSION {
                            safe_close(each_metadata.fd);
                            continue; // skip monitor self pid
                        }
                        if each_metadata.pid == pid as i32 {
                            safe_close(each_metadata.fd);
                            continue; // skip monitor self pid
                        }
                        let event_fpath = get_real_path_from_fd_link(pid, each_metadata.fd);
                        safe_close(each_metadata.fd);
                        match event_fpath.as_str() {
                            "-1" | "-3" => {
                                continue;
                            }
                            _ => {}
                        };
                        if event_fpath.ends_with(".swp")
                            || event_fpath.ends_with("(deleted)")
                            || event_fpath.ends_with(".swa")
                            || event_fpath.ends_with(".svz")
                            || event_fpath.ends_with(".swn")
                            || event_fpath.ends_with(".swo")
                            || event_fpath.ends_with(".tmp")
                            || event_fpath.ends_with(".tmpx")
                            || event_fpath.ends_with(".bash_history")
                            || event_fpath.ends_with(".viminfo")
                            || event_fpath.ends_with(".dpkg-new")
                        {
                            // skip vim tmp file
                            continue;
                        }

                        if let Some(_) = local_cache.cache_set(
                            (
                                each_metadata.pid,
                                each_metadata.mask,
                                event_fpath.to_string(),
                            ),
                            1,
                        ) {
                            continue;
                        }

                        debug!("fanotify event {:?}\n{}", &each_metadata.mask, event_fpath);

                        let event_pid = &each_metadata.pid;
                        let pstr: &str = &format!("/proc/{}/exe", event_pid);
                        let exe_fp = Path::new(pstr);
                        let exe_real = match std::fs::read_link(exe_fp) {
                            Ok(pf) => pf.to_string_lossy().to_string(),

                            Err(e) => {
                                debug!(
                                    "fanotify get target pid:{} exe_real_path failed, process may exit.",
                                    event_pid
                                );
                                continue;
                            }
                        };

                        let pstr_full: &str = &format!("/proc/{}/root{}", event_pid, exe_real);
                        let rfp = Path::new(pstr_full);

                        let fpath_real_sha256 = get_file_sha256(&event_fpath);

                        // fanotify only
                        if let Ok(map) = anti_ransome_inner.read() {
                            if !map.contains_key(&event_fpath) {
                                let (fsize, btime) = match rfp.metadata() {
                                    Ok(p) => {
                                        let fsize = p.len() as usize;
                                        let btime = crate::get_file_btime(&p);
                                        (fsize, btime)
                                    }
                                    Err(e) => {
                                        if let Ok(exe_rm) = Path::new(&exe_real).metadata() {
                                            let fsize = exe_rm.len() as usize;
                                            let btime = crate::get_file_btime(&exe_rm);
                                            (fsize, btime)
                                        } else {
                                            warn!(
                                                "error {}, while get exe realpath metadata",
                                                &exe_real
                                            );
                                            (0, (0, 0))
                                        }
                                    }
                                };
                                let default_mask_set: u64 = FANOTIFY_DEFAULT_CONFIG.2;
                                if match_event_mask(&each_metadata.mask, &default_mask_set) {
                                    let task = ScanTaskFanotify {
                                        pid: each_metadata.pid as i32,
                                        pid_exe: exe_real.to_string(),
                                        event_file_hash: fpath_real_sha256.to_string(),
                                        event_file_path: event_fpath.to_string(),
                                        event_file_mask: each_metadata.mask.to_string(),
                                        size: fsize,
                                        btime: btime,
                                    };
                                    debug!("fanotify event {:?}", task);

                                    while sender.len() > 256 {
                                        std::thread::sleep(Duration::from_secs(4));
                                    }

                                    match sender.try_send(DETECT_TASK::TASK_6054_FANOTIFY(task)) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            warn!("internal send task err : {:?}", e);
                                            s_locker.send(()).unwrap();
                                            break;
                                        }
                                    };
                                }
                                drop(map);
                                continue;
                            }
                            drop(map);
                        } else {
                            warn!("failed to read anti_ransome_inner map");
                        }

                        // anti_ransome
                        if let Some(fhash) = HONEYPOTSSHA256.get(&event_fpath) {
                            if fhash == &fpath_real_sha256 {
                                continue;
                            } else if crate::model::functional::anti_ransom::check_av_file(
                                &event_fpath,
                            ) {
                                continue;
                            }
                        }

                        let (fsize, btime) = match rfp.metadata() {
                            Ok(p) => {
                                if p.is_dir() {
                                    continue;
                                }
                                let fsize = p.len() as usize;
                                let btime = crate::get_file_btime(&p);
                                (fsize, btime)
                            }
                            Err(e) => {
                                if let Ok(exe_rm) = Path::new(&exe_real).metadata() {
                                    let fsize = exe_rm.len() as usize;
                                    let btime = crate::get_file_btime(&exe_rm);
                                    (fsize, btime)
                                } else {
                                    warn!("error {}, while get exe realpath metadata", &exe_real);
                                    (0, (0, 0))
                                }
                            }
                        };

                        if fsize > crate::model::engine::clamav::config::CLAMAV_MAX_FILESIZE {
                            continue;
                        }
                        let default_mask_set: u64 = FANOTIFY_DEFAULT_CONFIG.2;

                        if match_event_mask(&each_metadata.mask, &default_mask_set) {
                            let task = ScanTaskFanotify {
                                pid: each_metadata.pid as i32,
                                pid_exe: exe_real.to_string(),
                                event_file_hash: fpath_real_sha256.to_string(),
                                event_file_path: event_fpath.to_string(),
                                event_file_mask: each_metadata.mask.to_string(),
                                size: fsize,
                                btime: btime,
                            };
                            debug!("fanotify event {:?}", task);

                            while sender.len() > 8 {
                                std::thread::sleep(Duration::from_secs(4));
                            }
                            match sender.try_send(DETECT_TASK::TASK_6054_ANTIVIRUS(task)) {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("internal send task err : {:?}", e);
                                    s_locker.send(()).unwrap();
                                    break;
                                }
                            };
                        }
                    }
                    metadata.clear();
                }
            });
            Ok(Self {
                fd: fd,
                pid: pid,
                worker_thread: Some(child),
                current_kernel_version: current_kernel_version,
                anti_ransome: anti_ransome,
                anti_ransome_dir: HashMap::new(),
            })
        }
    }
    pub fn flush(&mut self) {
        if unsafe { libc::fanotify_mark(self.fd, FAN_MARK_FLUSH, 0, 0, std::ptr::null()) } != 0 {
            warn!("mm.flush() :{}", Error::last_os_error());
        } else {
            info!("{}.flush success !", self.fd);
        }
        if let Ok(mut map) = self.anti_ransome.write() {
            map.clear();
            drop(map);
        }
    }
    pub fn add(&mut self, path: &str, is_anti_ransome: bool) -> Result<()> {
        if !FANOTIFY_DEFAULT_CONFIG.0 {
            return Ok(());
        }
        let target_path = Path::new(path);
        if target_path.exists() == false {
            return Ok(());
        }

        let cpath = CString::new(path).unwrap();
        if unsafe {
            libc::fanotify_mark(
                self.fd,
                FAN_MARK_ADD,
                FANOTIFY_DEFAULT_CONFIG.2,
                0,
                cpath.as_ptr(),
            )
        } != 0
        {
            let e = anyhow!(
                "add: {}, error :{:?} : kernel = {:?}",
                path,
                Error::last_os_error(),
                self.current_kernel_version
            );
            warn!(
                "kernel = {:?},fanotify add mask err {:?}",
                self.current_kernel_version, e
            );
            Err(e)
        } else {
            info!("fmonitor add {:?}", path);
            if let Ok(mut map) = self.anti_ransome.write() {
                if let Some(v) = map.insert(path.to_string(), is_anti_ransome) {
                    warn!(
                        "fmonitor add duplicate av:{:?},path:{:?}",
                        is_anti_ransome, path
                    );
                }
                drop(map);
            } else {
                warn!("failed to read anti_ransome_inner map");
            }

            Ok(())
        }
    }
    pub fn add_cfg(&mut self, cfg: &FanotifyTargetConfig) -> Result<()> {
        if !FANOTIFY_DEFAULT_CONFIG.0 {
            return Ok(());
        }
        let target_path = Path::new(cfg.path);
        if !target_path.exists() || !target_path.is_dir() {
            return Ok(());
        }
        self.add(cfg.path, false)?;
        match cfg.watch_mode {
            FAMode::RECUR(ndepth) => {
                let mut w_dir = WalkDir::new(&target_path)
                    .max_depth(ndepth)
                    .follow_links(cfg.follow_link)
                    .into_iter();
                loop {
                    let entry = match w_dir.next() {
                        None => break,
                        Some(Err(_err)) => {
                            break;
                        }
                        Some(Ok(entry)) => entry,
                    };
                    let fp = entry.path();
                    if !fp.is_dir() {
                        continue;
                    }
                    let cur_path = fp.to_string_lossy();
                    if let Some(child) = cfg.sp_child {
                        if cur_path.ends_with(child) {
                            self.add(&cur_path, false)?;
                        }
                    } else {
                        self.add(&cur_path, false)?;
                    }
                }
            }
            FAMode::SIGLE => {}
        }
        return Ok(());
    }
}

// get_real_path_from_fd_link get path from read_link
pub fn get_real_path_from_fd_link(pid: u32, fd: i32) -> String {
    if let Ok(path) = read_link(format!("/proc/{}/fd/{}", pid, fd)) {
        if let Ok(p) = path.into_os_string().into_string() {
            return p;
        } else {
            return "-1".to_owned();
        }
    } else {
        return "-3".to_owned();
    }
}

// match_event_mask
fn match_event_mask(event: &u64, mask: &u64) -> bool {
    (event & mask) != 0
}

fn safe_close(fd: i32) {
    let rcode = unsafe {
        let retc = libc::close(fd);
        debug!("close fd :{}; return:{}.", fd, retc);
        retc
    };
    if rcode != 0 {
        warn!("close fd :{}; return:{}.", fd, rcode);
    };
}
