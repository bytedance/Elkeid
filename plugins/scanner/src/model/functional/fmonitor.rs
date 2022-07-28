extern crate libc;
use libc::{__s32, __u16, __u32, __u64, __u8};

use log::*;

use std::{ffi::CString, process};
use std::{fs::read_link, path::Path, time::Duration};
use thread::JoinHandle;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use procfs::sys::kernel::Version;
use std::io::Error;
use std::thread;

use crate::detector::DetectTask;
use crate::get_file_sha256;
use crate::model::functional::anti_ransom::HONEYPOTSSHA256;

lazy_static! {
    pub static ref H51_KERNEL_VERSION: Version = Version::new(5, 1, 0);
}

use libc::{FAN_MARK_ADD, FAN_MARK_FLUSH};

/// report unique file id
pub const FAN_REPORT_FID: u32 = 0x0000_0200;

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
pub const LOW_FILE_MATCH_MASK: u64 = FAN_MODIFY | FAN_CLOSE_WRITE;

// settings for kernel >= 5.1
pub const H51_FILE_MATCH_MASK: u64 = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_DELETE_SELF | FAN_MOVE_SELF;
pub const H51_DIRS_MATCH_MASK: u64 = FAN_ONDIR
    | FAN_EVENT_ON_CHILD
    | FAN_CREATE
    | FAN_DELETE
    | FAN_DELETE_SELF
    | FAN_MOVE_SELF
    | FAN_MOVED_FROM
    | FAN_MOVED_TO;

const METADATA_MAX_LEN: usize = 1024;

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

// FileMonitor
pub struct FileMonitor {
    pub fd: i32,
    pub pid: u32,
    pub worker_thread: JoinHandle<Error>,
    pub current_kernel_version: Version,
}

impl Drop for FileMonitor {
    fn drop(&mut self) {
        let rcode = unsafe { libc::close(self.fd) };
        if rcode != 0 {
            error!("self close fd :{}; return:{}.", self.fd, rcode);
        } else {
            info!("self close fd :{}; success", self.fd);
        }
    }
}

// for 6004
impl FileMonitor {
    pub fn new(
        sender: crossbeam_channel::Sender<DetectTask>,
        s_locker: crossbeam_channel::Sender<()>,
    ) -> Result<FileMonitor> {
        let pid = process::id();

        let current_kernel_version = Version::current().unwrap();

        let fd = unsafe {
            match current_kernel_version >= *H51_KERNEL_VERSION {
                true => libc::fanotify_init(
                    libc::FAN_CLASS_NOTIF | FAN_REPORT_FID,
                    libc::O_RDONLY as u32,
                ),
                false => libc::fanotify_init(libc::FAN_CLASS_NOTIF, libc::O_RDONLY as u32),
            }
        };
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
                    if len == 0 {
                        continue;
                    }
                    if len == -1 {
                        let e = Error::last_os_error();
                        error!("get fanotify_event_metadata err:{}", e);
                        drop(sender);
                        s_locker.send(()).unwrap();
                        return e;
                    }
                    unsafe {
                        metadata.set_len(
                            len as usize / std::mem::size_of::<libc::fanotify_event_metadata>(),
                        );
                    }
                    for each_metadata in metadata.iter() {
                        let path = get_real_path_from_fd_link(pid, each_metadata.fd);
                        if path.ends_with(".swp")
                            || path.ends_with("(deleted)")
                            || path.ends_with(".swa")
                            || path.ends_with(".svz")
                            || path.ends_with(".swn")
                            || path.ends_with(".swo")
                            || path.ends_with(".tmp")
                            || path.ends_with(".bash_history")
                            || path.ends_with(".dpkg-new")
                        {
                            // skip vim tmp file
                            safe_close(each_metadata.fd);
                            continue;
                        }
                        debug!("fanotify event {:?}\n{}", &each_metadata.mask, path);

                        let event_pid = &each_metadata.pid;
                        let pstr: &str = &format!("/proc/{}/exe", event_pid);
                        let exe_fp = Path::new(pstr);
                        let (exe_real, rfp) = match std::fs::read_link(exe_fp) {
                            Ok(pf) => (pf.to_string_lossy().to_string(), pf),
                            Err(e) => {
                                error!(
                                    "fanotify get target pid:{} exe_real_path failed, process may exit.",
                                    event_pid
                                );
                                safe_close(each_metadata.fd);
                                continue;
                            }
                        };

                        let event_fpath = &each_metadata.fd;
                        let fpstr: &str = &format!("/proc/{}/fd/{}", pid, event_fpath);
                        let fpath_fp = Path::new(fpstr);
                        let fpath_real = match std::fs::read_link(fpath_fp) {
                            Ok(pf) => pf.to_string_lossy().to_string(),
                            Err(e) => {
                                error!(
                                    "fanotify get target fd:{} file failed, target file deleted.",
                                    event_fpath
                                );
                                "".to_string()
                            }
                        };
                        safe_close(each_metadata.fd);

                        let fpath_real_sha256 = get_file_sha256(&fpath_real);
                        if let Some(fhash) = HONEYPOTSSHA256.get(&fpath_real) {
                            if fhash == &fpath_real_sha256 {
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
                                error!("error {}, while get exe realpath metadata", &exe_real);
                                continue;
                            }
                        };

                        if fsize <= 0
                            || fsize > crate::model::engine::clamav::config::CLAMAV_MAX_FILESIZE
                        {
                            continue;
                        }
                        let default_mask_set: u64 =
                            match current_kernel_version >= *H51_KERNEL_VERSION {
                                true => H51_DIRS_MATCH_MASK | H51_FILE_MATCH_MASK,
                                false => LOW_FILE_MATCH_MASK,
                            };

                        if match_event_mask(&each_metadata.mask, &default_mask_set) {
                            let task = DetectTask {
                                task_type: "6054".to_string(),
                                pid: pid as i32,
                                path: exe_real.to_string(),
                                rpath: fpath_real.to_string(),
                                size: fsize,
                                btime: btime.0,
                                mtime: btime.1,
                                token: fpath_real_sha256.to_string(),
                                add_ons: None,
                                finished: None,
                            };
                            debug!("fanotify event {:?}", task);

                            while sender.len() > 8 {
                                std::thread::sleep(Duration::from_secs(4));
                            }
                            match sender.try_send(task) {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("internal send task err : {:?}", e);
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
                worker_thread: child,
                current_kernel_version: current_kernel_version,
            })
        }
    }
    pub fn flush(&mut self) {
        if unsafe { libc::fanotify_mark(self.fd, FAN_MARK_FLUSH, 0, 0, std::ptr::null()) } != 0 {
            error!("mm.flush() :{}", Error::last_os_error());
        } else {
            info!("{}.flush success !", self.fd);
        }
    }
    pub fn add(&mut self, path: &str) -> Result<()> {
        let target_path = Path::new(path);
        if target_path.exists() == false {
            return Ok(());
        }

        let cpath = CString::new(path).unwrap();
        if unsafe {
            match self.current_kernel_version >= *H51_KERNEL_VERSION {
                true => {
                    if target_path.is_dir() {
                        libc::fanotify_mark(
                            self.fd,
                            FAN_MARK_ADD,
                            H51_DIRS_MATCH_MASK,
                            0,
                            cpath.as_ptr(),
                        )
                    } else {
                        libc::fanotify_mark(
                            self.fd,
                            FAN_MARK_ADD,
                            H51_FILE_MATCH_MASK,
                            0,
                            cpath.as_ptr(),
                        )
                    }
                }
                false => libc::fanotify_mark(
                    self.fd,
                    FAN_MARK_ADD,
                    LOW_FILE_MATCH_MASK,
                    0,
                    cpath.as_ptr(),
                ),
            }
        } != 0
        {
            let e = anyhow!(
                "error :{:?} : kernel = {:?}",
                Error::last_os_error(),
                self.current_kernel_version
            );
            warn!(
                "kernel = {:?},fanotify add mask err {:?}",
                self.current_kernel_version, e
            );
            Err(e)
        } else {
            Ok(())
        }
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
        error!("close fd :{}; return:{}.", fd, rcode);
    };
}
