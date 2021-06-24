extern crate libc;
use libc::{__s32, __u16, __u32, __u64, __u8};

use log::*;

use std::{ffi::CString, process};
use std::{fs::read_link, path::Path, time::Duration};
use thread::JoinHandle;

use anyhow::{anyhow, Result};
use std::io::Error;
use std::thread;

use crate::detector::DetectTask;

use libc::{FAN_MARK_ADD, FAN_MARK_FLUSH};

pub const FAN_EVENT_ON_CHILD: u64 = 0x08000000;
pub const FAN_ONDIR: u64 = 0x40000000;
pub const FAN_MODIFY: u64 = 0x00000002; /* File was modified */

pub const FAN_MOVED_FROM: u64 = 0x00000040; /* File was moved from X */
// ERR before kernel 5.1
pub const FAN_MOVED_TO: u64 = 0x00000080; /* File was moved to Y */
// ERR before kernel 5.1

pub const FAN_CLOSE_WRITE: u64 = 0x00000008; /* Writtable file closed */

pub const DEFAULT_MASK: u64 = FAN_MODIFY | FAN_CLOSE_WRITE | FAN_ONDIR | FAN_EVENT_ON_CHILD;
pub const MATCH_MASK: u64 =
    FAN_MODIFY | FAN_CLOSE_WRITE | FAN_MOVED_TO | FAN_MOVED_FROM | FAN_ONDIR | FAN_EVENT_ON_CHILD;

pub const FILE_DEFAULT_MASK_S: &[u64] =
    &[FAN_MODIFY, FAN_CLOSE_WRITE, FAN_MOVED_TO, FAN_MOVED_FROM];

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
        let fd = unsafe { libc::fanotify_init(libc::FAN_CLASS_NOTIF, libc::O_RDONLY as u32) };
        if fd < 0 {
            error!("fanotify init error !!!!");
            s_locker.send(()).unwrap();
            Err(anyhow!(Error::last_os_error()))
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
                        {
                            // skip vim tmp file
                            continue;
                        }
                        warn!("fanotify event {:?}\n{}", &each_metadata.mask, path);

                        for each_m in FILE_DEFAULT_MASK_S {
                            if match_event_mask(&each_metadata.mask, &each_m) {
                                let task = DetectTask {
                                    task_type: "6004".to_string(),
                                    pid: each_metadata.pid,
                                    path: path.to_string(),
                                    rpath: path.to_string(),
                                    size: 0,
                                    btime: 0,
                                    mtime: 0,
                                    token: "".to_string(),
                                };
                                warn!("fanotify event {:?}", task);

                                while sender.is_full() {
                                    std::thread::sleep(Duration::from_secs(2));
                                }
                                match sender.try_send(task) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("internal send task err : {:?}", e);
                                        continue;
                                    }
                                };
                                break;
                            }
                        }

                        let rcode = unsafe {
                            let retc = libc::close(each_metadata.fd);
                            debug!(
                                "close fd :{}; return:{}.",
                                each_metadata.fd,
                                libc::close(each_metadata.fd)
                            );
                            retc
                        };

                        if rcode != 0 {
                            error!("close fd :{}; return:{}.", each_metadata.fd, rcode);
                        };
                    }
                    metadata.clear();
                }
            });
            Ok(Self {
                fd: fd,
                pid: pid,
                worker_thread: child,
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
        if Path::new(path).exists() == false {
            return Ok(());
        }
        let cpath = CString::new(path).unwrap();
        if unsafe { libc::fanotify_mark(self.fd, FAN_MARK_ADD, DEFAULT_MASK, 0, cpath.as_ptr()) }
            != 0
        {
            let e = anyhow!(Error::last_os_error());
            warn!("fanotify err {:?}", e);
            warn!(
                "debug {:?} {:x} {:x} {:?} {:?}",
                self.fd,
                FAN_MARK_ADD,
                DEFAULT_MASK,
                path,
                cpath.as_ptr()
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
    (event & mask) == *mask
}
