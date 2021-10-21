use anyhow::{anyhow, Result};
use libc::c_int;
use std::{
    io::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
pub struct Handler {
    control: Arc<AtomicBool>,
}
impl Handler {
    pub fn new() -> Self {
        Self {
            control: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn close(&self) {
        self.control.store(true, Ordering::SeqCst);
        unsafe {
            libc::kill(libc::getpid(), libc::SIGUSR1);
        }
    }
    pub fn get_inner(&self) -> Arc<AtomicBool> {
        return self.control.clone();
    }
}
impl Drop for Handler {
    fn drop(&mut self) {
        self.close()
    }
}
extern "C" fn read_atomic_bool(value: *const AtomicBool) -> c_int {
    unsafe { (*value).load(Ordering::SeqCst) as c_int }
}
extern "C" {
    fn rs_init_ring() -> c_int;
    fn rs_fini_ring();
    fn rs_read_ring(
        msg: *const u8,
        len: c_int,
        cb: extern "C" fn(*const AtomicBool) -> c_int,
        ctx: *const AtomicBool,
    ) -> c_int;
}
pub struct RingSlot {
    control: Arc<AtomicBool>,
    buf: [u8; 32 * 1024],
    offset: usize,
}
impl RingSlot {
    pub fn new(control: Arc<AtomicBool>) -> Result<Self> {
        let rc = unsafe { rs_init_ring() };
        if rc == 0 {
            Ok(Self {
                control,
                buf: [0; 32 * 1024],
                offset: 0,
            })
        } else {
            Err(Error::from_raw_os_error(-rc).into())
        }
    }
    pub fn read_rec(&mut self) -> Result<&[u8]> {
        let rc = unsafe {
            rs_read_ring(
                self.buf.as_mut_ptr(),
                self.buf.len() as i32,
                read_atomic_bool,
                &*self.control,
            )
        };
        if self.control.load(Ordering::SeqCst) {
            return Err(anyhow!("control has been set to exit"));
        };
        if rc > 0 {
            self.offset = rc as usize;
            // trim /u0000
            Ok(&self.buf[0..if self.buf[self.offset - 1] == 0 {
                self.offset - 1
            } else {
                self.offset
            }])
        } else {
            Err(anyhow!("unknown error"))
        }
    }
}

impl Drop for RingSlot {
    fn drop(&mut self) {
        self.control.store(true, Ordering::SeqCst);
        unsafe {
            libc::kill(libc::getpid(), libc::SIGUSR1);
            rs_fini_ring()
        }
    }
}
