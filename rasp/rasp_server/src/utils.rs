use anyhow::Result as AnyhowResult;
use procfs::process;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn four_bytes_to_num(array: [u8; 4]) -> usize {
    let res = ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + ((array[3] as u32) << 0);
    // res.to_usize()
    res as usize
}

// BE
pub fn num_to_four_bytes(len: usize) -> [u8; 4] {
    let x = len as usize;
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4];
}

pub struct ByteBuf<'a>(pub &'a [u8]);

impl<'a> std::fmt::LowerHex for ByteBuf<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for byte in self.0 {
            fmtr.write_fmt(format_args!("{:02x}", byte))?;
        }
        Ok(())
    }
}

pub fn generate_timestamp_f64() -> f64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time wen backwards");
    since_the_epoch.as_secs_f64()
}

// https://stackoverflow.com/questions/35883390/how-to-check-if-a-thread-has-finished-in-rust
// https://stackoverflow.com/a/39615208
#[derive(Clone)]
pub struct Control {
    pub working_atomic: Arc<AtomicBool>,
    pub control: Weak<AtomicBool>,
}

impl Control {
    pub fn new() -> Self {
        let working = Arc::new(AtomicBool::new(true));
        let control = Arc::downgrade(&working);
        Control {
            working_atomic: working,
            control,
        }
    }
    pub fn check(&mut self) -> bool {
        (*self.working_atomic).load(Ordering::Relaxed)
    }
    pub fn stop(&mut self) -> Result<(), ()> {
        return match self.control.upgrade() {
            Some(working) => {
                (*working).store(false, Ordering::Relaxed);
                Ok(())
            }
            None => {
                // world stopped
                Err(())
            }
        };
    }
}

pub fn time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn generate_patch(pid: i32) -> AnyhowResult<HashMap<String, String>> {
    let proc = process::Process::new(pid)?;
    let mut res = HashMap::new();
    let sid = proc.stat.session;
    res.insert("sid".to_string(), sid.to_string());
    res.insert("ppid".to_string(), proc.stat.ppid.to_string());
    res.insert("tgid".to_string(), proc.stat.tpgid.to_string());
    res.insert(
        "exe".to_string(),
        match proc.exe() {
            Ok(p) => String::from(p.to_string_lossy()),
            Err(_) => String::new(),
        },
    );
    res.insert(
        "argv".to_string(),
        match proc.cmdline() {
            Ok(cv) => cv.join(" "),
            Err(_) => String::new(),
        },
    );
    let status_result = proc.status();
    if let Ok(status) = status_result {
        res.insert("ruid".to_string(), status.ruid.to_string());
        res.insert("rgid".to_string(), status.rgid.to_string());
        res.insert("euid".to_string(), status.euid.to_string());
        res.insert("egid".to_string(), status.egid.to_string());
        res.insert("suid".to_string(), status.suid.to_string());
        res.insert("sgid".to_string(), status.sgid.to_string());
        res.insert("fuid".to_string(), status.fuid.to_string());
        res.insert("fgid".to_string(), status.fgid.to_string());
    }
    // debug!("update patch_field: {:?}", patch_field);
    Ok(res)
}
