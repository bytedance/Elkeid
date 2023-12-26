mod bindings;

use anyhow::{anyhow, Result};
use bindings::*;
use libc::c_int;
use std::{
    ffi::{c_void, CStr, CString},
    fs::{File, OpenOptions},
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub fn save_pre_unload() {
    unsafe { tb_pre_unload() }
}

pub struct RingSlot {
    control: Arc<AtomicBool>,
    buf: [u8; 32 * 1024],
}
impl RingSlot {
    pub fn new(dev_path: &str) -> Result<(Self, impl FnOnce()), i32> {
        let control = Arc::new(AtomicBool::new(false));
        let dev_path_cstr = CString::new(dev_path.as_bytes()).unwrap();
        let rc = unsafe { tb_init_ring(RING_KMOD, dev_path_cstr.as_ptr() as _) };
        if rc == 0 {
            Ok((
                Self {
                    control: control.clone(),
                    buf: [0; 32 * 1024],
                },
                move || {
                    if !control.swap(true, Ordering::SeqCst) {
                        unsafe {
                            libc::kill(libc::getpid(), libc::SIGUSR1);
                        }
                    }
                },
            ))
        } else {
            Err(rc)
        }
    }
    pub fn read_record(&mut self) -> Result<&[u8], i32> {
        let rc = unsafe {
            tb_read_ring(
                self.buf.as_mut_ptr(),
                self.buf.len() as i32,
                read_atomic_bool,
                &*self.control,
            )
        };
        if rc > 0 {
            let s = &self.buf[..(rc as usize)];
            match s.iter().rev().position(|p| *p != 0x00) {
                Some(p) => Ok(&s[..s.len() - p]),
                None => Err(-libc::EPROTO),
            }
        } else {
            Err(rc)
        }
    }
    pub fn canceled(&self) -> bool {
        self.control.load(Ordering::SeqCst)
    }
}

impl Drop for RingSlot {
    fn drop(&mut self) {
        if !self.control.swap(true, Ordering::SeqCst) {
            unsafe {
                libc::kill(libc::getpid(), libc::SIGUSR1);
            }
        }
        unsafe {
            tb_fini_ring();
        }
    }
}

pub struct SmithControl {
    buffer: Vec<u8>,
}

impl SmithControl {
    pub fn new(ctrl_path: &str) -> Result<Self> {
        unsafe {
            let ctrl_path_cstr = CString::new(ctrl_path.as_bytes()).unwrap();
            let rc = ac_init(RING_KMOD, ctrl_path_cstr.as_ptr() as _);
            if rc != 0 {
                return Err(anyhow!(
                    "ac_init({:x},{}) error:{}",
                    RING_KMOD,
                    ctrl_path,
                    rc
                ));
            }
        }
        return Ok(Self {
            buffer: Vec::with_capacity(1024 * 1024 * 8),
        });
    }

    pub fn clear_flag(&self, flag: c_int) -> Result<()> {
        unsafe {
            let mut rc = ac_clear(flag);
            if rc != 0 {
                return Err(anyhow!("ac_clear({:x}) error:{}", flag, rc));
            }
            return Ok(());
        }
    }

    pub fn clear_all(&self) -> Result<()> {
        unsafe {
            let mut rc = ac_clear(AL_TYPE_ARGV);
            if rc != 0 {
                return Err(anyhow!("ac_clear({:x}) error:{}", AL_TYPE_ARGV, rc));
            }

            rc = ac_clear(AL_TYPE_EXE);
            if rc != 0 {
                return Err(anyhow!("ac_clear({:x}) error:{}", AL_TYPE_EXE, rc));
            }

            rc = ac_clear(BL_JSON_MD5);
            if rc != 0 {
                return Err(anyhow!("ac_clear({:x}) error:{}", BL_JSON_MD5, rc));
            }

            rc = ac_clear(BL_JSON_EXE);
            if rc != 0 {
                return Err(anyhow!("ac_clear({:x}) error:{}", BL_JSON_EXE, rc));
            }

            /* rc = ac_clear(BL_JSON_DNS);
            if rc != 0 {
                return Err(anyhow!("ac_clear({:x}) error:{}", BL_JSON_DNS, rc));
            } */
        }
        return Ok(());
    }

    pub fn clear_all_force(&self) -> Result<()> {
        unsafe {
            let mut last_error = 0;
            let mut rc = ac_clear(AL_TYPE_ARGV);
            if rc != 0 {
                last_error |= 1;
            }

            rc = ac_clear(AL_TYPE_EXE);
            if rc != 0 {
                last_error |= 1 << 1;
            }

            rc = ac_clear(BL_JSON_MD5);
            if rc != 0 {
                last_error |= 1 << 2;
            }

            rc = ac_clear(BL_JSON_EXE);
            if rc != 0 {
                last_error |= 1 << 3;
            }

            /* rc = ac_clear(BL_JSON_DNS);
            if rc != 0 {
                last_error |= 1 << 4;
            } */

            if last_error != 0 {
                return Err(anyhow!(
                    "clear_all_force ({:02x}) error:{:08b}",
                    last_error,
                    last_error
                ));
            }
        }
        return Ok(());
    }

    pub fn ac_add_allow_exe_bytes(&self, target: &[u8]) -> Result<()> {
        unsafe {
            let cstr = CString::new(target)?;
            let rc = ac_setup(AL_TYPE_EXE, cstr.as_ptr() as _, target.len() as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{}) error:{}",
                    AL_TYPE_EXE,
                    target,
                    target.len(),
                    rc
                ));
            }
        }

        return Ok(());
    }

    pub fn ac_add_allow_exe(&self, target: &str) -> Result<()> {
        return self.ac_add_allow_exe_bytes(target.as_bytes());
    }

    pub fn ac_add_allow_argv_bytes(&self, target: &[u8]) -> Result<()> {
        unsafe {
            let cstr = CString::new(target)?;
            let rc = ac_setup(AL_TYPE_ARGV, cstr.as_ptr() as _, target.len() as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{}) error:{}",
                    AL_TYPE_ARGV,
                    target,
                    target.len(),
                    rc
                ));
            }
        }
        return Ok(());
    }

    pub fn ac_add_allow_argv(&self, target: &str) -> Result<()> {
        return self.ac_add_allow_argv_bytes(target.as_bytes());
    }

    pub fn ac_query_allow_exe(&mut self) -> Result<i32> {
        unsafe {
            self.buffer.clear();
            let rc = ac_query(
                AL_TYPE_EXE,
                self.buffer.as_mut_ptr() as _,
                (1024 * 1024 * 8) as _,
            );
            return Ok(rc);
        }
    }

    pub fn ac_query_allow_argv(&mut self) -> Result<i32> {
        unsafe {
            self.buffer.clear();
            let rc = ac_query(
                AL_TYPE_ARGV,
                self.buffer.as_mut_ptr() as _,
                (1024 * 1024 * 8) as _,
            );
            return Ok(rc);
        }
    }

    pub fn ac_check_allow_exe(&self, target: &str) -> Result<i32> {
        unsafe {
            let target_cstr = CString::new(target.as_bytes())?;
            let rc = ac_check(AL_TYPE_EXE, target_cstr.as_ptr() as _, target.len() as _);
            return Ok(rc);
        }
    }

    pub fn ac_check_allow_argv(&self, target: &str) -> Result<i32> {
        unsafe {
            let target_cstr = CString::new(target.as_bytes())?;
            let rc = ac_check(AL_TYPE_ARGV, target_cstr.as_ptr() as _, target.len() as _);
            return Ok(rc);
        }
    }

    pub fn ac_del_allow_exe_bytes(&self, target: &[u8]) -> Result<()> {
        unsafe {
            let target_cstr = CString::new(target)?;
            let rc = ac_erase(AL_TYPE_EXE, target_cstr.as_ptr() as _, target.len() as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_erase({:x},{:?}) error:{}",
                    AL_TYPE_EXE,
                    target,
                    rc
                ));
            }
        }
        return Ok(());
    }

    pub fn ac_del_allow_exe(&self, target: &str) -> Result<()> {
        return self.ac_del_allow_exe_bytes(target.as_bytes());
    }

    pub fn ac_del_allow_argv_bytes(&self, target: &[u8]) -> Result<()> {
        unsafe {
            let target_cstr = CString::new(target)?;
            let rc = ac_erase(AL_TYPE_ARGV, target_cstr.as_ptr() as _, target.len() as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_erase({:x},{:?}) error:{}",
                    AL_TYPE_ARGV,
                    target,
                    rc
                ));
            }
        }
        return Ok(());
    }

    pub fn ac_del_allow_argv(&self, target: &str) -> Result<()> {
        return self.ac_del_allow_argv_bytes(target.as_bytes());
    }

    pub fn ac_set_block_md5(&self, json_cfg_path: &str) -> Result<()> {
        unsafe {
            let buf: Vec<u8> = std::fs::read(json_cfg_path)?;
            let target_cstr = CString::new(buf.as_slice()).unwrap();
            let rc = ac_setup(BL_JSON_MD5, target_cstr.as_ptr() as _, buf.len() as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{}) error {}",
                    BL_JSON_MD5,
                    &target_cstr,
                    buf.len(),
                    rc
                ));
            }
        }
        return Ok(());
    }

    pub fn ac_set_block_exe_argv(&self, json_cfg_path: &str) -> Result<()> {
        unsafe {
            let buf = std::fs::read(json_cfg_path)?;
            let target_cstr = CString::new(buf.as_slice())?;
            let rc = ac_setup(BL_JSON_EXE, target_cstr.as_ptr() as _, buf.len() as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{}) error {}",
                    BL_JSON_EXE,
                    &target_cstr,
                    buf.len(),
                    rc
                ));
            }
        }
        return Ok(());
    }

    pub fn ac_set_block_dns(&self, json_cfg_path: &str) -> Result<()> {
        unsafe {
            let buf = std::fs::read(json_cfg_path)?;
            let target_cstr = CString::new(buf.as_slice())?;
            let rc = ac_setup(BL_JSON_DNS, target_cstr.as_ptr() as _, buf.len() as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{}) error {}",
                    BL_JSON_DNS,
                    &target_cstr,
                    buf.len(),
                    rc
                ));
            }
        }
        return Ok(());
    }

    pub fn psad_enable(&self) -> Result<()> {
        return control_flag(
            "/sys/module/hids_driver/parameters/psad_switch",
            ENABLE_PSAD_SWITHER,
        );
    }

    pub fn psad_disable(&self) -> Result<()> {
        return control_flag(
            "/sys/module/hids_driver/parameters/psad_switch",
            DISABLE_PSAD_SWITHER,
        );
    }
    pub fn psad_set_flag(&self, flags: &Vec<usize>) -> Result<()> {
        let setstring: String = gen_psad_flag(flags);
        return control_flag(
            "/sys/module/hids_driver/parameters/psad_flags",
            &setstring.as_bytes(),
        );
    }

    pub fn psad_add_allowlist_ipv4(&self, iplist: &Vec<String>) -> Result<()> {
        let setdata = gen_psad_ipv4_allowlist(iplist);
        unsafe {
            let set_bufsize = std::mem::size_of_val(&*setdata);
            let rc = ac_setup(AL_TYPE_PSAD, setdata.as_ptr() as _, set_bufsize as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{:?},{}) error {}",
                    AL_TYPE_PSAD,
                    &iplist,
                    &setdata,
                    set_bufsize,
                    rc
                ));
            }
            if set_bufsize as c_int != rc {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{:?},{}) fault rc {}",
                    AL_TYPE_PSAD,
                    &iplist,
                    &setdata,
                    set_bufsize,
                    rc
                ));
            }
        }
        return Ok(());
    }

    pub fn psad_add_allowlist_ipv6(&self, iplist: &Vec<String>) -> Result<()> {
        let setdata = gen_psad_ipv6_allowlist(iplist);
        unsafe {
            let set_bufsize = std::mem::size_of_val(&*setdata);

            let rc = ac_setup(AL_TYPE_PSAD, setdata.as_ptr() as _, set_bufsize as _);
            if rc < 0 {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{:?},{}) error {}",
                    AL_TYPE_PSAD,
                    &iplist,
                    &setdata,
                    set_bufsize,
                    rc
                ));
            }
            if set_bufsize as c_int != rc {
                return Err(anyhow!(
                    "ac_setup({:x},{:?},{:?},{}) fault rc {}",
                    AL_TYPE_PSAD,
                    &iplist,
                    &setdata,
                    set_bufsize,
                    rc
                ));
            }
        }
        return Ok(());
    }
}

impl Drop for SmithControl {
    fn drop(&mut self) {
        unsafe {
            ac_fini(RING_KMOD);
        }
    }
}

fn control_flag(controler: &str, flag: &[u8]) -> Result<()> {
    let mut fcontroler = match OpenOptions::new().write(true).open(controler) {
        Ok(f) => f,
        Err(err) => {
            return Err(err.into());
        }
    };
    let mut buf = Vec::with_capacity(flag.len() + 1);
    buf.extend_from_slice(flag);
    buf.push(b'\n');
    let _ = fcontroler.write_all(&buf);
    return Ok(());
}
