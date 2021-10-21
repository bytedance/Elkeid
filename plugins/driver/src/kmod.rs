use crate::{config::*, utils::download};
use anyhow::{anyhow, Result};
use log::*;
use nix::{
    kmod::{self, finit_module},
    sys::utsname::uname,
};
use parking_lot::Mutex;
use std::{
    env::consts::ARCH,
    ffi::CString,
    fs::{read_to_string, File, OpenOptions},
    io::Write,
    mem::replace,
    process::Command,
    sync::Arc,
};
fn control(controler: &mut File, flag: &[u8], contents: &[u8]) {
    let mut buf = Vec::with_capacity(flag.len() + contents.len() + 1);
    buf.extend_from_slice(flag);
    buf.extend_from_slice(contents);
    buf.push(b'\n');
    let _ = controler.write_all(&buf);
}
pub struct Kmod {
    controler: Arc<Mutex<Option<File>>>,
}

impl Kmod {
    pub fn new() -> Result<Self> {
        Self::install()?;
        let controler = match OpenOptions::new().write(true).open(CONTROL_PATH) {
            Ok(f) => f,
            Err(err) => {
                let _ = kmod::delete_module(
                    &CString::new(KMOD_NAME).unwrap(),
                    kmod::DeleteModuleFlags::empty(),
                );
                return Err(err.into());
            }
        };
        let controler = Arc::new(Mutex::new(Some(controler)));
        let mut res = Self { controler };
        for argv in ARGV_WHITELIST {
            res.add_filtered_argv_fixed(argv);
        }
        for exe in EXE_WHITELIST {
            res.add_filtered_exe_fixed(exe);
        }
        Ok(res)
    }
    fn install() -> Result<()> {
        // 判断目前加载的版本是否是最新版本
        if let Ok(version) = read_to_string(format!("/sys/module/{}/version", KMOD_NAME)) {
            if version.contains(KMOD_VERSION) {
                info!("kmod is the latest version");
                let mut controler = OpenOptions::new().write(true).open(CONTROL_PATH)?;
                control(&mut controler, REMOVE_ALL_ARGV_FILTER_FLAG, PADDING_CONTENT);
                control(&mut controler, REMOVE_ALL_EXE_FILTER_FLAG, PADDING_CONTENT);
                return Ok(());
            } else {
                info!("kmod isn't latest version,deleting old version...");
                kmod::delete_module(
                    &CString::new(KMOD_NAME).unwrap(),
                    kmod::DeleteModuleFlags::empty(),
                )?;
                info!("delete success");
            }
        };
        let ko_dst = format!(
            "{}_latest_{}_{}.ko",
            KMOD_NAME,
            uname().release(),
            match ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                default => default,
            }
        );
        if let Ok(output) = Command::new("modinfo")
            .arg(&ko_dst)
            .env("PATH", "/sbin:/usr/sbin")
            .output()
        {
            if output.status.success()
                && String::from_utf8(output.stdout)
                    .unwrap_or_default()
                    .lines()
                    .any(|line| line.contains("version") && line.contains(KMOD_VERSION))
            {
                if let Ok(f) = File::open(&ko_dst) {
                    return finit_module(
                        &f,
                        &CString::new("").unwrap(),
                        kmod::ModuleInitFlags::empty(),
                    )
                    .map_err(|err| anyhow!("load module failed: {}", err));
                }
            }
        }
        let src = format!(
            "{}_{}_{}_{}.ko",
            KMOD_NAME,
            KMOD_VERSION,
            uname().release(),
            match ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                default => default,
            }
        );
        download(&src, &ko_dst)?;
        let file = File::open(ko_dst)?;
        finit_module(
            &file,
            &CString::new("").unwrap(),
            kmod::ModuleInitFlags::empty(),
        )
        .map_err(|err| anyhow!("load module failed: {}", err))
    }

    pub fn add_filtered_argv_fixed(&mut self, argv: &[u8]) {
        let mut controler = self.controler.lock();
        control(
            (*(controler)).as_mut().unwrap(),
            ADD_ARGV_FILTER_FLAG,
            &argv,
        );
    }

    pub fn add_filtered_exe_fixed(&mut self, exe: &[u8]) {
        let mut controler = self.controler.lock();
        control((*(controler)).as_mut().unwrap(), ADD_EXE_FILTER_FLAG, &exe);
    }
}
impl Drop for Kmod {
    fn drop(&mut self) {
        let mut controler = self.controler.lock();
        let controler = replace(&mut (*controler), None);
        drop(controler);
        let _ = kmod::delete_module(
            &CString::new(KMOD_NAME).unwrap(),
            kmod::DeleteModuleFlags::empty(),
        );
    }
}
