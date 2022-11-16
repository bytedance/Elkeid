use crate::{config::*, utils::download};
use anyhow::{anyhow, Result};
use log::*;
use nix::{
    kmod::{self, finit_module},
    sys::utsname::uname,
};
use parking_lot::Mutex;
use plugins::{Client, Record};
use serde_json::to_string;
use std::{
    borrow::Cow,
    collections::VecDeque,
    env::consts::ARCH,
    ffi::CString,
    fs::{read_to_string, File, OpenOptions},
    io::Write,
    mem::replace,
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use walkdir::WalkDir;
fn control(controler: &mut File, flag: &[u8], contents: &[u8]) {
    let mut buf = Vec::with_capacity(flag.len() + contents.len() + 1);
    buf.extend_from_slice(flag);
    buf.extend_from_slice(contents);
    buf.push(b'\n');
    let _ = controler.write_all(&buf);
}
fn check_crash() -> Result<()> {
    // walk through all crashes
    for entry in WalkDir::new("/var/crash")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().is_some())
    {
        let file_name = entry.file_name().to_str().unwrap_or_default();
        let is_expired = std::time::SystemTime::now()
            .duration_since(entry.metadata().unwrap().modified().unwrap())
            .unwrap()
            > std::time::Duration::from_secs(48 * 60 * 60);
        if is_expired {
            continue;
        }
        // [smith]
        if file_name.starts_with("dmesg") {
            let content = read_to_string(entry.path()).unwrap_or_default();
            if content.find(format!("[{}]", KMOD_NAME).as_str()).is_some() {
                return Err(anyhow!("detect driver crash: {}", content));
            } else {
                return Ok(());
            }
        }
    }
    Ok(())
}
pub struct Kmod {
    filtered_exe_entries: Arc<Mutex<VecDeque<(Instant, Vec<u8>)>>>,
    filtered_argv_entries: Arc<Mutex<VecDeque<(Instant, Vec<u8>)>>>,
    controler: Arc<Mutex<Option<File>>>,
}

impl Kmod {
    pub fn new(mut client: Client) -> Result<Self> {
        check_crash()?;
        Self::install(&mut client)?;
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
        let controler_c = controler.clone();
        let filtered_exe_entries = Arc::new(Mutex::new(VecDeque::<(Instant, Vec<u8>)>::new()));
        let filtered_argv_entries = Arc::new(Mutex::new(VecDeque::<(Instant, Vec<u8>)>::new()));
        let filtered_exe_entries_c = filtered_exe_entries.clone();
        let filtered_argv_entries_c = filtered_argv_entries.clone();
        let filtered_exe_entries_c1 = filtered_exe_entries.clone();
        let filtered_argv_entries_c1 = filtered_argv_entries.clone();
        let mut res = Self {
            filtered_exe_entries,
            filtered_argv_entries,
            controler,
        };
        for argv in ARGV_WHITELIST {
            res.add_filtered_argv_fixed(argv);
        }
        for exe in EXE_WHITELIST {
            res.add_filtered_exe_fixed(exe);
        }
        let _ = thread::Builder::new()
            .name("ttl_filters".to_string())
            .spawn(move || loop {
                {
                    let mut filtered_exe_entries = filtered_exe_entries_c.lock();
                    loop {
                        if let Some((instant, exe)) = filtered_exe_entries.pop_front() {
                            if instant.elapsed() < EXE_FILTER_TIME {
                                filtered_exe_entries.push_front((instant, exe));
                                break;
                            }
                            let mut controler = controler_c.lock();
                            if let Some(controler) = &mut (*controler) {
                                control(controler, REMOVE_EXE_FILTER_FLAG, exe.as_slice());
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    let mut filtered_argv_entries = filtered_argv_entries_c.lock();
                    loop {
                        if let Some((instant, argv)) = filtered_argv_entries.pop_front() {
                            if instant.elapsed() < ARGV_FILTER_TIME {
                                filtered_exe_entries.push_front((instant, argv));
                                break;
                            }
                            let mut controler = controler_c.lock();
                            if let Some(controler) = &mut (*controler) {
                                control(controler, REMOVE_ARGV_FILTER_FLAG, argv.as_slice());
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
                thread::sleep(Duration::from_secs(5));
            });
        let _ = thread::Builder::new()
            .name("heartbeat".to_string())
            .spawn(move || loop {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let mut rec = Record::new();
                rec.timestamp = timestamp as i64;
                {
                    let filtered_exe_entries = filtered_exe_entries_c1.lock();
                    let filtered_argv_entries = filtered_argv_entries_c1.lock();
                    // let monitored_write_entries = monitored_write_entries_c1.lock();
                    rec.data_type = 900;
                    let pld = rec.mut_data();
                    pld.fields.insert(
                        "filtered_exe_entries".to_string(),
                        to_string(
                            &filtered_exe_entries
                                .iter()
                                .map(|(k, v)| (k.elapsed().as_secs(), String::from_utf8_lossy(v)))
                                .collect::<Vec<(u64, Cow<'_, str>)>>(),
                        )
                        .unwrap(),
                    );
                    pld.fields.insert(
                        "filtered_argv_entries".to_string(),
                        to_string(
                            &filtered_argv_entries
                                .iter()
                                .map(|(k, v)| (k.elapsed().as_secs(), String::from_utf8_lossy(v)))
                                .collect::<Vec<(u64, Cow<'_, str>)>>(),
                        )
                        .unwrap(),
                    );
                    let dir = WalkDir::new(PARAMETERS_DIR);
                    for file in dir {
                        if let Ok(file) = file {
                            if let Ok(parameter) = read_to_string(file.path()) {
                                pld.fields.insert(
                                    file.file_name().to_str().unwrap().to_owned(),
                                    parameter.trim().to_owned(),
                                );
                            }
                        }
                    }
                    // pld.fields.insert(
                    //     "monitored_write_entries".to_string(),
                    //     to_string(&*monitored_write_entries).unwrap(),
                    // );
                }
                if let Err(err) = client.send_record(&rec) {
                    warn!("heartbeat will exit: {}", err);
                    break;
                };
                info!("heartbeat: {:?}", rec.get_data().get_fields());
                thread::sleep(Duration::from_secs(30))
            });
        Ok(res)
    }
    fn install(client: &mut Client) -> Result<()> {
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
                    .or_else(|_| {
                        match Command::new("insmod")
                            .arg(ko_dst)
                            .env("PATH", "/sbin:/usr/sbin")
                            .output()
                        {
                            Err(err) => Err(err.into()),
                            Ok(output) => {
                                if !output.status.success() {
                                    return Err(anyhow!(String::from_utf8(output.stderr).unwrap()));
                                } else {
                                    return Ok(());
                                }
                            }
                        }
                    })
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
        loop {
            match download(&src, &ko_dst) {
                Ok(_) => break,
                Err(err) => {
                    let mut rec = Record::new();
                    rec.set_data_type(901);
                    rec.set_timestamp(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64,
                    );
                    rec.mut_data()
                        .fields
                        .insert("kmod_version".into(), KMOD_VERSION.into());
                    rec.mut_data()
                        .fields
                        .insert("kernel_version".into(), uname().release().into());
                    rec.mut_data().fields.insert(
                        "arch".into(),
                        match ARCH {
                            "x86_64" => "amd64",
                            "aarch64" => "arm64",
                            default => default,
                        }
                        .into(),
                    );
                    client.send_record(&rec).unwrap();
                    match err.downcast::<ureq::Error>() {
                        Ok(inner_err) => match inner_err {
                            ureq::Error::Status(500, _) | ureq::Error::Status(404, _) => {
                                warn!("cann't download driver kmod temporary, sleeping...");
                                std::thread::sleep(std::time::Duration::from_secs(3600));
                            }
                            _ => {
                                return Err(inner_err.into());
                            }
                        },
                        Err(err) => {
                            return Err(err.into());
                        }
                    };
                }
            }
        }
        let file = File::open(&ko_dst)?;
        finit_module(
            &file,
            &CString::new("").unwrap(),
            kmod::ModuleInitFlags::empty(),
        )
        .or_else(|_| {
            match Command::new("insmod")
                .arg(ko_dst)
                .env("PATH", "/sbin:/usr/sbin")
                .output()
            {
                Err(err) => Err(err.into()),
                Ok(output) => {
                    if !output.status.success() {
                        return Err(anyhow!(String::from_utf8(output.stderr).unwrap()));
                    } else {
                        return Ok(());
                    }
                }
            }
        })
        .map_err(|err| anyhow!("load module failed: {}", err))
    }
    pub fn add_filtered_argv(&mut self, argv: &[u8]) {
        let mut controler = self.controler.lock();
        let mut filtered_argv_entries = self.filtered_argv_entries.lock();
        if filtered_argv_entries.len() >= 128 - ARGV_WHITELIST.len() {
            let (_, front_argv) = filtered_argv_entries.pop_front().unwrap();
            control(
                (*(controler)).as_mut().unwrap(),
                REMOVE_ARGV_FILTER_FLAG,
                &front_argv,
            );
        }
        control(
            (*(controler)).as_mut().unwrap(),
            ADD_ARGV_FILTER_FLAG,
            &argv,
        );
        filtered_argv_entries.push_back((Instant::now(), argv.to_vec()));
    }
    pub fn add_filtered_argv_fixed(&mut self, argv: &[u8]) {
        let mut controler = self.controler.lock();
        control(
            (*(controler)).as_mut().unwrap(),
            ADD_ARGV_FILTER_FLAG,
            &argv,
        );
    }
    pub fn add_filtered_exe(&mut self, exe: &[u8]) {
        let mut controler = self.controler.lock();
        let mut filtered_exe_entries = self.filtered_exe_entries.lock();
        if filtered_exe_entries.len() > 128 - EXE_WHITELIST.len() {
            let (_, front_exe) = filtered_exe_entries.pop_front().unwrap();
            control(
                (*(controler)).as_mut().unwrap(),
                REMOVE_EXE_FILTER_FLAG,
                &front_exe,
            );
        }
        control((*(controler)).as_mut().unwrap(), ADD_EXE_FILTER_FLAG, &exe);
        filtered_exe_entries.push_back((Instant::now(), exe.to_vec()));
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
        )
        .or_else(|_| {
            Command::new("rmmod")
                .arg(KMOD_NAME)
                .env("PATH", "/sbin:/usr/sbin")
                .spawn()
                .map(|_| ())
        });
    }
}
