use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use log::*;
use nix::unistd::{chown, Gid, Uid};
use std::{
    collections::HashMap,
    fs,
    io::{self, BufRead, BufReader, Read},
    path::Path,
    sync::{Arc, Mutex},
    thread,
};

use phf::{phf_map, Map};

use crate::data_type::{AnitRansomFunc, AntiRansomEvent, DETECT_TASK};
use procfs::sys::kernel::Version;

use super::fmonitor::FileMonitor;

lazy_static! {
    pub static ref H26_KERNEL_VERSION: Version = Version::new(2, 6, 37);
    static ref AN_CHECK_KEY: regex::bytes::Regex =
        regex::bytes::Regex::new(r"6a4c1ebe0dbf718afcf110469c0d6ac4beab6e837646eea5f1c5edd0da73b08ba0336feaab383712872582b5054a56895adbda56c45aebdcac0e7a4f6fc976af").unwrap();
}

pub static HONEYPOTSSHA256: Map<&'static str, &'static str> = phf_map! {
    "0_elkeid_hids_anti_ransom.csv" => "71457f09ba8fe11a0ee50c27c56a0482286955e7ec7821729875c2a30ebfb4eb",
    "0_elkeid_hids_anti_ransom.doc" => "5c77d3b491bc678f27e44193346fbc0c853a08efe900eefb40c7b0f7ef17870e",
    "0_elkeid_hids_anti_ransom.pdf" => "4f63c17039909dc985e4eb3647271bca87d022d06a511064e9b10d9706f75979",
    "0_elkeid_hids_anti_ransom.png" => "1fd2e99445b30f2945ba74092c3517e625daf1be31b4144a108dd0bebf73b5c4",
    "0_elkeid_hids_anti_ransom.txt" => "fb4877e0f8094877bd7cf8f0a87a3d9d3ea82e000889881cb6a405a178cbbdbb",
    "0_elkeid_hids_anti_ransom.xls" => "f8ef4abc6cd51f73587c989fd6528d9d2d27875910714e7bf4113a2c16233b15",
};

pub static HONEYPOTS: &[&str] = &[
    "0_elkeid_hids_anti_ransom.csv",
    "0_elkeid_hids_anti_ransom.png",
    "0_elkeid_hids_anti_ransom.txt",
    "0_elkeid_hids_anti_ransom.xls",
    "0_elkeid_hids_anti_ransom.doc",
    "0_elkeid_hids_anti_ransom.pdf",
];

pub struct HoneyPot {
    pub target_md5maps: HashMap<String, String>,
    pub user_homes: HashMap<String, (u32, u32, String)>,
    pub sender: crossbeam_channel::Sender<DETECT_TASK>,
    pub s_locker: crossbeam_channel::Sender<()>,
    pub anti_ransome_status: Arc<Mutex<String>>,
    pub moniter: FileMonitor,
    _cronjob_report_antiransom_statue: Option<thread::JoinHandle<()>>,
    _cronjob_refresh_monitor: Option<thread::JoinHandle<()>>,
}

impl HoneyPot {
    pub fn new(
        sender: crossbeam_channel::Sender<DETECT_TASK>,
        s_locker: crossbeam_channel::Sender<()>,
    ) -> Result<Self> {
        let current_kernel_version = Version::current().unwrap();
        let is = sender.clone();
        let is_l = s_locker.clone();

        if current_kernel_version < *H26_KERNEL_VERSION {
            return Err(anyhow!(
                "kernel version unsupported {:?}",
                current_kernel_version
            ));
        }
        let anti_ransome_status = Arc::new(Mutex::new("off".to_string()));

        let mut target_md5maps = HashMap::new();
        let mut user_homes = HashMap::<String, (u32, u32, String)>::new();

        let etc_passwd = fs::File::open("/etc/passwd")?;
        let reader = BufReader::new(etc_passwd);

        for line in reader.lines() {
            if let Ok(each_line) = line {
                let lvec: Vec<&str> = each_line.split(":").into_iter().collect();
                let uid: u32 = lvec[2].parse().unwrap_or_default();
                let gid: u32 = lvec[3].parse().unwrap_or_default();
                if lvec[6].ends_with("sh")
                    && (lvec[5].starts_with("/root") || lvec[5].starts_with("/home"))
                {
                    user_homes.insert(lvec[0].to_string(), (uid, gid, lvec[5].to_string()));
                    let dst = format!("{}/elkeid_targets", lvec[5]);
                    fs::remove_dir_all(dst);
                }
            }
        }

        // file_monitor scan
        let mut fmonitor_t = FileMonitor::new(sender, s_locker, 16, 4096)?;

        let fmonitor_cfg = crate::config::gen_fmonitor_cfg()?;
        for each in &fmonitor_cfg {
            if let Err(e) = fmonitor_t.add_cfg(&each) {
                warn!("reset_fanotify add_cfg Err {:?}", e);
            }
        }

        // file_monitor support docker
        let docker_path_list = parse_docker_mountinfo()?;
        for each_docker in &docker_path_list {
            for each_cfg in &fmonitor_cfg {
                let tmp_docker_cfg = each_cfg.with_prefix(each_docker);
                if let Err(e) = fmonitor_t.add_cfg(&tmp_docker_cfg) {
                    warn!(
                        "reset_fanotify add_cfg Err {:?},with {:?}",
                        e, tmp_docker_cfg
                    );
                }
            }
        }

        return Ok(Self {
            target_md5maps: target_md5maps,
            user_homes: user_homes,
            anti_ransome_status: anti_ransome_status,
            sender: is,
            s_locker: is_l,
            moniter: fmonitor_t,
            _cronjob_report_antiransom_statue: None,
            _cronjob_refresh_monitor: None,
        });
    }
    pub fn reset_monitor(&mut self) -> Result<()> {
        let mut w = self.anti_ransome_status.lock().unwrap();
        let current_stat = w.to_string();
        drop(w);
        if &current_stat == "on" {
            self.reset_antiransome()?;
        } else {
            self.reset_fanotify()?;
        }
        return Ok(());
    }
    pub fn reset_fanotify(&mut self) -> Result<()> {
        self.moniter.flush();

        for (k, (uid, gid, home_path)) in &self.user_homes {
            let dst = format!("{}/elkeid_targets", home_path);
            fs::remove_dir_all(dst);
        }

        let fmonitor_cfg = crate::config::gen_fmonitor_cfg()?;

        for each_cfg in &fmonitor_cfg {
            if let Err(e) = self.moniter.add_cfg(&each_cfg) {
                warn!("reset_fanotify add_cfg Err {:?},with {:?}", e, each_cfg);
            }
        }
        // file_monitor support docker
        let docker_path_list = parse_docker_mountinfo()?;
        for each_docker in &docker_path_list {
            for each_cfg in &fmonitor_cfg {
                let tmp_docker_cfg = each_cfg.with_prefix(each_docker);
                if let Err(e) = self.moniter.add_cfg(&tmp_docker_cfg) {
                    warn!(
                        "reset_fanotify add_cfg Err {:?},with {:?}",
                        e, tmp_docker_cfg
                    );
                }
            }
        }

        let mut w = self.anti_ransome_status.lock().unwrap();
        *w = "off".to_string();
        drop(w);
        return Ok(());
    }

    pub fn reset_antiransome(&mut self) -> Result<()> {
        self.reset_fanotify()?;
        for (k, (uid, gid, home_path)) in &self.user_homes {
            let dst = format!("{}/elkeid_targets", home_path);
            copy_elkeid_targets(&dst, uid.to_owned(), gid.to_owned())?;
            for each_target in HONEYPOTS {
                if let Err(e) = self.moniter.add(&format!("{}/{}", &dst, each_target), true) {
                    warn!("fmonitor add fpath err {:?}:{:?}", &dst, e);
                }
            }
        }
        let mut w = self.anti_ransome_status.lock().unwrap();
        *w = "on".to_string();
        drop(w);
        return Ok(());
    }

    pub fn run_cronjob(&mut self) {
        let sender = self.sender.clone();
        let s_locker = self.s_locker.clone();
        let anti_ransome_status = self.anti_ransome_status.clone();

        // anti_ransom status report cronjob
        let recv_worker = thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(60));
            let status = {
                let arfs = anti_ransome_status.lock().unwrap();
                let s = arfs.as_str().to_string();
                drop(arfs);
                s
            };
            let event = AnitRansomFunc { status: status };
            if let Err(e) = sender.send(DETECT_TASK::TASK_6054_TASK_6054_ANTIVIRUS_STATUS(event)) {
                warn!("internal task send err {:?}", e);
                s_locker.send(()).unwrap();
            };
            thread::sleep(std::time::Duration::from_secs(540));
        });
        self._cronjob_report_antiransom_statue = Some(recv_worker);

        let sender = self.sender.clone();
        let s_locker = self.s_locker.clone();
        let anti_ransome_status = self.anti_ransome_status.clone();

        let raw_monitorfd = self.moniter.fd;
        // anti_ransom reset cronjob
        let recv_worker = thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(3600 * 4));

            FileMonitor::raw_flush(raw_monitorfd);
            // file_monitor scan
            let fmonitor_cfg = crate::config::gen_fmonitor_cfg().unwrap();
            for each in &fmonitor_cfg {
                if let Err(e) = FileMonitor::raw_add_cfg(raw_monitorfd, &each) {
                    warn!("reset_fanotify add_cfg Err {:?}", e);
                }
            }
            // file_monitor support docker
            let docker_path_list = parse_docker_mountinfo().unwrap_or_default();
            for each_docker in &docker_path_list {
                for each_cfg in &fmonitor_cfg {
                    let tmp_docker_cfg = each_cfg.with_prefix(each_docker);
                    if let Err(e) = FileMonitor::raw_add_cfg(raw_monitorfd, &tmp_docker_cfg) {
                        warn!(
                            "reset_fanotify add_cfg Err {:?},with {:?}",
                            e, tmp_docker_cfg
                        );
                    }
                }
            }

            let status = {
                let arfs = anti_ransome_status.lock().unwrap();
                let s = arfs.as_str().to_string();
                drop(arfs);
                s
            };
            if status.contains("on") {
                let etc_passwd = match fs::File::open("/etc/passwd") {
                    Ok(f) => f,
                    Err(e) => {
                        warn!("failed check /etc/passwd");
                        continue;
                    }
                };
                let reader = BufReader::new(etc_passwd);
                for line in reader.lines() {
                    if let Ok(each_line) = line {
                        let lvec: Vec<&str> = each_line.split(":").into_iter().collect();
                        let uid: u32 = lvec[2].parse().unwrap_or_default();
                        let gid: u32 = lvec[3].parse().unwrap_or_default();
                        if lvec[6].ends_with("sh")
                            && (lvec[5].starts_with("/root") || lvec[5].starts_with("/home"))
                        {
                            // clean & reset anti-ransom targets
                            let dst = format!("{}/elkeid_targets", lvec[5]);
                            fs::remove_dir_all(&dst);
                            if let Err(e) =
                                copy_elkeid_targets(&dst, uid.to_owned(), gid.to_owned())
                            {
                                warn!("failed reset {}:{}:{}:targets", &uid, &gid, &dst);
                                continue;
                            }
                            for each_target in HONEYPOTS {
                                if let Err(e) = FileMonitor::raw_add(
                                    raw_monitorfd,
                                    &format!("{}/{}", &dst, each_target),
                                    true,
                                ) {
                                    warn!("fmonitor add fpath err {:?}:{:?}", &dst, e);
                                }
                            }
                        }
                    }
                }
            }
        });
        self._cronjob_refresh_monitor = Some(recv_worker);
    }
}

impl Drop for HoneyPot {
    fn drop(&mut self) {
        self.moniter.flush();
        for (k, (uid, gid, home_path)) in &self.user_homes {
            let dst = format!("{}/elkeid_targets", home_path);
            fs::remove_dir_all(dst);
        }
    }
}

fn copy_elkeid_targets(dst: &str, ruid: u32, rgid: u32) -> io::Result<()> {
    let target_path = Path::new(dst);
    let uid = Uid::from_raw(ruid);
    let gid = Gid::from_raw(rgid);

    if !target_path.exists() {
        fs::create_dir_all(&dst)?;
    }
    chown(dst, Some(uid), Some(gid))?;
    for entry in fs::read_dir("./elkeid_targets")? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if !ty.is_dir() {
            let dest_full = target_path.join(entry.file_name());
            fs::copy(entry.path(), &dest_full)?;
            chown(&dest_full, Some(uid), Some(gid))?;
        }
    }
    Ok(())
}

pub fn check_av_file(file_path: &str) -> bool {
    let mut f = match fs::File::open(file_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut buf = [0; 1024 * 1024 * 4];
    let read_len = match f.read(&mut buf) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let caps = match AN_CHECK_KEY.captures(&buf[..read_len]) {
        Some(_) => return true,
        None => return false,
    };

    return false;
}

fn parse_docker_mountinfo() -> Result<Vec<String>> {
    let mut results = Vec::new();
    let proc_net_unix_file = fs::File::open("/proc/self/mountinfo")?;
    let reader = BufReader::new(proc_net_unix_file);

    for line in reader.lines() {
        if let Ok(line) = line {
            let mut s: Vec<&str> = line.split_whitespace().collect();
            // s[0] mount_id
            // s[4] mount_point
            // s[8] filesystem

            // overlay2
            if s[4].ends_with("/merged") && s[4].contains("docker") {
                results.push(s[4].to_string());
                continue;
            }
            // kubepods
            if s[4].ends_with("/rootfs") && s[4].contains("containerd") {
                results.push(s[4].to_string());
                continue;
            }
        }
    }
    return Ok(results);
}
