use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use log::*;
use nix::unistd::{chown, Gid, Uid};
use std::{
    collections::HashMap,
    fs,
    io::{self, BufRead, BufReader},
    path::Path,
};

use phf::{phf_map, Map};

use crate::data_type::DETECT_TASK;
use procfs::sys::kernel::Version;

use super::fmonitor::FileMonitor;

lazy_static! {
    pub static ref H26_KERNEL_VERSION: Version = Version::new(2, 6, 37);
}

pub static HONEYPOTSSHA256: Map<&'static str, &'static str> = phf_map! {
    "0_elkeid_hids_anti_ransom.csv" => "668f23ce53e38f964564ecdc3e5f1a646169ed779d774fda1009d23f9e52bce0",
    "0_elkeid_hids_anti_ransom.doc" => "4974f533cbc6bb6df5d5a99c3ef94240d9e3076a227fde44fc00a240d70bc71b",
    "0_elkeid_hids_anti_ransom.pdf" => "20b3b1d7d0440fbe57f9f5e6998d660890892c9c7703de787c9de66fc2368636",
    "0_elkeid_hids_anti_ransom.png" => "86dbc28537142e8fba1bb58b801889cb6a61d50ba60f1e6ca9ba879cb297cfa7",
    "0_elkeid_hids_anti_ransom.txt" => "55ccb1e3b83ca0bfbccd9c2cc1cd1b8ac3d04c21853a6209f23e2592e63f9f65",
    "0_elkeid_hids_anti_ransom.xls" => "5d9d6e5ed89989c44e50a1bd8d3722869d4ffb8b7e9b0dbb1a30a242dfb727b4",
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
    moniter: FileMonitor,
}

impl HoneyPot {
    pub fn new(
        sender: crossbeam_channel::Sender<DETECT_TASK>,
        s_locker: crossbeam_channel::Sender<()>,
    ) -> Result<Self> {
        let current_kernel_version = Version::current().unwrap();

        if current_kernel_version < *H26_KERNEL_VERSION {
            return Err(anyhow!(
                "kernel version unsupported {:?}",
                current_kernel_version
            ));
        }

        let mut target_md5maps = HashMap::new();
        let mut user_homes = HashMap::<String, (u32, u32, String)>::new();

        let etc_passwd = std::fs::File::open("/etc/passwd")?;
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
                }
            }
        }

        // file_monitor scan
        let mut fmonitor_t = FileMonitor::new(sender, s_locker)?;

        for (k, (uid, gid, home_path)) in &user_homes {
            let dst = format!("{}/elkeid_targets", home_path);
            copy_elkeid_targets(&dst, uid.to_owned(), gid.to_owned())?;
            for each_target in HONEYPOTS {
                if let Err(e) = fmonitor_t.add(&format!("{}/{}", &dst, each_target)) {
                    error!("fmonitor add fpath err {}/{}:{:?}", &dst, each_target, e);
                }
            }
        }

        return Ok(Self {
            target_md5maps: target_md5maps,
            user_homes: user_homes,
            moniter: fmonitor_t,
        });
    }

    pub fn reset(&mut self) -> Result<()> {
        self.moniter.flush();
        for (k, (uid, gid, home_path)) in &self.user_homes {
            let dst = format!("{}/elkeid_targets", home_path);
            copy_elkeid_targets(&dst, uid.to_owned(), gid.to_owned())?;
            for each_target in HONEYPOTS {
                if let Err(e) = self.moniter.add(&format!("{}/{}", &dst, each_target)) {
                    error!("fmonitor add fpath err {:?}:{:?}", &dst, e);
                }
            }
        }
        return Ok(());
    }
}

impl Drop for HoneyPot {
    fn drop(&mut self) {
        self.moniter.flush();
        for (k, (uid, gid, home_path)) in &self.user_homes {
            let dst = format!("{}/elkeid_targets", home_path);
            std::fs::remove_dir_all(dst);
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
