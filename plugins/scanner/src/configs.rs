use std::path::Path;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub const WAIT_INTERVAL_SCAN: std::time::Duration = std::time::Duration::from_secs(1);

pub const FULLSCAN_CPU_IDLE_INTERVAL: u64 = 5;
pub const FULLSCAN_CPU_IDLE_100PCT: u64 = 30;
pub const FULLSCAN_CPU_QUOTA_DEFAULT_MIN: u64 = 10_000;
pub const FULLSCAN_CPU_QUOTA_DEFAULT_MAX: u64 = 800_000;
pub const FULLSCAN_CPU_MAX_TIME_SECS: u64 = 48 * 3600;

pub const FULLSCAN_MAX_SCAN_ENGINES: u32 = 6;
pub const FULLSCAN_MAX_SCAN_CPU_100: u32 = 600;
pub const FULLSCAN_MAX_SCAN_MEM_MB: u32 = 512;
pub const FULLSCAN_MAX_SCAN_TIMEOUT_FULL: u64 = 48 * 3600;
pub const FULLSCAN_MAX_SCAN_TIMEOUT_QUICK: u64 = 3600;

pub const FULLSCAN_SCAN_MODE_FULL: &str = "full";
pub const FULLSCAN_SCAN_MODE_QUICK: &str = "quick";

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct ScanConfig<'a> {
    pub fpath: &'a str,
    pub max_depth: usize,
}

// SCAN_DIR : config directory for scan
pub const SCAN_DIR_CONFIG: &[&ScanConfig] = &[
    &ScanConfig {
        fpath: "/root",
        max_depth: 3,
    },
    &ScanConfig {
        fpath: "/bin",
        max_depth: 2,
    },
    &ScanConfig {
        fpath: "/sbin",
        max_depth: 2,
    },
    &ScanConfig {
        fpath: "/usr/bin",
        max_depth: 2,
    },
    &ScanConfig {
        fpath: "/usr/sbin",
        max_depth: 2,
    },
    &ScanConfig {
        fpath: "/usr/local",
        max_depth: 3,
    },
    &ScanConfig {
        fpath: "/lib/systemd/system",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/etc",
        max_depth: 2,
    },
    &ScanConfig {
        fpath: "/var/www/",
        max_depth: 20,
    },
];

pub const SCAN_DIR_FILTER: &[&str] = &[
    // root filter
    "/root/.debug", // vscode debug at root
    "/root/.vscode",
    "/root/.bash_history",
    // file filter
    "/usr/bin/killall",
    "/usr/bin/virt",
    "/usr/bin/upx",
    "/usr/bin/fim",
    "/usr/bin/nc",
    "/usr/bin/inputattach",
    // clamav
    "/usr/bin/clamdscan",
    "/usr/bin/clamconf",
    "/usr/bin/sigtool",
    "/usr/bin/clamdtop",
    "/usr/bin/clamsubmit",
    "/usr/bin/clambc",
    "/usr/bin/clamscan",
    "/usr/sbin/clamd",
    "/usr/sbin/clamonacc",
    // bin
    "/bin/nc",
    "/bin/netcat",
    "/bin/upx",
    "/bin/inputattach",
    // etc alternatives
    "/etc/alternatives/upx",
    "/etc/alternatives/nc",
    "/etc/alternatives/netcat",
    "/etc/dictionaries-common/words",
    // full disk scan filter
    "/dev",
    "/boot",
    "/sys",
    "/usr/src",
    "/usr/local/src",
];

#[derive(Clone, Debug, Copy)]
pub enum FAMode {
    RECUR(usize),
    SIGLE,
}

#[derive(Clone, Debug, Copy)]
pub enum FAType {
    MONITOR,
    ANTI_VIRUS,
}

#[derive(Clone, Debug)]
pub struct FanotifyTargetConfig<'a> {
    pub path: &'a str,
    pub watch_mode: FAMode,
    pub follow_link: bool,
    pub sp_child: Option<&'a str>,
    pub watch_type: FAType,
}

impl<'a> FanotifyTargetConfig<'a> {
    pub fn new(
        fpath: &'a str,
        fmode: FAMode,
        ftype: FAType,
        follow_link: bool,
        sp_child: Option<&'a str>,
    ) -> Result<Self> {
        let target_p = Path::new(&fpath);
        if !target_p.exists() {
            return Err(anyhow!("PathNotExists:{}", fpath));
        }
        return Ok(Self {
            path: fpath,
            watch_mode: fmode,
            watch_type: ftype,
            follow_link: follow_link,
            sp_child: sp_child,
        });
    }
}

pub const FANOTIFY_CONFIGS: &[&FanotifyTargetConfig] = &[
    &FanotifyTargetConfig {
        path: "/",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/bin",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/lib64",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/apt",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/cron.d",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/cron.daily",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/cron.hourly",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/cron.monthly",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/cron.weekly",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/dpkg",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/init.d",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/ld.so.conf.d",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/ldap",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/pam.d",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/security",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/profile.d",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/ssh",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/etc/ssl",
        watch_mode: FAMode::SIGLE,
        follow_link: false,
        sp_child: None,
        watch_type: FAType::MONITOR,
    },
    &FanotifyTargetConfig {
        path: "/home/",
        watch_mode: FAMode::RECUR(2),
        watch_type: FAType::MONITOR,
        follow_link: true,
        sp_child: Some(".ssh"),
    },
    &FanotifyTargetConfig {
        path: "/lib/x86_64-linux-gnu",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/opt",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: true,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/root",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/root/.ssh",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/sbin",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/usr/bin",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/usr/lib/cron/tabs",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/usr/local/bin",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/usr/local/sbin",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/usr/sbin",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/var/spool/cron",
        watch_mode: FAMode::RECUR(2),
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/boot/grub",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/sys/fs/cgroup",
        watch_mode: FAMode::RECUR(1),
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
    &FanotifyTargetConfig {
        path: "/dev/shm",
        watch_mode: FAMode::SIGLE,
        watch_type: FAType::MONITOR,
        follow_link: false,
        sp_child: None,
    },
];
