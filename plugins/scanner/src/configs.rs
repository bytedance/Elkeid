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
