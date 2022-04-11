use serde::{Deserialize, Serialize};

pub const CLAMAV_MAX_FILESIZE: usize = 1024 * 1024 * 20;
pub const CLAMAV_MAX_SCANSIZE: i64 = 1024 * 1024 * 40;

pub const WAIT_INTERVAL_SCAN: std::time::Duration = std::time::Duration::from_secs(1);

pub const DB_URLS: &'static [&'static str] = &[
    "http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default",
    "http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default",
    "http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default",
    "http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default",
];

pub const ARCHIVE_DB_PWD: &str = &"clamav_default_passwd";
pub const ARCHIVE_DB_HASH: &str =
    &"d3cfbdfa5747c28dec0c0060974c6b891dbab7c48fdd8d463382fff5d4f4da70";
pub const ARCHIVE_DB_VERSION: &str = &"20220222";

pub const ARCHIVE_DB_VERSION_FILE: &str = &"version";
pub const DB_PATH: &str = "./dat";
pub const TMP_PATH: &str = "./tmp";

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct ScanConfig<'a> {
    pub fpath: &'a str,
    pub max_depth: usize,
}

// SCAN_DIR : config directory for yara scan
#[cfg(not(feature = "debug"))]
pub const SCAN_DIR_CONFIG: &[&ScanConfig] = &[
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
        fpath: "/root",
        max_depth: 3,
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
];
