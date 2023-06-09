use anyhow::{anyhow, Result};
use config::{Config, File};
use lazy_static;
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

lazy_static::lazy_static!(
    pub static ref SETTINGS: Config = load_config("settings").unwrap();

    pub static ref SERVICE_PID_LOCK_PATH: String = settings_string("service","flock_path").unwrap().to_string();
    pub static ref SERVICE_DEFAULT_CG_NAME: String = settings_string("service","cgroup_name").unwrap().to_string();
    pub static ref SERVICE_DEFAULT_CG_MEM: i64 = settings_int("service","cgroup_mem_limit").unwrap() as _;
    pub static ref SERVICE_DEFAULT_CG_CPU: i64 = settings_int("service","cgroup_cpu_limit").unwrap() as _;

    pub static ref SERVICE_DEFAULT_LOG_LEVEL: String = settings_string("service","log_level").unwrap().to_string();
    pub static ref SERVICE_DEFAULT_LOG_PATH: String = settings_string("service","log_path").unwrap().to_string();
    pub static ref SERVICE_DEFAULT_LOG_RLEVEL: String = settings_string("service","remote_log_level").unwrap().to_string();
    pub static ref SERVICE_DEFAULT_LOG_MAX_BAK: i64 = settings_int("service","max_backups").unwrap() as _;

    pub static ref SCAN_DIR_CONFIG: Vec<ScanConfigs> = gen_scan_dir().unwrap();
    pub static ref SCAN_DIR_FILTER: Vec<String> = settings_vec_string("scan","filter").unwrap();

    pub static ref FULLSCAN_CPU_IDLE_INTERVAL: u64 = settings_int("fullscan","fullscan_cpu_idle_interval").unwrap() as _;
    pub static ref FULLSCAN_CPU_IDLE_100PCT: u64 = settings_int("fullscan","fullscan_cpu_idle_100pct").unwrap() as _;
    pub static ref FULLSCAN_CPU_QUOTA_DEFAULT_MIN: u64 = settings_int("fullscan","fullscan_cpu_quota_default_min").unwrap() as _;
    pub static ref FULLSCAN_CPU_QUOTA_DEFAULT_MAX: u64 = settings_int("fullscan","fullscan_cpu_quota_default_max").unwrap() as _;
    pub static ref FULLSCAN_MAX_SCAN_ENGINES: u32 = settings_int("fullscan","fullscan_max_scan_engines").unwrap() as _;
    pub static ref FULLSCAN_MAX_SCAN_CPU_100: u32 = settings_int("fullscan","fullscan_max_scan_cpu_100").unwrap() as _;
    pub static ref FULLSCAN_MAX_SCAN_MEM_MB: u32 = settings_int("fullscan","fullscan_max_scan_mem_mb").unwrap() as _;
    pub static ref FULLSCAN_MAX_SCAN_TIMEOUT_FULL: u64 = settings_int("fullscan","fullscan_max_scan_timeout_full").unwrap() as _;
    pub static ref FULLSCAN_MAX_SCAN_TIMEOUT_QUICK: u64 = settings_int("fullscan","fullscan_max_scan_timeout_quick").unwrap() as _;

    pub static ref  CLAMAV_MAX_FILESIZE: usize = settings_int("engine","clamav_max_filesize").unwrap() as _;
    pub static ref  CLAMAV_MAX_SCANSIZE: i64 = settings_int("engine","clamav_max_scansize").unwrap() as _;
    pub static ref  CLAMAV_MAX_SCANTIME: i64 = settings_int("engine","clamav_max_scantime").unwrap() as _;
    pub static ref  DB_DEFAULT: String = settings_string("engine","default_db_path").unwrap().to_string();

    pub static ref DB_URLS: Vec<String> = settings_vec_string("database","db_urls").unwrap();
    pub static ref ARCHIVE_DB_PWD: String = settings_string("database","archive_db_pwd").unwrap().to_string();
    pub static ref ARCHIVE_DB_HASH: String = settings_string("database","archive_db_hash").unwrap().to_string();
    pub static ref ARCHIVE_DB_VERSION: String = settings_string("database","archive_db_version").unwrap().to_string();
    pub static ref FMONITOR_EXE_WHITELIST: HashMap<String,bool> = gen_fmonitor_exe_filter().unwrap();
    pub static ref FMONITOR_ARGV_WHITELIST: HashMap<String,bool> = gen_fmonitor_argv_filter().unwrap();

);

pub const FULLSCAN_SCAN_MODE_FULL: &str = "full";
pub const FULLSCAN_SCAN_MODE_QUICK: &str = "quick";

#[inline]
pub fn settings_int(table: &'static str, key: &'static str) -> Result<i64> {
    debug!("load settings: [{}] {}", table, key);
    let service = SETTINGS.get_table(table)?;
    let value = service.get(key);
    if value.is_none() {
        return Err(anyhow::anyhow!("missing key `{}` in `[{}]`", key, table));
    }
    let value: i64 = value.unwrap().clone().into_int()?;
    Ok(value)
}

#[inline]
pub fn settings_string(table: &'static str, key: &'static str) -> Result<String> {
    debug!("load settings: [{}] {}", table, key);
    let service = SETTINGS.get_table(table)?;
    let value = service.get(key);
    if value.is_none() {
        return Err(anyhow::anyhow!("missing key `{}` in `[{}]`", key, table));
    }
    let value: String = value.unwrap().to_string();
    Ok(value)
}

#[inline]
pub fn settings_vec_string(table: &'static str, key: &'static str) -> Result<Vec<String>> {
    debug!("load settings: [{}] {}", table, key);
    let service = SETTINGS.get_table(table)?;
    let values = service.get(key);
    if values.is_none() {
        return Err(anyhow::anyhow!("missing key `{}` in `[{}]`", key, table));
    }
    let mut v = Vec::new();
    for value in values.unwrap().clone().into_array()? {
        v.push(value.into_str()?);
    }
    Ok(v)
}

#[inline]
pub fn load_config(path: &'static str) -> Result<Config> {
    let mut settings = Config::default();
    settings.merge(File::with_name(path))?;
    Ok(settings)
}

#[derive(Clone, Debug, Copy)]
pub enum FAMode {
    RECUR(usize),
    SIGLE,
}

#[derive(Clone, Debug)]
pub struct FanotifyTargetConfigs {
    pub path: String,
    pub watch_mode: FAMode,
    pub follow_link: bool,
    pub sp_child: Option<String>,
}

impl FanotifyTargetConfigs {
    pub fn with_prefix(&self, prefix: &str) -> Self {
        return Self {
            path: format!("{}{}", prefix, self.path),
            watch_mode: self.watch_mode,
            follow_link: self.follow_link,
            sp_child: self.sp_child.clone(),
        };
    }
}

pub fn gen_fmonitor_cfg() -> Result<Vec<FanotifyTargetConfigs>> {
    let mut results = Vec::new();
    let file_monitor = SETTINGS.get_array("file_monitor")?;
    for each in file_monitor {
        let each_item = each.into_table()?;
        let raw_fpath = each_item.get("path");
        if raw_fpath.is_none() {
            return Err(anyhow!("settings.toml missing '[[file_monitor]]' -> path"));
        }
        let fpath = raw_fpath.unwrap().to_string();

        let raw_watch_mode = each_item.get("watch_mode");
        if raw_watch_mode.is_none() {
            return Err(anyhow!(
                "settings.toml missing '[[file_monitor]]' '{}' -> watch_mode",
                fpath
            ));
        }
        let watch_mode_int = raw_watch_mode.unwrap().clone().into_int()?;
        if watch_mode_int < 0 {
            return Err(anyhow!(
                "settings.toml watch_mode<0 '[[file_monitor]]' '{}' -> watch_mode",
                fpath
            ));
        }
        let watch_mode = match watch_mode_int {
            0 => FAMode::SIGLE,
            t => FAMode::RECUR(t as _),
        };

        let raw_follow_link = each_item.get("follow_link");
        if raw_follow_link.is_none() {
            return Err(anyhow!(
                "settings.toml missing '[[file_monitor]]' -> follow_link"
            ));
        }
        let follow_link = raw_follow_link.unwrap().clone().into_bool()?;

        let raw_sp_child = each_item.get("sp_child");
        if raw_sp_child.is_none() {
            return Err(anyhow!(
                "settings.toml missing '[[file_monitor]]' -> sp_child"
            ));
        }
        let sp_child_str = raw_sp_child.unwrap().to_string();
        let sp_child = match sp_child_str.as_str() {
            "" => None,
            _ => Some(sp_child_str),
        };
        results.push(FanotifyTargetConfigs {
            path: fpath,
            watch_mode: watch_mode,
            follow_link: follow_link,
            sp_child: sp_child,
        })
    }
    return Ok(results);
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct ScanConfigs {
    pub fpath: String,
    pub max_depth: usize,
}

pub fn gen_scan_dir() -> Result<Vec<ScanConfigs>> {
    let mut scan_dir_configs = Vec::new();
    let scan_config = SETTINGS.get_table("scan")?;
    let scan_dir = scan_config.get("dir");
    if scan_dir.is_none() {
        return Err(anyhow!("settings.toml missing '[[scan.dir]]'"));
    }
    let scan_dir_config = scan_dir.unwrap().clone().into_array()?;
    for each in scan_dir_config {
        let each_item = each.into_table()?;
        let raw_fpath = each_item.get("fpath");
        if raw_fpath.is_none() {
            return Err(anyhow!("settings.toml missing '[[scan.dir]]' -> fpath"));
        }
        let fpath = raw_fpath.unwrap().to_string();
        let raw_max_depth = each_item.get("max_depth");
        if raw_max_depth.is_none() {
            return Err(anyhow!(
                "settings.toml missing '[[scan.dir]]' '{}' -> max_depth",
                fpath
            ));
        }
        let max_depth = raw_max_depth.unwrap().clone().into_int()?;
        if max_depth < 0 {
            return Err(anyhow!(
                "settings.toml max_depth<0 '[[scan.dir]]' '{}' -> max_depth",
                fpath
            ));
        }
        let scan_cfg = ScanConfigs {
            fpath: fpath,
            max_depth: max_depth as _,
        };
        scan_dir_configs.push(scan_cfg);
    }
    return Ok(scan_dir_configs);
}

pub fn gen_fmonitor_exe_filter() -> Result<HashMap<String, bool>> {
    let mut filter = HashMap::new();
    let filter_list = settings_vec_string("file_monitor_filter", "file_monitor_exe_whitelist")?;
    for each in filter_list {
        filter.insert(each, true);
    }
    return Ok(filter);
}

pub fn gen_fmonitor_argv_filter() -> Result<HashMap<String, bool>> {
    let mut filter = HashMap::new();
    let filter_list = settings_vec_string("file_monitor_filter", "file_monitor_argv_whitelist")?;
    for each in filter_list {
        filter.insert(each, true);
    }
    return Ok(filter);
}
