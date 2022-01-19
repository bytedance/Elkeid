use anyhow::Result as Anyhow;
use elkeid_rasp::config::*;
use elkeid_rasp::monitor;

/* init */
// create flock
use fs2::FileExt;
use plugins::logger::Config;
use plugins::logger::Logger;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;
// cgroup
use cgroups_rs::{self, cgroup_builder::CgroupBuilder, CgroupPid, Controller};

// log
use log::*;

fn main() -> Anyhow<()> {
    info!("Elkeid RASP Started");
    // setup file lock and cgroup limit
    init()?;
    monitor::rasp_monitor_start()?;
    return Ok(());
}

fn init() -> Anyhow<()> {
    // flock
    File::create(settings_string("service", "flock_path")?)?.try_lock_exclusive()?;
    // cgroup
    fn setup_cgroup(pid: u32) -> Anyhow<()> {
        let hier = cgroups_rs::hierarchies::auto();
        let new_cg = CgroupBuilder::new(&settings_string("service", "cgroup_name")?)
            .memory()
            .memory_hard_limit(1024 * 1024 * settings_int("service", "cgroup_mem_limit")?)
            .done()
            .build(hier);
        let mems: &cgroups_rs::memory::MemController = new_cg.controller_of().unwrap();
        mems.add_task(&CgroupPid::from(pid as u64))?;
        Ok(())
    }
    let self_pid = std::process::id();
    setup_cgroup(self_pid)?;
    //log
    let log_level = settings_string("service", "log_level")?;
    let logger = Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from("./rasp.log"),
        file_level: LevelFilter::from_str(&log_level)?,
        remote_level: LevelFilter::Error,
        max_backups: 10,
        compress: true,
        client: None,
    });
    set_boxed_logger(Box::new(logger))?;
    Ok(())
}
