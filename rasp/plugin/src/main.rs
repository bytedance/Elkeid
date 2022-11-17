use anyhow::Result as Anyhow;
use elkeid_rasp::config::*;
use elkeid_rasp::monitor;

/* init */
// create flock
use fs2::FileExt;
use plugins::logger::Config;
use plugins::logger::Logger;
use plugins::Client;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;
// cgroup
use cgroups_rs::{self, cgroup_builder::CgroupBuilder, CgroupPid, Controller};

// log
use log::*;

fn main() -> Anyhow<()> {
    // flock
    File::create(settings_string("service", "flock_path")?)?.try_lock_exclusive()?;
    info!("Elkeid RASP Started");
    // connect to agent
    let client = Client::new(false);
    // init
    init(client.clone())?;
    // start core loop
    monitor::rasp_monitor_start(client)?;
    info!("Elkeid RASP Stopped");
    return Ok(());
}

fn init(client: Client) -> Anyhow<()> {
    // cgroup
    fn setup_cgroup(pid: u32) -> Anyhow<()> {
        let hier = cgroups_rs::hierarchies::auto();
        let rasp_cg = CgroupBuilder::new(&settings_string("service", "cgroup_name")?)
            .memory()
                .memory_hard_limit(1024 * 1024 * settings_int("service", "cgroup_mem_limit")?)
                .done()
            .cpu()
                .quota(1000 * settings_int("service", "cgroup_cpu_limit")?).done()
            .build(hier);
        let mems: &cgroups_rs::memory::MemController = rasp_cg.controller_of().unwrap();
        mems.add_task(&CgroupPid::from(pid as u64))?;
        let cpus: &cgroups_rs::cpu::CpuController = rasp_cg.controller_of().unwrap();
        cpus.add_task(&CgroupPid::from(pid as u64))?;
        Ok(())
    }
    let self_pid = std::process::id();
    setup_cgroup(self_pid)?;
    //log
    let log_level = settings_string("service", "log_level")?;
    let log_path = settings_string("service", "log_path")?;
    let remote_log_level = settings_string("service", "remote_log_level")?;
    let max_backups = settings_int("service", "max_backups")?;
    let logger = Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from(format!("{}/rasp.log", log_path)),
        file_level: LevelFilter::from_str(&log_level)?,
        remote_level: LevelFilter::from_str(&remote_log_level)?,
        max_backups: max_backups as usize,
        compress: true,
        client: Some(client),
    });
    set_boxed_logger(Box::new(logger))?;
    Ok(())
}
