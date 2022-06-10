use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Result as AnyhowResult};
use librasp::process::ProcessInfo;
use procfs::process::Process;

use crate::filter::Filters;

pub(crate) fn collect(pid: i32, filters: &Filters) -> AnyhowResult<ProcessInfo> {
    let mut pi = ProcessInfo::new(pid);

    let process = Process::new(pid)?;
    let (exe_name, exe_path) = pi.update_exe(&process)?;
    for ignore_path in filters.ignore_exe_path.iter() {
        if exe_path.starts_with(ignore_path) {
            return Err(anyhow!("hit global exe_path filter: {}, ignore prcess", ignore_path));
        }
    }
    for ignore_name in filters.ignore_exe_name.iter() {
        if &exe_name == ignore_name {
            return Err(anyhow!("hit global exe_path filter: {}, ignore prcess", ignore_name));
        }
    }
    if filters.collect_all_env {
        log::debug!("collect_all_env");
        pi.update_all_env(&process)?
    } else {
        pi.update_env(&process, &filters.collect_env)?;
    }
    pi.update_cmdline(&process)?;
    pi.update_ns_info(&process)?;
    pi.update_ppid(&process)?;
    pi.update_tgid(&process)?;
    pi.update_sid(&process)?;
    pi.update_start_time(&process)?;
    pi.update_id(&process)?;
    log::debug!("collect_all_env: {:?}", pi.environ);
    Ok(pi)

}

pub fn poll_pid_func(tracking_pid: &Vec<i32>) -> AnyhowResult<(Vec<i32>, Vec<i32>)> {
    let all_pids = traverse_proc()?;
    let mut need_inspect_pids: Vec<i32> = Vec::new();
    // new pid filter
    for p in all_pids.iter() {
        // pid didn't pass filter
        if !tracking_pid.contains(p) {
            need_inspect_pids.push(p.clone());
        }
    }
    Ok((all_pids, need_inspect_pids))
}

fn traverse_proc() -> AnyhowResult<Vec<i32>> {
    let mut pids = Vec::new();
    for entry in read_dir("/proc")? {
        let filename = entry.file_name();

        if let Ok(pid) = filename.to_string_lossy().parse::<i32>() {
            pids.push(pid);
        }
    }
    Ok(pids)
}

// copy from https://github.com/rust-psutil/rust-psutil/blob/b50a3fbc77fbf042c58b6f9ca9345e2c3c8d449b/src/errors.rs#L88
fn read_dir<P>(path: P) -> AnyhowResult<Vec<fs::DirEntry>>
    where
        P: AsRef<Path>,
{
    fs::read_dir(&path)
        .map_err(|err| anyhow!("Failed to read file '{:?}': {}", path.as_ref(), err))?
        .map(|entry| {
            entry.map_err(|err| anyhow!("Failed to read file '{:?}': {}", path.as_ref(), err))
        })
        .collect()
}


pub fn process_health(traced_processes: &HashMap<i32, ProcessInfo>) -> Vec<i32> {
    let mut result = Vec::new();
    for (pid, _) in traced_processes.iter() {
        if let Ok(p) = Process::new(*pid) {
            // zombie check
            if let Ok(_) = p.status() {
                continue;
            } else {
                result.push(pid.clone());
            }
        } else {
            result.push(pid.clone());
        }
    }
    result
}
