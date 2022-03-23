use anyhow::{anyhow, Result};
use log::*;

use std::process::Command;

use crate::{process::ProcessInfo, settings};

use crate::runtime::{ProbeState, ProbeStateInspect};

pub struct CPythonProbeState {}

impl ProbeStateInspect for CPythonProbeState {
    fn inspect_process(process_info: &ProcessInfo) -> Result<ProbeState> {
        // out of date
        let tasks: procfs::process::TasksIter = match process_info.process_self.tasks() {
            Ok(ts) => ts,
            Err(e) => {
                return Err(anyhow!(e));
            }
        };
        for task_result in tasks {
            if let Err(_e) = task_result {
                continue;
            }
            if let Ok(task) = task_result {
                let task_stat_result = task.stat();
                if let Ok(task_stat) = task_stat_result {
                    if task_stat.comm == "python-client" {
                        return Ok(ProbeState::Attached);
                    }
                }
            }
        }
        Ok(ProbeState::NotAttach)
    }
}
pub fn python_attach(pid: i32) -> Result<bool> {
    debug!("python attach: {}", pid);
    let entry = settings::RASP_PYTHON_ENTRY;
    // pangolin inject
    pangolin_inject_file(pid, entry)
}

pub fn pangolin_inject_file(pid: i32, file_path: &str) -> Result<bool> {
    debug!("pangolin inject: {}", pid);
    // let nsenter = settings::RASP_NS_ENTER_BIN.to_string();
    let python_loader = settings::RASP_PYTHON_LOADER;
    let pangolin = settings::RASP_PANGOLIN_BIN;
    let file = "--file";
    let extra = "--";
    let pid_string = pid.clone().to_string();
    let args = &[
        pid_string.as_str(),
        extra,
        python_loader,
        file,
        file_path
    ];
    return match Command::new(pangolin).args(args).status() {
        Ok(st) => Ok(st.success()),
        Err(e) => Err(anyhow!(e.to_string())),
    };
}
