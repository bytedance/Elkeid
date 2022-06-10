use anyhow::{anyhow, Result};
use log::*;

use std::process::Command;

use crate::{process::ProcessInfo, settings};

use crate::runtime::{ProbeState, ProbeStateInspect};

pub struct CPythonProbeState {}

impl ProbeStateInspect for CPythonProbeState {
    fn inspect_process(process_info: &ProcessInfo) -> Result<ProbeState> {
        search_proc_map(process_info)
    }
}

fn search_proc_map(process_info: &ProcessInfo) -> Result<ProbeState> {
    let maps = procfs::process::Process::new(process_info.pid)?.maps()?;
    for map in maps.iter() {
        if let procfs::process::MMapPath::Path(p) = map.pathname.clone() {
            let s = match p.into_os_string().into_string() {
                Ok(s) => s,
                Err(os) => {
                    warn!("convert osstr to string failed: {:?}", os);
                    continue;
                }
            };
            if s.contains("python_loader") {
                return Ok(ProbeState::Attached);
            }
        }
    }
    Ok(ProbeState::NotAttach)
}

pub fn python_attach(pid: i32) -> Result<bool> {
    debug!("python attach: {}", pid);
    let cwd_path = std::env::current_dir()?;
    let cwd = cwd_path.to_str().unwrap();
    let entry = format!("{}/{}", cwd, settings::RASP_PYTHON_ENTRY);
    // pangolin inject
    pangolin_inject_file(pid, entry.as_str())
}

pub fn pangolin_inject_file(pid: i32, file_path: &str) -> Result<bool> {
    debug!("pangolin inject: {}", pid);
    // let nsenter = settings::RASP_NS_ENTER_BIN.to_string();
    let cwd_path = std::env::current_dir()?;
    let cwd = cwd_path.to_str().unwrap();
    let python_loader = format!("{}/{}", cwd, settings::RASP_PYTHON_LOADER);
    let pangolin = format!("{}/{}", cwd, settings::RASP_PANGOLIN_BIN);
    let file = "--file";
    let extra = "--";
    let pid_string = pid.clone().to_string();
    let args = &[
        pid_string.as_str(),
        extra,
        python_loader.as_str(),
        file,
        file_path
    ];
    return match Command::new(pangolin).args(args).status() {
        Ok(st) => Ok(st.success()),
        Err(e) => Err(anyhow!(e.to_string())),
    };
}
