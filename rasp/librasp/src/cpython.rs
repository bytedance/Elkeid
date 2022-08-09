use anyhow::{anyhow, Result};
use log::*;

use std::process::Command;

use crate::{process::ProcessInfo, settings};

use crate::runtime::{ProbeState, ProbeStateInspect, ProbeCopy};

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


pub struct CPythonProbe {}

impl ProbeCopy for CPythonProbe {
    fn names() -> (Vec<String>, Vec<String>) {
        (
            [settings::RASP_PYTHON_LOADER()].to_vec(),
            [settings::RASP_PYTHON_DIR()].to_vec(),
        )
    }
}

pub fn python_attach(pid: i32) -> Result<bool> {
    debug!("python attach: {}", pid);
    write_python_entry(pid)?;
    let entry = settings::RASP_PYTHON_ENTRY();
    // pangolin inject
    pangolin_inject_file(pid, entry.as_str())
}

pub fn write_python_entry(pid: i32) -> Result<()> {
    let content = format!(r#"import os
import sys

name = 'rasp'
path = '{}/rasp/__init__.py'

if sys.version_info >= (3, 3):
    from importlib.machinery import SourceFileLoader
    SourceFileLoader(name, path).load_module()
elif sys.version_info >= (2, 7):
    import imp
    imp.load_module(name, None, os.path.dirname(path), ('', '', imp.PKG_DIRECTORY))

"#, settings::RASP_PYTHON_DIR());
    let path = settings::RASP_PYTHON_ENTRY();
    let dest_dir = format!("/proc/{}/root{}",pid, path);
    fs_extra::file::write_all(dest_dir, content.as_str())?;
    Ok(())

}

pub fn pangolin_inject_file(pid: i32, file_path: &str) -> Result<bool> {
    debug!("pangolin inject: {}", pid);
    // let nsenter = settings::RASP_NS_ENTER_BIN.to_string();
    let python_loader = settings::RASP_PYTHON_LOADER();
    let pangolin = settings::RASP_PANGOLIN();
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
