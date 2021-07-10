use anyhow::{anyhow, Result};
use log::*;
use procfs::process::Process;

use std::{collections::HashMap, ffi::OsString, process::Command};

use crate::{process::ProcessInfo, settings};

use crate::runtime::{ProbeState, ProbeStateInspect};

pub struct CPythonProbeState {}

impl ProbeStateInspect for CPythonProbeState {
    fn inspect_process(process_info: &ProcessInfo) -> Result<ProbeState> {
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
    let entry = "/etc/elkeid/plugin/RASP/rasp/python/entry.py";
    // pangolin inject
    pangolin_inject_file(pid, entry)
}

pub fn pangolin_inject(pid: i32, pyscript: &str) -> Result<bool> {
    debug!("pangolin inject: {}", pid);
    // let nsenter = settings::RASP_NS_ENTER_BIN.to_string();
    let pyinject = "/etc/elkeid/plugin/RASP/rasp/python_inject";
    let pangolin = "--pangolin=/etc/elkeid/plugin/RASP/rasp/pangolin";
    let dash_s = "-s";
    let dash_p = "-p";
    let pid_string = pid.clone().to_string();
    /*
    let nspid = match ProcessInfo::read_ns_pid(pid) {
    Ok(nspid_option) => {
        if let Some(nspid) = nspid_option {
        nspid
        } else {
        pid
        }
    }
    Err(e) => {
        return Err(e);
    }
    };
    let nspid_string = nspid.clone().to_string();
    */
    let args = &[pangolin, dash_s, pyscript, dash_p, pid_string.as_str()];
    return match Command::new(pyinject).args(args).status() {
        Ok(st) => Ok(st.success()),
        Err(e) => Err(anyhow!(e.to_string())),
    };
}

pub fn pangolin_inject_file(pid: i32, file_path: &str) -> Result<bool> {
    debug!("pangolin inject: {}", pid);
    // let nsenter = settings::RASP_NS_ENTER_BIN.to_string();
    let pyinject = "/etc/elkeid/plugin/RASP/rasp/python_inject";
    let pangolin = "--pangolin=/etc/elkeid/plugin/RASP/rasp/pangolin";
    let dash_p = "-p";
    let file = "--file";
    let dash_s = "-s";
    let pid_string = pid.clone().to_string();
    let args = &[
        pangolin,
        file,
        dash_s,
        file_path,
        dash_p,
        pid_string.as_str(),
    ];
    return match Command::new(pyinject).args(args).status() {
        Ok(st) => Ok(st.success()),
        Err(e) => Err(anyhow!(e.to_string())),
    };
}
pub fn install_rasp_python_package(pid: i32, env: &HashMap<OsString, OsString>) -> Result<bool> {
    debug!("install rasp python package: {}", pid);
    // fetch pid's python path
    let python_process = match Process::new(pid) {
        Ok(pp) => pp,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    let venv_path_option = match env.get(&std::ffi::OsString::from("VIRTUAL_ENV")) {
        Some(osstr) => match osstr.clone().into_string() {
            Ok(s) => Some(s),
            Err(_) => None,
        },
        None => None,
    };
    let exe_path_str = if let Some(venv_path) = venv_path_option {
        let path = format!("{}/bin/python", venv_path);
        String::from(path)
    } else {
        let exe_path = match python_process.exe() {
            Ok(ep) => ep,
            Err(e) => return Err(anyhow!(e.to_string())),
        };
        let exe_path_str = match exe_path.to_str() {
            Some(p) => String::from(p),
            None => return Err(anyhow!(String::from("Path convert to str failed"))),
        };
        exe_path_str
    };
    debug!("using python interpreter: {}", exe_path_str.clone());
    return rasp_python_package_setup_install(pid, exe_path_str.as_str());
}

pub fn rasp_python_package_setup_install(pid: i32, python_path: &str) -> Result<bool> {
    let nsenter = settings::RASP_NS_ENTER_BIN.to_string();
    let pid_string = pid.clone().to_string();
    let args = &[
        "-m",
        "-n",
        "-p",
        "-t",
        pid_string.as_str(),
        python_path,
        "-m",
        "pip",
        "install",
        "--ignore-installed",
        "/etc/elkeid/plugin/RASP/rasp/rasp-1.0.0-py2.py3-none-any.whl",
    ];
    return match Command::new(nsenter)
        .current_dir("/etc/elkeid/plugin/RASP/rasp/")
        .args(args)
        .status()
    {
        Ok(st) => Ok(st.success()),
        Err(e) => Err(anyhow!(e.to_string())),
    };
}
