use anyhow::{anyhow, Result};

use log::*;
use regex::Regex;
use std::process::Command;

use crate::async_command::run_async_process;
use crate::process::ProcessInfo;
use crate::runtime::{ProbeCopy, ProbeState, ProbeStateInspect};
use crate::settings;

pub struct JVMProbeState {}

impl ProbeStateInspect for JVMProbeState {
    fn inspect_process(process_info: &ProcessInfo) -> Result<ProbeState> {
        if prop(process_info.pid)? {
            Ok(ProbeState::Attached)
        } else {
            Ok(ProbeState::NotAttach)
        }
    }
}

pub struct JVMProbe {}

impl ProbeCopy for JVMProbe {
    fn names() -> (Vec<String>, Vec<String>) {
        (
            [
                settings::RASP_JAVA_JATTACH_BIN(),
                settings::RASP_JAVA_PROBE_BIN(),
            ]
            .to_vec(),
            [].to_vec(),
        )
    }
}

pub fn java_attach(pid: i32) -> Result<bool> {
    let java_attach = settings::RASP_JAVA_JATTACH_BIN();
    let probe = settings::RASP_JAVA_PROBE_BIN();
    match run_async_process(Command::new(java_attach).args(&[
        pid.to_string().as_str(),
        "load",
        "instrument",
        "false",
        probe.as_str(),
    ])) {
        Ok((es, out, err)) => {
            if out.len() != 0 {
                info!("{}", &out);
            }
            if err.len() != 0 {
                info!("{}", &err);
            }
            let es_code = match es.code() {
                Some(ec) => ec,
                None => {
                    return Err(anyhow!("get status code failed: {}", pid));
                }
            };
            if es_code == 0 {
                return Ok(true);
            } else {
                let msg = format!(
                    "jvm attach exit code {} {} {} {}",
                    es_code, pid, &out, &err
                );
                error!("{}", msg);
                Err(anyhow!("{}", msg))
            }
        }
        Err(e) => {
            Err(anyhow!(e.to_string()))
        }
    }
}

pub fn jcmd(pid: i32, cmd: &'static str) -> Result<Vec<u8>> {
    let java_attach = settings::RASP_JAVA_JATTACH_BIN();

    match run_async_process(Command::new(java_attach).args(&[
        pid.to_string().as_str(),
        "jcmd",
       cmd,
    ])) {
        Ok((_, out, err)) => {
            // if out.len() != 0 {
            //     info!("{}", &out);
            // }
            if err.len() != 0 {
                info!("pid: {}, {}", pid, &err);
            }
            return Ok(out.into())
        }
        Err(e) => {
            Err(anyhow!(e.to_string()))
        }
    }
}

pub fn vm_version(pid: i32) -> Result<i32> {
    return match jcmd(pid, "VM.version") {
        Ok(stdout) => {
            let response = String::from_utf8(stdout).unwrap_or(String::new());
            let re = Regex::new(r"JDK (\d+)\.").unwrap();
            let version = match re.captures(&response) {
                Some(c) => c.get(1).map_or("", |m| m.as_str()),
                None => return Err(anyhow!(String::from("can not find version"))),
            };
            let version_number = match version.parse::<i32>() {
                Ok(vm) => vm,
                Err(e) => return Err(anyhow!(e.to_string())),
            };
            Ok(version_number)
        }
        Err(e) => Err(anyhow!(e)),
    };
}

pub fn prop(pid: i32) -> Result<bool> {
    return match jcmd(pid, " VM.system_properties") {
        Ok(stdout) => {
            let response = String::from_utf8_lossy(&stdout);
            let re = Regex::new(r"rasp\.probe").unwrap();
            Ok(re.is_match(&response))
        }
        Err(e) => Err(anyhow!(e)),
    };
}
