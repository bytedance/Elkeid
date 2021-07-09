use anyhow::{Result, anyhow};
use super::settings;

use regex::Regex;
use std::process::Command;

pub fn java_attach(pid: i32) -> Result<bool> {
    let java_attach = settings::RASP_JAVA_JATTACH_BIN;
    // let instrument = settings::RASP_JAVA_INSTRUMENT_BIN;
    let probe = settings::RASP_JAVA_PROBE_BIN;
    let status = match Command::new(java_attach)
        .args(&[
            pid.to_string().as_str(),
            "load",
            "instrument",
            "false",
            probe,
        ])
        .status()
    {
        Ok(s) => s,
        Err(e) => {
            return Err(anyhow!(e.to_string()));
        }
    };
    Ok(status.success())
}

pub fn jcmd(pid: i32, cmd: &'static str) -> Result<Vec<u8>> {
    let java_attach = settings::RASP_JAVA_JATTACH_BIN;
    let output = match Command::new(java_attach)
        .args(&[pid.to_string().as_str(), "jcmd", cmd])
        .output()
    {
        Ok(s) => s,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    Ok(output.stdout)
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
