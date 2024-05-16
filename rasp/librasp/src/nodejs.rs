use std::process::Stdio;
use std::{collections::HashMap, ffi::OsString, process::Command, thread::sleep, time::Duration};

use crate::process::ProcessInfo;
use crate::runtime::ProbeCopy;
use crate::settings;

use anyhow::{anyhow, Result};
use log::*;
use regex::Regex;
use wait_timeout::ChildExt;

pub struct NodeJSProbe {}

impl ProbeCopy for NodeJSProbe {
    fn names() -> (Vec<String>, Vec<String>) {
        ([].to_vec(), [settings::RASP_NODEJS_DIR()].to_vec())
    }
}

pub fn nodejs_attach(
    pid: i32,
    _environ: &HashMap<OsString, OsString>,
    node_path: &str,
) -> Result<bool> {
    debug!("node attach: {}", pid);
    let smith_module_path = settings::RASP_NODEJS_ENTRY();
    nodejs_run(pid, node_path, smith_module_path.as_str())
}

pub fn nodejs_run(pid: i32, node_path: &str, smith_module_path: &str) -> Result<bool> {
    let pid_string = pid.to_string();
    let nsenter = settings::RASP_NS_ENTER_BIN();
    let inject_script_path = settings::RASP_NODEJS_INJECTOR();
    let nspid = match ProcessInfo::read_nspid(pid) {
        Ok(nspid_option) => {
            if let Some(nspid) = nspid_option {
                nspid
            } else {
                pid
            }
        }
        Err(e) => {
            return Err(anyhow!(e));
        }
    };
    let nspid_string = nspid.clone().to_string();
    let prefix = "setTimeout((inspector) => {inspector.close(); }, 500, require('inspector')); if (!Object.keys(require.cache).some(m => m.includes('smith.js'))) { require('";
    let suffix = "');}";
    let require_module = format!("{}{}{}", prefix, smith_module_path, suffix);
    let args = [
        "-m",
        "-n",
        "-p",
        "-t",
        pid_string.as_str(),
        node_path,
        inject_script_path.as_str(),
        nspid_string.as_str(),
        require_module.as_str(),
    ];
    let mut child = Command::new(nsenter)
    .args(&args)
    .stderr(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()?;

    let timeout = Duration::from_secs(30);

    match child.wait_timeout(timeout).unwrap() {
        Some(status) => {
            let out = child.wait_with_output()?;

            if status.success() {
                sleep(Duration::from_secs(1));
                return Ok(true);
            }

            match status.code() {
                Some(n) => {
                    let stdout = match std::str::from_utf8(&out.stdout) {
                        Ok(s) => s,
                        Err(_) => "unknow stdout",
                    };
                    let stderr = match std::str::from_utf8(&out.stderr) {
                        Ok(s) => s,
                        Err(_) => "unknow stderr",
                    };
                    
                    let output = format!("{}\n{}", stdout, stderr);
                    // port
                    if n == 1 {
                        sleep(Duration::from_secs(1));
                        error!("can not attach nodejs, exit code: {}, output: {}", n, output);
                        return Err(anyhow!(output));
                    }
                    return Err(anyhow!("return code: {} {}", n, output));
                }
                None => return Err(anyhow!("no return code founded")),
            }
        },
        None => {
            // child hasn't exited yet within 30s, kill the child process
            child.kill()?;
            child.wait()?;
            return Err(anyhow!("command execution timeout"));
        }
    }
}

pub fn nodejs_version(pid: i32, nodejs_bin_path: &String) -> Result<(u32, u32, String)> {
    // exec nodejs
    let nsenter = settings::RASP_NS_ENTER_BIN();
    let pid_string = pid.to_string();
    let args = [
        "-m",
        "-n",
        "-p",
        "-t",
        pid_string.as_str(),
        nodejs_bin_path,
        "-v",
    ];
    let output = match Command::new(nsenter).args(&args).output() {
        Ok(s) => s,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    let output_string = String::from_utf8(output.stdout).unwrap_or(String::new());
    if output_string.is_empty() {
        return Err(anyhow!("empty stdout"));
    }
    // parse nodejs version
    let re = Regex::new(r"v((\d+)\.(\d+)\.\d+)").unwrap();
    let (major, minor, version) = match re.captures(&output_string) {
        Some(c) => {
            let major = c.get(2).map_or("", |m| m.as_str());
            let minor = c.get(3).map_or("", |m| m.as_str());
            let version = c.get(1).map_or("", |m| m.as_str());
            (major, minor, version)
        }
        None => return Err(anyhow!(String::from("can not find version"))),
    };
    let major_number = match major.parse::<u32>() {
        Ok(n) => n,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    let minor_number = match minor.parse::<u32>() {
        Ok(n) => n,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    Ok((major_number, minor_number, String::from(version)))
}
