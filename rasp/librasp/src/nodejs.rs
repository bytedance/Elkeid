use std::process::Stdio;
use std::{collections::HashMap, ffi::OsString, process::Command, thread::sleep, time::Duration};

use crate::process::ProcessInfo;
use crate::runtime::ProbeCopy;
use crate::settings;

use anyhow::{anyhow, Result};
use log::*;
use regex::Regex;
use wait_timeout::ChildExt;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

const NODEJS_INSPECT_PORT_MIN:u16 = 19230;
const NODEJS_INSPECT_PORT_MAX:u16 = 19235;
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
    port: Option<u16>,
) -> Result<bool> {
    debug!("node attach: {}", pid);
    let smith_module_path = settings::RASP_NODEJS_ENTRY();
    nodejs_run(pid, node_path, smith_module_path.as_str(), port)
}

fn parse_port_from_address(address: &str) -> Option<u16> {
    if let Some(pos) = address.find(':') {
        let port_hex = &address[pos + 1..];
        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
            return Some(port);
        }
    }
    None
}

pub fn get_process_listening_port(pid: i32) -> u16 {

    // frist get ipv4 listen port
    let file_path = format!("/proc/{}/net/tcp", pid);
    let file = match File::open(&file_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let reader = BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = match line {
            Ok(l) => l,
            Err(_) => return 0,
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let local_address = parts[1];

            let status = parts[3];
            if status == "0A" {
                if let Some(port) = parse_port_from_address(local_address) {
                    if (NODEJS_INSPECT_PORT_MIN..= NODEJS_INSPECT_PORT_MAX).contains(&port) {
                        info!("Found  IPv4 listen port {} for pid {}", port, pid);
                        return port;
                    }
                }
            }
        }
    }

    // get ipv6 listen port
    let tcp6_path = format!("/proc/{}/net/tcp6", pid);
    let file = match File::open(&tcp6_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1)  {
        let line = match line {
            Ok(l) => l,
            Err(_) => return 0,
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let local_address = parts[1];
            let status = parts[3];

            if status == "0A" {
                if let Some(port) = parse_port_from_address(local_address) {
                    if (NODEJS_INSPECT_PORT_MIN..= NODEJS_INSPECT_PORT_MAX).contains(&port) {
                        info!("Found IPv6 listen port {} for pid {}", port, pid);
                        return port;
                    }
                }
            }
        }
    }
    info!("cannot found {} sutible  inspect port", pid);
    0
}


pub fn get_inspect_port(process_info: &ProcessInfo) -> u16 {
    let process = match procfs::process::Process::new(process_info.pid) {
        Ok(p) => p,
        Err(_) => {return 0;}
    };
    
    let re = regex::Regex::new(r"inspect(?:-brk|-port)?=(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}:)?(\d+)")
        .expect("Invalid regex pattern");
    

    let cmdline = process_info.cmdline.clone().unwrap_or(String::new());

    if let Some(captures) = re.captures(&cmdline) {
        if let Some(port) = captures.get(1) {
            info!("inspect port: {}", port.as_str());
            return port.as_str().parse().unwrap_or(0);
        }
    }
    let env = match process.environ() {
        Ok(env) => env,
        Err(_) =>  {return 0;}
    };

    match env.get(&std::ffi::OsString::from("NODE_OPTIONS")) {
        Some(v) => match v.clone().into_string() {
            Ok(s) => {
                if let Some(captures) = re.captures(s.as_str()) {
                    if let Some(port) = captures.get(1) {
                        info!("inspect port: {}", port.as_str());
                        return port.as_str().parse().unwrap_or(0);
                    }
                }
            }
            Err(_) => {}
        },
        None => {}
    };

    0
}

pub fn nodejs_run(pid: i32, node_path: &str, smith_module_path: &str, port: Option<u16>) -> Result<bool> {
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
    let port_str;
    let args;
    if let Some(port) = port.as_ref() {
        port_str = port.to_string();
        debug!("port is : {}", port_str);
        args = vec![
            "-m",
            "-n",
            "-p",
            "-t",
            pid_string.as_str(),
            node_path,
            inject_script_path.as_str(),
            nspid_string.as_str(),
            require_module.as_str(),
            port_str.as_str(),
        ];
    } else {
        args = vec![
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
    }
    debug!("args is : {:?}", args.clone());
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

pub fn check_nodejs_version(ver: &String) -> Result<()> {
    let major_minor: Option<(u32, u32)> = match ver.split('.').next() {
        Some(major_str) => {
            if let Ok(major) = major_str.parse::<u32>() {
                if let Some(minor_str) = ver.split('.').nth(1) {
                    if let Ok(minor) = minor_str.parse::<u32>() {
                        Some((major, minor))
                    } else {
                        None
                    }
                } else {
                    Some((major, 0))
                }
            } else {
                None
            }
        }
        None => None,
    };

    if let Some((major, minor)) = major_minor {
        if major > 8 || (major == 8 && minor >= 6) {
            return Ok(());
        } else {
            let msg = format!("nodejs version lower than 8.6: {}", ver);
            return Err(anyhow!(msg));
        }
    } else {
        let msg = format!("nodejs version cannot parse: {}", ver);
        return Err(anyhow!(msg));
    }
}