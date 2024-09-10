use anyhow::{anyhow, Result};
use log::*;

use std::fs::{self, File};
use std::path::PathBuf;
use std::process::Command;

use goblin::elf::Elf;
use memmap::MmapOptions;
use regex::Regex;

use crate::async_command::run_async_process;
use crate::runtime::{ProbeCopy, ProbeState, ProbeStateInspect};
use crate::{process::ProcessInfo, settings};

pub struct CPythonProbeState {}

impl ProbeStateInspect for CPythonProbeState {
    fn inspect_process(process_info: &mut ProcessInfo) -> Result<ProbeState> {
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

pub struct CPythonRuntime {}

impl CPythonRuntime {
    pub fn python_inspect(process_info: &ProcessInfo) -> Option<String> {
        match Self::libpython_inspect(process_info) {
            Ok(s) => {
                if s.is_some() {
                    return s;
                }
            }
            Err(e) => {
                warn!("inspect libpython failed: {}", e)
            }
        }
        match Self::symbol_inspect(&process_info) {
            Ok(s) => {
                if s.is_some() {
                    return s;
                }
            }
            Err(e) => {
                warn!("inspect python symbol failed: {}", e)
            }
        }
        None
    }
    pub fn libpython_inspect(process_info: &ProcessInfo) -> Result<Option<String>> {
        let maps = procfs::process::Process::new(process_info.pid)?.maps()?;
        let regex_str = r"libpython(\d\.\d+)[m]?\.so";
        let regex = Regex::new(regex_str)?;
        for map in maps.iter() {
            if let procfs::process::MMapPath::Path(p) = map.pathname.clone() {
                let s = match p.into_os_string().into_string() {
                    Ok(s) => s,
                    Err(os) => {
                        warn!("convert osstr to string failed: {:?}", os);
                        continue;
                    }
                };
                match regex.captures(&s) {
                    Some(c) => {
                        if let Some(version) = c.get(1) {
                            return Ok(Some(String::from(version.as_str())));
                        }
                    }
                    None => continue,
                }
            }
        }
        Ok(None)
    }
    pub fn symbol_inspect(process_info: &ProcessInfo) -> Result<Option<String>> {
        let pid = process_info.pid.clone();
        let exe_path = process_info.exe_path.clone().unwrap();
        // /proc/<pid>/<exe_path> for process in container
        let mut path = PathBuf::from(format!("/proc/{}/root/", pid));
        let exe_path_buf = PathBuf::from(exe_path);
        if !exe_path_buf.has_root() {
            path.push(exe_path_buf);
        } else {
            for p in exe_path_buf.iter() {
                if p == std::ffi::OsString::from("/") {
                    continue;
                }
                path.push(p);
            }
        }
        let metadata = fs::metadata(path.clone())?;
        let size = metadata.len();
        if size >= (500 * 1024 * 1024) {
            return Err(anyhow!("bin file oversize: {}", process_info.pid));
        }
        let file = File::open(path)?;
        let bin = unsafe { MmapOptions::new().map(&file)? };
        let elf = Elf::parse(&bin)?;

        for dynsym in elf.dynsyms.iter() {
            let name = elf.dynstrtab[dynsym.st_name].to_string();
            if name == "PyRun_SimpleString" {
                return Ok(Some("Unknow".to_string()));
            }
        }
        for sym in elf.syms.iter() {
            let name = elf.strtab[sym.st_name].to_string();
            if name == "PyRun_SimpleString" {
                return Ok(Some("Unknow".to_string()));
            }
        }

        return Ok(None);
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
    let content = format!(
        r#"import os
import sys

name = 'rasp'
path = '{}/__init__.py'

if sys.version_info >= (3, 3):
    from importlib.machinery import SourceFileLoader
    SourceFileLoader(name, path).load_module()
elif sys.version_info >= (2, 7):
    import imp
    imp.load_module(name, None, os.path.dirname(path), ('', '', imp.PKG_DIRECTORY))

"#,
        settings::RASP_PYTHON_DIR()
    );
    let path = settings::RASP_PYTHON_ENTRY();
    let dest_dir = format!("/proc/{}/root{}", pid, path);
    fs_extra::file::write_all(dest_dir, content.as_str())?;
    Ok(())
}

pub fn pangolin_inject_file(pid: i32, file_path: &str) -> Result<bool> {
    debug!("pangolin inject: {}", pid);
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
        file_path,
    ];
    match run_async_process(Command::new(pangolin).args(args)) {
        Ok((es, stdout, stderr)) => {
            if stdout.len() != 0 {
                info!("return code: {}\n{}", es.to_string(), &stdout);
            }
            if stderr.len() != 0 {
                warn!("return code: {}\n{}", es.to_string(), &stderr);
            }
            let es_code = match es.code() {
                Some(ec) => ec,
                None => {
                    return Err(anyhow!("get status code failed: {}", pid));
                }
            };
            if es_code == 0 {
                Ok(true)
            } else if es_code == 255 {
                let msg = format!(
                    "python attach exit code 255: {} {} {}",
                    es_code, &stdout, &stderr
                );
                error!("pid: {}, {}", pid, msg);
                Err(anyhow!("{}", msg))
            } else {
                let msg = format!(
                    "python attach exit code {} {} {}",
                    es_code, &stdout, &stderr
                );
                error!("pid: {}, {}", pid, msg);
                Err(anyhow!("{}", msg))
            }
        }
        Err(e) => Err(anyhow!(e.to_string())),
    }
}
