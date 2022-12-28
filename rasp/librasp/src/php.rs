use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;
use crate::process::ProcessInfo;
use procfs::process::Process;
use anyhow::{anyhow, Result as AnyhowResult};
use libc::{kill, pid_t, SIGUSR2};
use regex::Regex;
use crate::settings::RASP_PHP_PROBE;
use log::*;
use crate::async_command::run_async_process;
use crate::runtime::{ProbeState, ProbeStateInspect};

pub fn inspect_phpfpm(process: &ProcessInfo) -> AnyhowResult<bool> {
    if String::from(process.exe_name.as_ref().unwrap()).starts_with("php-fpm") {
        let ppi = ProcessInfo::from_pid(process.ppid)?;
        if String::from(ppi.exe_name.as_ref().unwrap()).starts_with("php-fpm") {
            return Ok(false);
        } else {
            return Ok(true);
        }
    }
    return Ok(false);
}

pub fn inspect_phpfpm_version(process: &ProcessInfo) -> AnyhowResult<String> {
    let regex = Regex::new(r"PHP ((\d\.\d+)\.\d+)(-| )")?;
    let output = execute_phpfpm_version(
        process.pid,
        String::from(process.exe_path.as_ref().unwrap()),
    )?;
    if let Some(caps) = regex.captures(output.as_str()) {
        if caps.len() == 4 {
            return Ok(String::from(caps.get(2).unwrap().as_str()));
        }
    }
    Err(anyhow!("can not found php version"))
}

pub fn inspect_phpfpm_zts(process: &ProcessInfo) -> AnyhowResult<bool> {
    let phprc_env = if let Some(rc) = Process::new(process.pid)?
        .environ()?
        .get(OsStr::new("PHPRC"))
    {
        let mut envs = HashMap::new();
        envs.insert(String::from("PHPRC"), rc.to_string_lossy().to_string());
        envs
    } else {
        HashMap::new()
    };
    let output = execute_phpfpm_info(
        process.pid, String::from(process.exe_path.as_ref().unwrap()),
        &phprc_env,
    )?;
    let regex = Regex::new(r"Configure Command.+zts")?;
    Ok(regex.is_match(output.as_str()))
}

fn execute_phpfpm_version(pid: i32, phpfmp: String) -> AnyhowResult<String> {
    let (exit_status, output, stderr) = run_async_process(
        Command::new(crate::settings::RASP_NS_ENTER_BIN())
            .args([
                "-m", "-p",
                "-t", pid.to_string().as_str(),
                phpfmp.as_str(),
                "-v"
            ])
    )?;
    if !exit_status.success() {
        warn!("check phpfpm failed: {} {} {} {}", pid, exit_status, output, stderr);
        return Err(anyhow!("can not fetch phpfpm version: {} {} {}", pid, exit_status, stderr));
    }
    Ok(output)
}

fn execute_phpfpm_info(pid: i32, phpfmp: String, origin_env: &HashMap<String,String>) -> AnyhowResult<String> {
    let (exit_status, output, stderr) = run_async_process(
        Command::new(crate::settings::RASP_NS_ENTER_BIN())
            .args([
                "-m", "-p",
                "-t", pid.to_string().as_str(),
                phpfmp.as_str(),
                "-i"
            ]).env_clear()
            .envs(origin_env)
    )?;
    if !exit_status.success() {
        warn!("check phpfpm failed: {} {} {} {}", pid, exit_status, output, stderr);
        return Err(anyhow!("can not fetch phpfpm info: {} {} {}", pid, exit_status, stderr));
    }
    Ok(output)
}


pub struct PHPProbeState {}

impl ProbeStateInspect for PHPProbeState {
    fn inspect_process(process_info: &ProcessInfo) -> AnyhowResult<ProbeState> {
        check_probe(process_info)
    }
}

fn check_probe(process_info: &ProcessInfo) -> AnyhowResult<ProbeState> {
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
            if s.contains("probe") {
                return Ok(ProbeState::Attached);
            }
        }
    }
    Ok(ProbeState::NotAttach)
}

pub fn inspect_php_ini_scan_dir(process: &ProcessInfo) -> AnyhowResult<String> {
    let phprc_env = if let Some(rc) = Process::new(process.pid)?
        .environ()?
        .get(OsStr::new("PHPRC"))
    {
        let mut envs = HashMap::new();
        envs.insert(String::from("PHPRC"), rc.to_string_lossy().to_string());
        envs
    } else {
        HashMap::new()
    };
    // grep "Scan this dir for additional .ini files"
    let output = execute_phpfpm_info(
        process.pid, String::from(process.exe_path.as_ref().unwrap()),
        &phprc_env,
    )?;
    let regex = Regex::new(r"Scan this dir for additional \.ini files => (.+)\n")?;
    if let Some(caps) = regex.captures(&output) {
        if caps.len() == 2 {
            let scanned_dir = caps.get(1).unwrap().as_str();
            if Path::new(scanned_dir).exists() {
                return Ok(String::from(scanned_dir));
            }
        }
    }
    Err(anyhow!("PHP additional scanned dir not found in phpinfo()"))
}


pub fn php_attach(process_info: &ProcessInfo, version: String) -> AnyhowResult<bool> {
    let splited: Vec<&str> = version.split(".").collect();
    let (probe_path, probe_name) = if splited.len() == 2 {
        let major = splited.get(0);
        let miner = splited.get(1);
        RASP_PHP_PROBE(major.unwrap(), miner.unwrap(), false).unwrap()
    } else if splited.len() == 3 {
        let major = splited.get(0);
        let miner = splited.get(1);
        RASP_PHP_PROBE(major.unwrap(), miner.unwrap(), true).unwrap()
    } else {
        return Err(anyhow!("PHP version: {} not support", &version));
    };
    let path = inspect_php_ini_scan_dir(&process_info)?;
    match write_conf_to_cond_dir(
        format!("/proc/{}/root", process_info.pid),
        path,
        probe_path,
        probe_name,
    ) {
        Ok(_) => {
            reload_phpfpm(process_info.pid)?;
            return Ok(true);
        }
        Err(e) => {
            warn!("can not write conf: {}", e);
        }
    }
    Ok(false)
}

// fn search_maps(process: &Process) -> AnyhowResult<Option<String>> {
//     let regex = Regex::new(r"\b/php.+\.so")?;
//     let maps = process.maps()?;
//     for map in maps.iter() {
//         if let procfs::process::MMapPath::Path(p) = map.pathname.clone() {
//             let s = match p.into_os_string().into_string() {
//                 Ok(s) => s,
//                 Err(os) => {
//                     warn!("convert osstr to string failed: {:?}", os);
//                     continue;
//                 }
//             };
//             if regex.is_match(&s) {
//                 return Ok(Some(s));
//             }
//         }
//     }
//     return Ok(None);
// }

pub fn copy_so_to_extension_dir(root_dir: String, extension_dir: String, probe_path: String, probe_name: String) -> AnyhowResult<()> {
    let target_path = format!("{}/{}/{}", root_dir, extension_dir, probe_name);
    if std::path::Path::new(&target_path).exists() {
        return Ok(());
    }
    debug!("{} -> {}", probe_path, target_path);
    // create path
    let copy_options = fs_extra::file::CopyOptions::default();
    fs_extra::file::copy(
        probe_path,
        target_path,
        &copy_options,
    )?;
    Ok(())
}

pub fn write_conf_to_cond_dir(root_dir: String, confd_dir: String, probe_path: String, _probe_name: String) -> AnyhowResult<()> {
    let so_target_path = format!("{}/{}", root_dir, probe_path);
    debug!("{} -> {}", probe_path, so_target_path);
    copy_file_from_to_dest(probe_path.clone(), root_dir.clone())?;
    let conf_path = format!("{}/{}/{}", root_dir, confd_dir, "999-php_probe.ini");
    debug!("{} -> {}", probe_path.clone(), conf_path);
    fs_extra::file::write_all(conf_path, format!("extension={}", probe_path).as_str())?;
    Ok(())
}

pub fn copy_file_from_to_dest(from: String, dest_root: String) -> AnyhowResult<()> {
    let target = format!("{}/{}", dest_root, from);
    if Path::new(&target).exists() {
        return Ok(());
    }
    let dir = Path::new(&from).parent().unwrap();
    create_dir_if_not_exist(dir.to_str().unwrap().to_string(), dest_root.clone())?;
    let options = fs_extra::file::CopyOptions::new();
    debug!("copy file: {} {}", from.clone(), format!("{}/{}", dest_root, from));
    return match fs_extra::file::copy(from.clone(), format!("{}/{}", dest_root, from), &options) {
        Ok(_) => Ok(()),
        Err(e) => {
            warn!("can not copy: {}", e);
            Err(anyhow!(
		    "copy failed: from {} to {}: {}",
		    from,
		    format!("{}/{}", dest_root, from),
		    e
		))
        }
    };
}

pub fn create_dir_if_not_exist(dir: String, dest_root: String) -> AnyhowResult<()> {
    let target = format!("{}{}", dest_root, dir);
    if Path::new(&target).exists() {
        return Ok(());
    }
    fs_extra::dir::create_all(format!("{}{}", dest_root, dir), true)?;
    Ok(())
}


fn reload_phpfpm(pid: i32) -> AnyhowResult<()> {
    let pidt = pid_t::from(pid);
    unsafe {
        match kill(pidt, SIGUSR2) {
            -1 => {
                // let err = str::raw::from_c_str(strerror( as libc::c_int));
                return Err(anyhow!("restart phpfpm failed: {} {}", pid, -1));
            }
            _ => {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod php_test {
    use crate::php::{check_probe, inspect_phpfpm, inspect_phpfpm_version, inspect_php_ini_scan_dir};
    use crate::process::ProcessInfo;
    use crate::runtime::ProbeState;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[test]
    fn test_inspect_phpfpm() {
        use env_logger;
        env_logger::init();
        for process in procfs::process::all_processes().unwrap().iter() {
            let process_info = match ProcessInfo::from_pid(process.pid) {
                Ok(pi) => pi,
                Err(e) => {
                    println!("{} can not fetch info {}", process.pid, e);
                    continue;
                }
            };
            println!("{} fetched", process_info.pid);
            let inspect_result = match inspect_phpfpm(&process_info) {
                Ok(ir) => ir,
                Err(e) => {
                    println!("{} inspect failed: {}", process.pid, e);
                    continue;
                }
            };
            if inspect_result {
                println!("{} inspected", process.pid);
                println!("try inspect phpfpm version");
                match inspect_phpfpm_version(&process_info) {
                    Ok(v) => {
                        println!("{} phpfpm version: {}", process_info.pid, v);
                    }
                    Err(e) => {
                        println!("{} inspect version failed: {}", process_info.pid, e);
                    }
                }
                // attach check
                match check_probe(&process_info) {
                    Ok(ProbeState::Attached) => {
                        println!("probe ATTACHED");
                    }
                    Ok(ProbeState::NotAttach) => {
                        println!("probe NotATTACH");
                    }
                    Err(e) => {
                        println!("{} check probe state failed: {}", process_info.pid, e);
                    }
                }
                // confd
                match inspect_php_ini_scan_dir(&process_info) {
                    Ok(confd) => {
                        println!("php confd: {}", confd);
                    }
                    Err(e) => {
                        println!("php confd failed: {}", e);
                    }
                }
                break
            } else {
                println!("{} not php", process.pid);
            }
        }
    }
}
