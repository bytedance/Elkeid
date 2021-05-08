use super::config::*;
use anyhow::*;
use lazy_static::lazy_static;
use log::*;
use regex::Regex;
use reqwest::blocking;
use sha2::{Digest, Sha256};
use std::fs::*;
use walkdir::WalkDir;
lazy_static! {
    pub static ref KERNEL_VERSION_RE: Regex =
        Regex::new(r"(^3\.1[0-9]\.)|(^4\.1[0-9]\.)|(^4\.[0-9]\.)|(^4\.20\.)|(^5\.[0-4]\.)")
            .unwrap();
}

fn download_sha(url: &str) -> Result<String> {
    // shasum is short. we can clone it
    let resp = blocking::get(url)?;
    Ok(resp.error_for_status()?.text()?)
}

fn download_and_verify_sha(file_url: &str, file_path: &str, sha_url: &str) -> Result<()> {
    info!("Downloading checksum from {}", sha_url);
    let digest = download_sha(sha_url)?;
    let digest = digest.trim();

    info!("Downloading from {}", file_url);
    let resp = blocking::get(file_url)?;
    let bin = resp.error_for_status()?.bytes()?;

    info!("Download success");

    if digest != format!("{:x}", Sha256::digest(&bin)) {
        Err(anyhow!("Checksum check failed"))
    } else {
        info!("Checksum check passed");
        Ok(write(file_path, bin)?)
    }
}

// Check if there is a recent crash
pub fn check_crash() -> Option<String> {
    // walk through all crashes
    for entry in WalkDir::new("/var/crash")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_str().is_some())
    {
        let file_name = entry.file_name().to_str().unwrap_or_default();
        let is_expired = std::time::SystemTime::now()
            .duration_since(entry.metadata().unwrap().modified().unwrap())
            .unwrap()
            > std::time::Duration::from_secs(48 * 60 * 60);
        if is_expired {
            continue;
        }
        if file_name.starts_with("dmesg") {
            let content = read_to_string(entry.path()).unwrap_or_default();
            if content.find("[hids_driver]").is_some() {
                return Some(content);
            } else {
                return None;
            }
        }
    }
    None
}

// Check if the kernel version meets the requirements
pub fn check_kernel_version() -> std::result::Result<(), String> {
    let kernel_version = read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    if (*KERNEL_VERSION_RE).is_match(&kernel_version) {
        Ok(())
    } else {
        Err(kernel_version)
    }
}

// Uninstall the driver
pub fn uninstall_driver() {
    let _ = std::process::Command::new("rmmod")
        .arg("hids_driver")
        .env("PATH", "/sbin:/bin:/usr/bin:/usr/sbin")
        .output();
}

fn get_modinfo(arg: &str) -> Result<std::process::Output> {
    std::process::Command::new("modinfo")
        .arg(arg)
        .env("PATH", "/sbin:/bin:/usr/bin:/usr/sbin")
        .output()
        .map_err(|e| anyhow!("{}", e))
}

fn get_info_from_modinfo(arg: &str, prefix: &str) -> Result<String> {
    let output = get_modinfo(arg)?;
    let lines = std::str::from_utf8(&output.stdout)?.lines();
    for i in lines {
        if i.starts_with(prefix) {
            let fields: Vec<&str> = i.split_whitespace().collect();
            if fields.len() == 2 {
                return Ok(fields[1].trim().to_owned());
            }
        }
    }

    Err(anyhow!("cannot find {} in modinfo output", prefix))
}
fn insmodprobe(cmd: &str, arg: &str) -> Result<()> {
    let output = std::process::Command::new(cmd)
        .arg(arg)
        .env("PATH", "/sbin:/bin:/usr/bin:/usr/sbin")
        .output()?;
    if output.status.success() {
        info!("{} hids_driver success", cmd);
        Ok(())
    } else {
        Err(anyhow!(String::from_utf8(output.stderr).unwrap_or_default()))
    }
}

// Prepare compatible ko
pub fn prepare_ko() -> Result<()> {
    // Uninstall LKM in case the user mode process aborted abnormally
    uninstall_driver();

    // Get the previous driver version
    let ko_file = format!("./{}-latest.ko", NAME);
    let last_version = get_info_from_modinfo(&ko_file, "version:").unwrap_or_default();

    // If version is the same, insmod and exit the function
    if last_version == VERSION {
        info!("Last version is the same version");
        return insmodprobe("insmod", &ko_file);
    }

    let kernel_version = read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();

    // version is different. download the dpkg package and install
    for i in KO_URL {
        // gen download link
        let checksum_url = format!("{}{}_{}_{}.sha256", i, NAME, VERSION,kernel_version);
        let ko_url = format!("{}{}_{}_{}.ko", i, NAME, VERSION,kernel_version);

        info!("Downloading ko from {}", ko_url);

        if let Err(e) = download_and_verify_sha(&ko_url, &ko_file, &checksum_url) {
            warn!("{}", e);
            continue;
        }

        info!("Ko write in file succeeded.");

        // Verify ko's vermagic
        if let Ok(info) = get_info_from_modinfo(&ko_file, "vermagic:") {
            if info.find(&kernel_version).is_none() {
                return Err(anyhow!("Ko vermagic verified failed"));
            }
        }
        // Install after verification
        return insmodprobe("insmod", &ko_file);
    }
    Err(anyhow!("Couldn't download ko"))
}
