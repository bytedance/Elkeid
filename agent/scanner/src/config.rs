use serde::{Deserialize, Serialize};

// Cronjob wait interval time = 24 hours.
pub const WAIT_INTERVAL_DAILY: u64 = 3600 * 24;
pub const CACHE_SIZE: usize = 100;

// Plugin Config
pub const NAME: &str = "scanner";
pub const VERSION: &str = "0.0.0.0";
pub const SOCKET_PATH: &str = "./plugin.sock";

// Scanner Config
pub const LOAD_MMAP_MAX_SIZE: usize = 1024 * 1024 * 44; // scan max file size

// Cronjob Config
pub const WAIT_INTERVAL_DIR_SCAN: std::time::Duration = std::time::Duration::from_secs(2);
pub const WAIT_INTERVAL_PROC_SCAN: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct ScanConfig<'a> {
    pub fpath: &'a str,   // scan dir
    pub max_depth: usize, // scan dir max depth
}

// SCAN_DIR : config directory for yara scan
#[cfg(not(feature = "debug"))]
pub const SCAN_DIR_CONFIG: &[&ScanConfig] = &[
    &ScanConfig {
        fpath: "/bin", // scan dir
        max_depth: 1,  // scan dir max depth
    },
    &ScanConfig {
        fpath: "/sbin",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/usr/bin",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/usr/sbin",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/usr/local",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/usr/local/bin",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/usr/local/sbin",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/usr/local/share",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/usr/local/sbin",
        max_depth: 1,
    },
    &ScanConfig {
        fpath: "/root",
        max_depth: 2,
    },
    &ScanConfig {
        fpath: "/root/.ssh",
        max_depth: 2,
    },
    &ScanConfig {
        fpath: "/etc",
        max_depth: 2,
    },
];

pub const SCAN_DIR_FILTER: &[&str] = &[
    // root filter
    "/root/.debug", // vscode debug at root
    "/root/.vscode",
    "/root/.bash_history",
    // file filter
    "/usr/bin/killall",
    "/usr/bin/upx",
    "/etc/alternatives/upx",
];

// RULES_SET : yara rule sets
pub const RULES_SET: &str = r#"
private rule is_elf
{
    condition:
    uint32(0) == 0x464c457f
}

private rule upx_file_size
{
    condition:
    is_elf and filesize < 20MB
}

private rule is_script
{
    condition:
    uint32(0) != 0x464c457f and filesize < 512KB
}

rule miner_stratum_elf
{
	strings:
    $a1 = "stratum+tcp"
    $a2 = "stratum+udp"
    $a3 = "stratum+ssl"
    condition:
    is_elf and any of them
}

rule miner_script
{
	strings:
    $a1 = "stratum+tcp"
    $a2 = "stratum+udp"
    $a3 = "stratum+ssl"
    $a4 = "ethproxy+tcp"
    $a5 = "nicehash+tcp"
    condition:
    is_script and any of them
}

rule miner_ioc
{
	strings:
    $m1 = "Miner"
    $m2 = "miner"
    $s1 = "Stratum"
    $s2 = "stratum"
    $e1 = "encrypt"
    $e2 = "Encrypt"

    condition:
    is_elf and ($m1 or $m2) and ($s1 or $s2) and ($e1 or $e2)
}

rule upx_base
{
	strings:
    $a1 = "UPX!"
    $a2 = " UPX "
    condition:
    upx_file_size and ($a1 or $a2)
}

rule upx_detail
{
	strings:
	$h1 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 41 ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 48 89 E5 44 8B 09 49 89 D0 48 89 F2 48 8D 77 02 56 8A 07 FF CA 88 C1 }
    $h2 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB 31 C9 48 83 CD FF E8 ?? ?? ?? ?? 01 DB 74 ?? F3 C3 8B 1E 48 83 EE FC 11 DB 8A }
    $h3 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 11 0B 00 00 60 8B 74 24 24 8B 7C 24 2C 83 CD FF 89 E5 8B 55 28 AC 4A 88 C1 24 07 C0 E9 03 BB 00 FD FF FF D3 E3 8D A4 5C 90 F1 FF FF 83 E4 E0 6A 00 6A }
    $h4 = { FC 41 5B 41 80 F8 ?? 74 0D E9 ?? ?? ?? ?? 48 FF C6 88 17 48 FF C7 8A 16 01 DB 75 0A 8B 1E 48 83 EE FC 11 DB 8A 16 72 E6 8D 41 01}
	condition:
    upx_file_size and any of them
}

rule suspicious_script
{
    strings:
        $kill1 = "kill -9" 
        $kill2 = "killall"
        $kill3 = "pkill -f"
        $remove1 = "rm -f"
        $remove2 = "rm -rf"
        $download1 = "wget "
        $download2 = "curl "
        $download3 = "tftp "
        $iptables1 = "iptables -A"
        $iptables2 = "iptables -F"
        $has_sensitive_file1 = "/root"
        $has_sensitive_file2 = "/etc/cron"
        $has_sensitive_file3 = "/.ssh"
        $has_sensitive_file4 = "system"
        $has_sensitive_file5 = "/usr/bin/passwd"
        $sensitive_ops1 = "chmod 777 "
        $sensitive_ops2 = "setsid"
        $sensitive_ops3 = "chattr -i"
        $sensitive_ops4 = "nohup" 
        $sensitive_ops6 = "netcat" 
        $bad_ops1 = "nc -l" 
        $bad_ops2 = "bash -i"
        $sensitive_ops9 = "ulimit -n"
        $root1 = "insmod"
        $root2 = "modprobe"
        $root3 = "sysctl -w"
        $root4 = "wrmsr -a"
    condition:
    is_script
    and (
         (8 of them) or $bad_ops1 or $bad_ops2
    )
}
"#;
