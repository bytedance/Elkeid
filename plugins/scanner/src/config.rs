use serde::{Deserialize, Serialize};

// Cronjob wait interval time = 24 hours.
pub const WAIT_INTERVAL_DAILY: u64 = 3600 * 24;
pub const CACHE_SIZE: usize = 100;

// Plugin Config
pub const NAME: &str = "scanner";
pub const VERSION: &str = "0.0.0.1";

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
rule Andr_Exploit_Droidkungfu
{
strings:
	$s1 = "/system/bin/kill -9 %s"
	$s2 = "%s/myicon"
	$s3 = "%s/secbin"
	$s4 = "/system/bin/secbin"
condition:
	uint16(0) == 0x457f and all of them
}
rule Andr_Exploit_ExploitTools
{
strings:
	$s0 = "stack corruption detected: aborted" fullword ascii
	$s1 = "/proc/%d/fd/%d" fullword ascii
	$s2 = "SUCCESS: Enjoy the shell." fullword ascii
condition:
	uint16(0) == 0x457f and 2 of them
}
rule Andr_Exploit_Gingerbreak_unlocking_tools
{
strings:
	$s1 = "Android Exploid Crew."
	$s2 = "Killing ADB and restarting as root... enjoy!"
	$s3 = "GingerBread"
condition:
	uint16(0) == 0x457f and 2 of them
}
rule Andr_Exploit_ToolsZerglings
{
strings:
	$s0 = "Overseer found a path ! 0x%08x" fullword ascii
	$s1 = "Killing ADB and restarting as root... enjoy!" fullword ascii
	$s2 = "Zerglings" fullword ascii
condition:
	uint16(0) == 0x457f and 2 of them
}
rule HTML_CVE_2021_40444
{
strings:
	$h1 = "<?xml " ascii wide
	$s1 = "109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#109;&#108" ascii wide
condition:
	filesize < 25KB and all of them
}
rule Multios_CVE_2021_33766
{
strings:
	$ss0 = "POST " ascii
	$ss1 = " 500 0 0"
	$sa1 = "/ecp/" ascii
	$sa2 = "/RulesEditor/InboxRules.svc/NewObject" ascii
	$sb1 = "/ecp/" ascii
	$sb2 = "SecurityToken=" ascii
condition:
	all of ( $ss* ) and ( all of ( $sa* ) or all of ( $sb* ) )
}
rule Multios_Coinminer_MinerKeywords
{
strings:
	$m1 = "Miner"
	$m2 = "miner"
	$s1 = "Stratum"
	$s2 = "stratum"
	$e1 = "encrypt"
	$e2 = "Encrypt"
condition:
	($s1 or $s2) and ($m1 or $m2) and  ($e1 or $e2)
}
rule Multios_Coinminer_NameIoc
{
strings:
	$k01 = "_ZN5Miner"
	$k02 = "_ZN5miner"
	$k11 = "NBMiner"
	$k21 = "_ZN5xmrig"
	$k22 = "_ZN5Xmrig"
condition:
	any of them
}
rule Multios_Coinminer_StratumIoc
{
strings:
	$a1 = "stratum+tcp"
	$a2 = "stratum+udp"
	$a3 = "stratum+ssl"
	$a4 = "ethproxy+tcp"
	$a5 = "nicehash+tcp"
condition:
	any of them
}
rule Multios_Coinminer_StratumProtocol
{
strings:
	$a1 = "stratum+tcp"
	$a2 = "stratum+udp"
	$a3 = "stratum+ssl"
	$a4 = "ethproxy+tcp"
	$a5 = "nicehash+tcp"
condition:
	any of them
}
rule Multios_HKTL_KhepriBeaconRID3027
{
strings:
	$x1 = "NT %d.%d Build %d  ProductType:%s" ascii fullword
	$xe1 = "YzIuQ01EUEFSQU0uY21k" ascii
	$xe2 = "MyLkNNRFBBUkFNLmNtZ" ascii
	$xe3 = "jMi5DTURQQVJBTS5jbW" ascii
	$sx1 = "c2.ProcessItem.user" ascii fullword
	$sx2 = "c2.CMDPARAM.cmd" ascii fullword
	$sx3 = "c2.DownLoadFile.file_path" ascii fullword
	$sa1 = "file size zero"
	$sa2 = "cmd.exe /c "
	$sa3 = "error parse param"
	$sa4 = "innet_ip"
	$op1 = { c3 b9 b4 98 49 00 87 01 5d c3 b8 b8 98 49 00 c3 8b ff }
	$op2 = { 8b f1 80 3d 58 97 49 00 00 0f 85 96 00 00 00 33 c0 40 b9 50 97 49 00 87 01 33 db }
	$op3 = { 90 d5 0c 43 00 34 0d 43 00 ea 0c 43 00 7e 0d 43 00 b6 0d 43 00 cc }
	$op4 = { 69 c0 ff 00 00 00 8b 4d c0 23 88 40 7c 49 00 89 4d c0 8b 45 cc 0b 45 c0 89 45 cc 8b 45 d0 }
condition:
	( uint16 (0) == 0x5a4d or uint32(0) == 0x464c457f ) and filesize < 2000KB and ( 1 of ( $x* ) or 2 of ( $sx* ) or all of ( $sa* ) or 3 of ( $op* ) ) or ( filesize < 10MB and 1 of ( $xe* ) ) or 5 of them
}
rule Multios_Ransome_BlackMatter
{
strings:
	$s1 = "Another Instance Currently Running..."
	$s2 = "Removing Self Executable..."
	$s3 = "web_reporter::main_sender_proc()"
	$s4 = "NO stat available for "
	$s5 = "Please, just wait..."
	$s6 = ".cfgETD"
condition:
	all of them
}
rule Multios_Trojan_Stowaway
{
strings:
	$k1 = "Stowaway"
condition:
	$k1
}
rule Unix_CVE_2021_26084
{
strings:
	$xr1 = /isSafeExpression Unsafe clause found in \['[^\n]{1,64}\\u0027/ ascii
	$xs1 = "[util.velocity.debug.DebugReferenceInsertionEventHandler] referenceInsert resolving reference [$!queryString]"
	$xs2 = "userName: anonymous | action: createpage-entervariables ognl.ExpressionSyntaxException: Malformed OGNL expression: '\\' [ognl.TokenMgrError: Lexical error at line 1"
	$sa1 = "GET /pages/doenterpagevariables.action"
	$sb1 = "%5c%75%30%30%32%37"
	$sb2 = "\\u0027"
	$sc1 = " ERROR "
	$sc2 = " | userName: anonymous | action: createpage-entervariables"
	$re1 = /\[confluence\.plugins\.synchrony\.SynchronyContextProvider\] getContextMap (\n )?-- url: \/pages\/createpage-entervariables\.action/
condition:
	1 of ( $x* ) or ( $sa1 and 1 of ( $sb* ) ) or ( all of ( $sc* ) and $re1 )
}
rule Unix_CVE_2021_38647
{
strings:
	$a1 = "/opt/omi/bin/omiagent" ascii fullword
	$s1 = "OMI-1.6.8-0 - " ascii
	$s2 = "OMI-1.6.6-0 - " ascii
	$s3 = "OMI-1.6.4-1 - " ascii
	$s4 = "OMI-1.6.4-0 - " ascii
	$s5 = "OMI-1.6.2-0 - " ascii
	$s6 = "OMI-1.6.1-0 - " ascii
	$s7 = "OMI-1.5.0-0 - " ascii
	$s8 = "OMI-1.4.4-0 - " ascii
	$s9 = "OMI-1.4.3-2 - " ascii
	$s10 = "OMI-1.4.3-1 - " ascii
	$s11 = "OMI-1.4.3-0 - " ascii
	$s12 = "OMI-1.4.2-5 - " ascii
	$s13 = "OMI-1.4.2-4 - " ascii
	$s14 = "OMI-1.4.2-3 - " ascii
	$s15 = "OMI-1.4.2-2 - " ascii
	$s16 = "OMI-1.4.2-1 - " ascii
	$s17 = "OMI-1.4.1-1 - " ascii
	$s18 = "OMI-1.4.1-0 - " ascii
	$s19 = "OMI-1.4.0-6 - " ascii
condition:
	uint32(0) == 0x464c457f and $a1 and 1 of ( $s* )
}
rule Unix_CVE_2021_40539
{
strings:
	$x1 = "/ServletApi/../RestApi/LogonCustomization" ascii wide
	$x2 = "/ServletApi/../RestAPI/Connection" ascii wide
condition:
	filesize < 50MB and 1 of them
}
rule Unix_DDOS_Kaiten
{
strings:
	$irc = /(PING)|(PONG)|(NOTICE)|(PRIVMSG)/
	$kill = "Killing pid %d" nocase
	$subnet = "What kind of subnet address is that" nocase
	$version = /(Helel mod)|(Kaiten wa goraku)/
	$flood = "UDP <target> <port> <secs>" nocase
condition:
	uint16(0) == 0x457f and $irc and 2 of ($kill, $subnet, $version, $flood)
}
rule Unix_Exploit_PsyBNC
{
strings:
	$s1 = "psychoid Exp"
	$s2 = "(%s)!psyBNC@lam3rz.de PRIVMSG %s :%s"
condition:
	uint16(0) == 0x457f and all of them
}
rule Unix_Malware_HttpsdARM
{
strings:
	$hexsts01 = { f0 4f 2d e9 1e db 4d e2 ec d0 4d e2 01 40 a0 e1 }
	$hexsts02 = { f0 45 2d e9 0b db 4d e2 04 d0 4d e2 3c 01 9f e5 }
	$hexsts03 = { f0 45 2d e9 01 db 4d e2 04 d0 4d e2 bc 01 9f e5 }
	$st01 = "k.conectionapis.com" fullword nocase wide ascii
	$st02 = "key=%s&host_name=%s&cpu_count=%d&os_type=%s&core_count=%s" fullword nocase wide ascii
	$st03 = "id=%d&result=%s" fullword nocase wide ascii
	$st04 = "rtime" fullword nocase wide ascii
	$st05 = "down" fullword nocase wide ascii
	$st06 = "cmd" fullword nocase wide ascii
	$st07 = "0 */6 * * * root" fullword nocase wide ascii
	$st08 = "/etc/cron.d/httpsd" fullword nocase wide ascii
	$st09 = "cat /proc/cpuinfo |grep processor|wc -l" fullword nocase wide ascii
	$st10 = "k.conectionapis.com" fullword nocase wide ascii
	$st11 = "/api" fullword nocase wide ascii
	$st12 = "/tmp/.httpslog" fullword nocase wide ascii
	$st13 = "/bin/.httpsd" fullword nocase wide ascii
	$st14 = "/tmp/.httpsd" fullword nocase wide ascii
	$st15 = "/tmp/.httpspid" fullword nocase wide ascii
	$st16 = "/tmp/.httpskey" fullword nocase wide ascii
condition:
	uint16(0) == 0x457f and filesize < 200KB and all of them
}
rule Unix_Malware_Httpsdi86
{
strings:
	$hexsts01 = { 8d 4c 24 04 83 e4 f0 ff 71 fc 55 89 e5 57 56 53 }
	$hexsts02 = { 55 89 e5 57 56 53 81 ec 14 2c 00 00 68 7a 83 05 }
	$hexsts03 = { 55 89 e5 57 56 53 81 ec 10 04 00 00 68 00 04 00 }
	$st01 = "k.conectionapis.com" fullword nocase wide ascii
	$st02 = "key=%s&host_name=%s&cpu_count=%d&os_type=%s&core_count=%s" fullword nocase wide ascii
	$st03 = "id=%d&result=%s" fullword nocase wide ascii
	$st04 = "rtime" fullword nocase wide ascii
	$st05 = "down" fullword nocase wide ascii
	$st06 = "cmd" fullword nocase wide ascii
	$st07 = "0 */6 * * * root" fullword nocase wide ascii
	$st08 = "/etc/cron.d/httpsd" fullword nocase wide ascii
	$st09 = "cat /proc/cpuinfo |grep processor|wc -l" fullword nocase wide ascii
	$st10 = "k.conectionapis.com" fullword nocase wide ascii
	$st11 = "/api" fullword nocase wide ascii
	$st12 = "/tmp/.httpslog" fullword nocase wide ascii
	$st13 = "/bin/.httpsd" fullword nocase wide ascii
	$st14 = "/tmp/.httpsd" fullword nocase wide ascii
	$st15 = "/tmp/.httpspid" fullword nocase wide ascii
	$st16 = "/tmp/.httpskey" fullword nocase wide ascii
condition:
	(uint16(0) == 0x457f) and (filesize < 200KB) and (all of them)
}
rule Unix_Malware_RebirthVulcan
{
strings:
	$spec01 = "vulcan.sh" fullword nocase wide ascii
	$spec02 = "Vulcan" fullword nocase wide ascii
	$str01 = "/usr/bin/python" fullword nocase wide ascii
	$str02 = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" fullword nocase wide ascii
	$str03 = "Telnet Range %d->%d" fullword nocase wide ascii
	$str04 = "Mirai Range %d->%d" fullword nocase wide ascii
	$str05 = "[Updating] [%s:%s]" fullword nocase wide ascii
	$str06 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*" fullword nocase wide ascii
	$str07 = "\x1B[96m[DEVICE] \x1B[97mConnected" fullword nocase wide ascii
	$hex01 = { 0D C0 A0 E1 00 D8 2D E9 }
	$hex02 = { 3C 1C 00 06 27 9C 97 98 }
	$hex03 = { 94 21 EF 80 7C 08 02 A6 }
	$hex04 = { E6 2F 22 4F 76 91 18 3F }
	$hex05 = { 06 00 1C 3C 20 98 9C 27 }
	$hex06 = { 55 89 E5 81 EC ?? 10 00 }
	$hex07 = { 55 48 89 E5 48 81 EC 90 }
	$hex08 = { 6F 67 69 6E 00 }
	$bot01 = "MIRAITEST" fullword nocase wide ascii
	$bot02 = "TELNETTEST" fullword nocase wide ascii
	$bot03 = "UPDATE" fullword nocase wide ascii
	$bot04 = "PHONE" fullword nocase wide ascii
	$bot05 = "RANGE" fullword nocase wide ascii
	$bot06 = "KILLATTK" fullword nocase wide ascii
	$bot07 = "STD" fullword nocase wide ascii
	$bot08 = "BCM" fullword nocase wide ascii
	$bot09 = "NETIS" fullword nocase wide ascii
	$bot10 = "FASTLOAD" fullword nocase wide ascii
condition:
	uint32(0) == 0x464c457f and filesize < 300KB and all of ($spec*) and 4 of ($str*) and 2 of ($hex*) and 6 of ($bot*)
}
rule Unix_Packer_MumblehardM1
{
strings:
	$decrypt = { 31 db  [1-10]  ba ?? 00 00 00  [0-10]  (56 5f | 89 F7) 39 d3 75 13 81 fa ?? (00 | 01) 00 00 75 02 31 d2 81 c2 ?? 00 00 00 31 db 43 ac 30 d8 aa 43 e2 e2 }
condition:
	$decrypt
}
rule Unix_Packer_UpxDetail
{
strings:
	$a1 = "UPX!"
	$a2 = " UPX "
	$a3 = "!XPU"
	$h1 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 41 ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 48 89 E5 44 8B 09 49 89 D0 48 89 F2 48 8D 77 02 56 8A 07 FF CA 88 C1 }
	$h2 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB 31 C9 48 83 CD FF E8 ?? ?? ?? ?? 01 DB 74 ?? F3 C3 8B 1E 48 83 EE FC 11 DB 8A }
	$h3 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 11 0B 00 00 60 8B 74 24 24 8B 7C 24 2C 83 CD FF 89 E5 8B 55 28 AC 4A 88 C1 24 07 C0 E9 03 BB 00 FD FF FF D3 E3 8D A4 5C 90 F1 FF FF 83 E4 E0 6A 00 6A }
	$h4 = { FC 41 5B 41 80 F8 ?? 74 0D E9 ?? ?? ?? ?? 48 FF C6 88 17 48 FF C7 8A 16 01 DB 75 0A 8B 1E 48 83 EE FC 11 DB 8A 16 72 E6 8D 41 01}
condition:
	uint32(0) == 0x464c457f and any of them
}
rule Unix_Spyware_Bouncer
{
strings:
	$s1 = "/shutdown_request\">Shutdown Bouncer"
	$s2 = "Bouncer Successfully Shutdown"
	$s3 = "%s Bouncer Daemonized (PID = %d)"
condition:
	uint16(0) == 0x457f and all of them
}
rule Unix_Spyware_EquationGroup_morerats_client_Store
{
strings:
	$s1 = "[-] Failed to mmap file: %s" fullword ascii
	$s2 = "[-] can not NULL terminate input data" fullword ascii
	$s3 = "Missing argument for `-x'." fullword ascii
	$s4 = "[!] Value has size of 0!" fullword ascii
condition:
	uint16(0) == 0x457f and filesize < 60KB and 2 of them
}
rule Unix_Spyware_Suspicious_script
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
	$sensitive_ops6 = "netcat -l"
	$bad_ops1 = "nc -l"
	$bad_ops2 = "bash -i"
	$sensitive_ops9 = "ulimit -n"
	$root1 = "insmod"
	$root2 = "modprobe"
	$root3 = "sysctl -w"
	$root4 = "wrmsr -a"
condition:
	uint32(0) != 0x464c457f and filesize < 256KB and ( (8 of them) or $bad_ops1 or $bad_ops2 )
}
rule Unix_Trojan_TinyShell
{
strings:
	$vara01 = { 73 3A 70 3A 00 }
	$vara02 = { 55 74 61 67 65 3A 20 25 73 }
	$vara03 = { 5B 20 2D 73 20 73 65 63 72 65 74 20 5D }
	$vara04 = { 5B 20 2D 70 20 70 6F 72 74 20 5D }
	$varb01 = { 41 57 41 56 41 55 41 54 55 53 0F B6 06 }
	$varb02 = { 48 C7 07 00 00 00 00 48 C7 47 08 00 00 }
	$vard01 = { 55 48 89 E5 41 57 41 56 41 55 41 54 53 }
	$vard02 = { 55 48 89 E5 48 C7 47 08 00 00 00 00 48 }
	$varb03 = { 89 DF E8 FB A4 FF FF 83 C3 01 81 FB 00 04 }
	$vard03 = { 66 89 05 7D 5E 00 00 }
	$vare01 = "socket"
	$vare02 = "connect"
	$vare03 = "alarm"
	$vare04 = "dup2"
	$vare05 = "execl"
	$vare06 = "openpty"
	$vare07 = "putenv"
	$vare08 = "setsid"
	$vare09 = "ttyname"
	$vare00 = "waitpid"
	$varc01 = "HISTFIL"
	$varc02 = "TERML"
	$varc03 = "/bin/sh"
condition:
	(uint16(0) == 0x457f) and (all of ($vara*)) and ( filesize > 20KB or ( filesize < 100KB and ( (2 of ($varb*) or 2 of ($vard*)) or (1 of ($varb0*)) or (5 of ($vare*) or 2 of ($varc*)) ) ) )
}
rule Win_Packer_AnskyaNTPackerGeneratorAnskya
{
strings:
	$a0 = { 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50 E8 71 FB FF FF 8B D8 85 DB 74 2F 53 A1 14 31 00 10 50 E8 97 FB FF FF 85 C0 74 1F 53 A1 14 31 00 10 50 E8 5F FB FF FF 85 C0 74 0F 50 E8 5D FB FF FF 85 C0 74 05 E8 70 FC FF FF 5B E8 F2 F6 FF FF 00 00 48 45 41 52 54 }
condition:
	uint16 (0) == 0x5a4d and $a0
}
rule Win_Packer_BanbraBanker
{
strings:
	$a = "senha" fullword nocase
	$b = "cartao" fullword nocase
	$c = "caixa"
	$d = "login" fullword nocase
	$e = ".com.br"
condition:
	uint16 (0) == 0x5a4d and (#a > 3 and #b > 3 and #c > 3 and #d > 3 and #e > 3)
}
rule Win_Packer_Borland
{
strings:
	$patternBorland = "Borland" wide ascii
condition:
	uint16 (0) == 0x5a4d and $patternBorland
}
rule Win_Packer_DxPackV086Dxd
{
strings:
	$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }
condition:
	uint16 (0) == 0x5a4d and $a0
}
rule Win_Packer_EmbedPEV100V124cyclotron
{
strings:
	$a0 = { 00 00 00 00 [4] 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [12] 00 00 00 00 [12] 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 }
condition:
	uint16 (0) == 0x5a4d and $a0
}
rule Win_Packer_Emotet
{
strings:
	$pdb1 = "123EErrrtools.pdb"
	$pdb2 = "gGEW\\F???/.pdb"
condition:
	uint16 (0) == 0x5a4d and $pdb1 or $pdb2
}
rule Win_Packer_EnigmaProtector1XSukhovVladimirSergeNMarkin
{
strings:
	$a0 = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 52 65 67 43 6C 6F 73 65 4B 65 79 00 00 00 53 79 73 46 72 65 65 53 74 72 69 6E 67 00 00 00 43 72 65 61 74 65 46 6F 6E 74 41 00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 00 00 }
condition:
	uint16 (0) == 0x5a4d and $a0
}
rule Win_Packer_MSLRHv032afakePCGuard4xxemadicius
{
strings:
	$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
condition:
	uint16 (0) == 0x5a4d and $a0
}
rule Win_Packer_SPLayerv008
{
strings:
	$a0 = { 8D 40 00 B9 [4] 6A ?? 58 C0 0C [2] 48 [2] 66 13 F0 91 3B D9 [8] 00 00 00 00 }
condition:
	uint16 (0) == 0x5a4d and $a0
}
rule Win_Packer_ZbotBanker
{
strings:
	$a = "__SYSTEM__" wide
	$b = "*tanentry*"
	$c = "*<option"
	$d = "*<select"
	$e = "*<input"
condition:
	uint16 (0) == 0x5a4d and (($a and $b) or ($c and $d and $e))
}
"#;
