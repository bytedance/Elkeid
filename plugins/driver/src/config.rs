use std::{collections::HashSet, time::Duration};

use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;
use lazy_static::lazy_static;
pub const KMOD_VERSION: &str = "1.7.0.4";
pub const KMOD_NAME: &str = "hids_driver";
pub const PIPE_PATH: &str = "/proc/elkeid-endpoint";
pub const CONTROL_PATH: &str = "/dev/hids_driver_allowlist";
pub const PARAMETERS_DIR: &str = "/sys/module/hids_driver/parameters";
pub const REMOVE_EXE_FILTER_FLAG: &[u8] = b"F";
pub const ADD_EXE_FILTER_FLAG: &[u8] = b"Y";
pub const REMOVE_ALL_EXE_FILTER_FLAG: &[u8] = b"w";
pub const REMOVE_ARGV_FILTER_FLAG: &[u8] = b"J";
pub const ADD_ARGV_FILTER_FLAG: &[u8] = b"m";
pub const REMOVE_ALL_ARGV_FILTER_FLAG: &[u8] = b"u";
pub const PADDING_CONTENT: &[u8] = b"elkeid";
pub const CONNECT_FILTER_TIME: Duration = Duration::from_secs(60 * 30);
pub const ARGV_FILTER_SIZE: usize = 1024 * 8;
pub const CONNECT_FILTER_SIZE: usize = 1024 * 16;
pub const EXE_FILTER_TIME: Duration = Duration::from_secs(60 * 10);
// limit tps=9000/60=150
pub const EXE_FILTER_QUOTA: usize = 9000;
pub const EXE_FILTER_WINDOW: Duration = Duration::from_secs(60);
pub const EXE_FILTER_SIZE: usize = 32 * 1024;
// limit tps=600/60=25
pub const ARGV_FILTER_TIME: Duration = Duration::from_secs(60);
pub const ARGV_FILTER_QUOTA: usize = 1500;
pub const ARGV_FILTER_WINDOW: Duration = Duration::from_secs(60 * 60);
pub const ARGV_DYN_FILTER_SIZE: usize = 512;
pub const ARGV_DYN_FILTER_QUOTA: usize = 6000;
pub const ARGV_DYN_FILTER_WINDOW: Duration = Duration::from_secs(60);
pub const DOWNLOAD_HOSTS: &'static [&'static str] = &[
    "https://lf3-elkeid.bytetos.com/obj/elkeid-download/ko/",
    "https://lf6-elkeid.bytetos.com/obj/elkeid-download/ko/",
    "https://lf9-elkeid.bytetos.com/obj/elkeid-download/ko/",
    "https://lf26-elkeid.bytetos.com/obj/elkeid-download/ko/",
];
pub const DNS_SUFFIX_WHITELIST: &[&[u8]] = &[];
// max length=128
pub const EXE_WHITELIST: &[&[u8]] = &[];
// max length=128
pub const ARGV_WHITELIST: &[&[u8]] = &[];
lazy_static! {
    pub static ref IPV4_FILTER: IpRange<Ipv4Net> = {
        let mut r = IpRange::new();
        r.add("127.0.0.1/8".parse().unwrap());
        r
    };
    pub static ref IPV6_FILTER: IpRange<Ipv6Net> = {
        let mut r = IpRange::new();
        r.add("fe80::/10".parse().unwrap())
            .add("::ffff:127.0.0.1/104".parse().unwrap())
            .add("::1/128".parse().unwrap());
        r
    };
    pub static ref PGID_ARGV_WHITELIST: HashSet<&'static [u8]> = {
        let s = HashSet::new();
        s
    };
}
