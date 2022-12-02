mod cache;
mod schema;

use anyhow::{anyhow, Result};
use lru_cache::LruCache;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    io::{Error, ErrorKind},
    str,
    time::{SystemTime, UNIX_EPOCH},
};
use ttl_cache::TtlCache;

use crate::config::*;
use crate::kmod::Kmod;

use self::cache::*;
#[cfg(not(feature = "debug"))]
#[inline]
fn encode_varint(mut n: u64, dst: &mut [u8]) -> usize {
    let mut i = 0;
    while n >= 0x80 {
        dst[i] = 0x80 | (n as u8);
        i += 1;
        n >>= 7;
    }
    dst[i] = n as u8;
    i + 1
}
#[cfg(not(feature = "debug"))]
#[inline]
fn encoded_varint_len(n: u64) -> usize {
    // Based on [VarintSize64][1].
    // [1]: https://github.com/google/protobuf/blob/3.3.x/src/google/protobuf/io/coded_stream.h#L1301-L1309
    ((((n | 1).leading_zeros() ^ 63) * 9 + 73) / 64) as usize
}
#[cfg(not(feature = "debug"))]
fn protobuf_encode(
    timestamp: u64,
    keys: &&[&[u8]],
    values: &[&[u8]],
    dst: &mut [u8],
    data_type: u64,
) -> Result<usize> {
    let mut needed_length: usize = 0;
    if data_type > 0 {
        needed_length += 3 + encoded_varint_len(data_type);
    }
    if timestamp > 0 {
        needed_length += 3 + encoded_varint_len(timestamp);
    }
    let mut map_length = 0;
    if keys.len() > 0 {
        for i in 0..keys.len() {
            let entry_length = 1
                + keys[i].len()
                + encoded_varint_len(keys[i].len() as u64)
                + 1
                + values[i].len()
                + encoded_varint_len(values[i].len() as u64);
            map_length += 1 + entry_length + encoded_varint_len(entry_length as u64);
        }
        needed_length += 1 + map_length + encoded_varint_len(map_length as u64);
    }
    if needed_length > dst.len() {
        Err(Error::new(ErrorKind::WriteZero, "not enough buffer").into())
    } else {
        let mut index = needed_length;
        if keys.len() > 0 {
            for i in 0..keys.len() {
                let base_index = index;
                index -= values[i].len();
                dst[index..index + values[i].len()].copy_from_slice(values[i]);
                index -= encoded_varint_len(values[i].len() as u64);
                encode_varint(values[i].len() as u64, &mut dst[index..]);
                index -= 1;
                dst[index] = 0x12;
                index -= keys[i].len();
                dst[index..index + keys[i].len()].copy_from_slice(keys[i]);
                index -= encoded_varint_len(keys[i].len() as u64);
                encode_varint(keys[i].len() as u64, &mut dst[index..]);
                index -= 1;
                dst[index] = 0xa;
                let entry_length = base_index - index;
                index -= encoded_varint_len((entry_length) as u64);
                encode_varint((entry_length) as u64, &mut dst[index..]);
                index -= 1;
                dst[index] = 0xa;
            }
            index -= encoded_varint_len((map_length) as u64);
            encode_varint((map_length) as u64, &mut dst[index..]);
        }
        index -= 1;
        dst[index] = 0x1a;
        if timestamp != 0 {
            index -= encoded_varint_len((timestamp) as u64);
            encode_varint((timestamp) as u64, &mut dst[index..]);
            index -= 1;
            dst[index] = 0x10;
        }
        index -= encoded_varint_len(data_type);
        encode_varint(data_type, &mut dst[index..]);
        dst[4] = 0x8;
        dst[..4].copy_from_slice(&((needed_length - 4) as u32).to_le_bytes()[..]);
        Ok(needed_length)
    }
}
#[cfg(feature = "debug")]
fn json_encode(
    timestamp: u64,
    keys: &&[&[u8]],
    values: &[&[u8]],
    dst: &mut [u8],
    data_type: u64,
) -> Result<usize> {
    use serde_json::to_vec;
    use std::collections::HashMap;
    let mut data = HashMap::new();
    for i in 0..keys.len() {
        data.insert(
            str::from_utf8(keys[i]).unwrap(),
            str::from_utf8(values[i]).unwrap(),
        );
    }
    use serde::Serialize;
    #[derive(Serialize)]
    struct Record<'a> {
        data_type: u64,
        timestamp: u64,
        data: HashMap<&'a str, &'a str>,
    }
    let rec = Record {
        data_type,
        timestamp,
        data,
    };
    let mut buf = to_vec(&rec)?;
    buf.push(b'\n');
    if buf.len() > dst.len() {
        Err(Error::new(ErrorKind::WriteZero, "not enough buffer").into())
    } else {
        dst[..buf.len()].copy_from_slice(&buf);
        Ok(buf.len())
    }
}
fn encode(
    timestamp: u64,
    keys: &&[&[u8]],
    values: &[&[u8]],
    dst: &mut [u8],
    data_type: u64,
) -> Result<usize> {
    #[cfg(feature = "debug")]
    {
        json_encode(timestamp, keys, values, dst, data_type)
    }
    #[cfg(not(feature = "debug"))]
    {
        protobuf_encode(timestamp, keys, values, dst, data_type)
    }
}
pub struct Transformer {
    argv_cache: ArgvCache,
    hash_cache: HashCache,
    ns_cache: NsCache,
    user_cache: UserCache,
    pid_tree_cache: LruCache<Vec<u8>, Vec<u8>>,
    connect_filter: TtlCache<Vec<u8>, ()>,
    exe_filter: TtlCache<Vec<u8>, usize>,
    argv_filter: TtlCache<Vec<u8>, usize>,
    argv_dyn_filter: TtlCache<Vec<u8>, usize>,
}

impl Transformer {
    pub fn new() -> Self {
        Self {
            argv_cache: ArgvCache::new(1024 * 8),
            hash_cache: HashCache::new(1024 * 4),
            ns_cache: NsCache::new(1024),
            user_cache: UserCache::new(),
            pid_tree_cache: LruCache::new(2048),
            connect_filter: TtlCache::new(CONNECT_FILTER_SIZE),
            exe_filter: TtlCache::new(EXE_FILTER_SIZE),
            argv_filter: TtlCache::new(ARGV_FILTER_SIZE),
            argv_dyn_filter: TtlCache::new(ARGV_DYN_FILTER_SIZE),
        }
    }
    pub fn transform(&mut self, data: &[u8], dst: &mut [u8], kmod: &mut Kmod) -> Result<usize> {
        let length = data.len();
        let mut index = 0;
        while index < length {
            if data[index] == 0x1e {
                break;
            }
            index += 1;
        }
        let data_type = str::from_utf8(&data[..index])?.parse::<u32>()?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;
        let data = &data[index + 1..];
        match data_type {
            42 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 25] = [&[]; 25];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                }
                if {
                    if values[12] == b"10" {
                        if let Ok(Ok(ip)) =
                            str::from_utf8(values[13]).map(|s| s.parse::<Ipv6Addr>())
                        {
                            IPV6_FILTER.contains(&ip)
                        } else {
                            false
                        }
                    } else {
                        if let Ok(Ok(ip)) =
                            str::from_utf8(values[13]).map(|s| s.parse::<Ipv4Addr>())
                        {
                            IPV4_FILTER.contains(&ip)
                        } else {
                            false
                        }
                    }
                } || {
                    // sid dip dport res
                    let mut key = Vec::with_capacity(
                        values[6].len() + values[13].len() + values[14].len() + values[17].len(),
                    );
                    key.extend_from_slice(values[6]);
                    key.extend_from_slice(values[13]);
                    key.extend_from_slice(values[14]);
                    key.extend_from_slice(values[17]);
                    if self.connect_filter.contains_key(&key) {
                        true
                    } else {
                        self.connect_filter.insert(key, (), CONNECT_FILTER_TIME);
                        false
                    }
                } {
                    return Ok(0);
                }
                let argv = self.argv_cache.get(values[5]);
                values[18] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[19] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[20] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[21] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[22] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[23] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[24] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            49 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 23] = [&[]; 23];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                }
                let argv = self.argv_cache.get(values[5]);
                values[16] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[17] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[18] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[19] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[20] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[21] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[22] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            59 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 33] = [&[]; 33];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                self.argv_cache.put(values[5].to_vec(), values[12].to_vec());
                self.pid_tree_cache
                    .insert(values[5].to_vec(), values[21].to_vec());
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                    if let Some(value) = self.argv_filter.get_mut(values[12]) {
                        if *value > ARGV_FILTER_QUOTA {
                            kmod.add_filtered_argv(values[12]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[12].to_vec(), 1, ARGV_FILTER_WINDOW);
                    };
                }
                let socket_argv = self.argv_cache.get(values[23]);
                values[27] = &socket_argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[28] = &ppid_argv;
                if PPID_ARGV_WHITELIST.contains(ppid_argv.as_slice()) {
                    return Ok(0);
                }
                let pgid_argv = self.argv_cache.get(values[4]);
                if PGID_ARGV_WHITELIST.contains(pgid_argv.as_slice()) {
                    return Ok(0);
                }
                values[29] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[30] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[31] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[32] = &exe_hash;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            82 | 86 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 22] = [&[]; 22];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                }
                let argv = self.argv_cache.get(values[5]);
                values[15] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[16] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[17] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[18] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[19] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[20] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[21] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            101 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 24] = [&[]; 24];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                let argv = self.argv_cache.get(values[5]);
                values[17] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[18] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[19] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[20] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[21] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[22] = &exe_hash;
                let target_argv = self.argv_cache.get(values[13]);
                values[23] = &target_argv;
                self.pid_tree_cache
                    .insert(values[5].to_vec(), values[16].to_vec());
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            112 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 19] = [&[]; 19];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                }
                let argv = self.argv_cache.get(values[5]);
                values[12] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[13] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[14] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[15] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[16] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[17] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[18] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            157 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 21] = [&[]; 21];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                }
                let argv = self.argv_cache.get(values[5]);
                if argv != b"-3" {
                    if let Some(counter) = self.argv_dyn_filter.get_mut(&argv) {
                        if *counter > ARGV_DYN_FILTER_QUOTA {
                            return Ok(0);
                        } else {
                            *counter += 1;
                        }
                    } else {
                        self.argv_dyn_filter
                            .insert(argv.to_vec(), 0, ARGV_DYN_FILTER_WINDOW);
                    }
                }
                values[14] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[15] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[16] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[17] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[18] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[19] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[20] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            165 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 23] = [&[]; 23];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                }
                let argv = self.argv_cache.get(values[5]);
                values[17] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[18] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[19] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[20] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[21] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[22] = &exe_hash;
                self.pid_tree_cache
                    .insert(values[5].to_vec(), values[12].to_vec());
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            356 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 21] = [&[]; 21];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                let argv = self.argv_cache.get(values[5]);
                values[14] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[15] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[16] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[17] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[18] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[19] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[20] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            601 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 27] = [&[]; 27];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                if {
                    let mut flag = false;
                    for i in DNS_SUFFIX_WHITELIST {
                        flag = values[12].ends_with(i);
                        break;
                    }
                    flag
                } {
                    return Ok(0);
                }
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                }
                let argv = self.argv_cache.get(values[5]);
                values[20] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[21] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[22] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[23] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[24] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[25] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[26] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            602 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 28] = [&[]; 28];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                if !(values[1].starts_with(b"/bin/")
                    || values[1].starts_with(b"/sbin/")
                    || values[1].starts_with(b"/usr/bin/")
                    || values[1].starts_with(b"/usr/sbin/")
                    || values[1] == b"-1"
                    || values[1] == b"-2"
                    || values[1] == b"")
                {
                    if let Some(value) = self.exe_filter.get_mut(values[1]) {
                        if *value > EXE_FILTER_QUOTA {
                            kmod.add_filtered_exe(values[1]);
                            *value = 1;
                        }
                        *value += 1;
                    } else {
                        self.exe_filter
                            .insert(values[1].to_vec(), 1, EXE_FILTER_WINDOW);
                    };
                }
                let argv = self.argv_cache.get(values[5]);
                if argv != b"-3" {
                    if let Some(counter) = self.argv_dyn_filter.get_mut(&argv) {
                        if *counter > ARGV_DYN_FILTER_QUOTA {
                            return Ok(0);
                        } else {
                            *counter += 1;
                        }
                    } else {
                        self.argv_dyn_filter
                            .insert(argv.to_vec(), 0, ARGV_DYN_FILTER_WINDOW);
                    }
                }
                values[20] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[21] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[22] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[23] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[24] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[25] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[26] = &pid_tree;
                let socket_argv = self.argv_cache.get(values[18]);
                values[27] = &socket_argv;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            603 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 21] = [&[]; 21];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                let argv = self.argv_cache.get(values[5]);
                values[15] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[16] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[17] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[18] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[19] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[20] = &exe_hash;
                self.pid_tree_cache
                    .insert(values[5].to_vec(), values[13].to_vec());
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            604 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 22] = [&[]; 22];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                let argv = self.argv_cache.get(values[5]);
                values[15] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[16] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[17] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[18] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[19] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[20] = &exe_hash;
                self.pid_tree_cache
                    .insert(values[5].to_vec(), values[12].to_vec());
                let old_username = self.user_cache.get(values[13]);
                values[21] = &old_username;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            607 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 3] = [&[]; 3];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            608 | 609 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 22] = [&[]; 22];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                let argv = self.argv_cache.get(values[5]);
                values[14] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[15] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[16] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[17] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[18] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[19] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[20] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            610 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 23] = [&[]; 23];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                let argv = self.argv_cache.get(values[5]);
                values[16] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[17] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[18] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[19] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[20] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[21] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[22] = &pid_tree;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            611 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 24] = [&[]; 24];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                let argv = self.argv_cache.get(values[5]);
                values[16] = &argv;
                let ppid_argv = self.argv_cache.get(values[3]);
                values[17] = &ppid_argv;
                let pgid_argv = self.argv_cache.get(values[4]);
                values[18] = &pgid_argv;
                let username = self.user_cache.get(values[0]);
                values[19] = &username;
                let pod_name = if values[10] != values[11] {
                    self.ns_cache.get(values[10], values[6])
                } else {
                    b"-3".to_vec()
                };
                values[20] = &pod_name;
                let exe_hash = self.hash_cache.get(values[1]);
                values[21] = &exe_hash;
                let pid_tree = self
                    .pid_tree_cache
                    .get_mut(values[5])
                    .map(|v| v.clone())
                    .unwrap_or(b"-3".to_vec());
                values[22] = &pid_tree;
                let dpid_argv = self.argv_cache.get(values[12]);
                values[23] = &dpid_argv;
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            700 | 702 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 1] = [&[]; 1];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            701 | 703 => {
                let keys = schema::SCHEMA.get(&data_type).unwrap();
                let mut values: [&[u8]; 2] = [&[]; 2];
                let mut index = 0;
                let mut base_index = 0;
                for i in 0..data.len() {
                    if data[i] == 0x1e {
                        values[index] = &data[base_index..i];
                        index += 1;
                        base_index = i + 1;
                    }
                }
                values[index] = &data[base_index..];
                encode(timestamp, keys, &values, dst, data_type as u64)
            }
            dt => Err(anyhow!("unknown data type: {:?}", dt)),
        }
    }
}
