use std::{
    fs::{read, File},
    hash::Hasher,
    intrinsics::copy,
    io::{ErrorKind, Read},
    num::NonZeroU32,
    str,
};

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use hex::encode;
use lru_cache::LruCache;
use twox_hash::XxHash64;
pub struct NsCache {
    cache: LruCache<Vec<u8>, Vec<u8>>,
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}
impl NsCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: LruCache::new(cap),
            limiter: RateLimiter::direct(Quota::per_second(NonZeroU32::new(25).unwrap())),
        }
    }
    pub fn get(&mut self, pns: &[u8], pid: &[u8]) -> Vec<u8> {
        let pid = match str::from_utf8(pid).unwrap_or_default().parse::<usize>() {
            Ok(pid) => pid,
            Err(_) => {
                return b"-3".to_vec();
            }
        };
        return match self.cache.get_mut(pns) {
            Some(v) => v.to_owned(),
            None => {
                let pod_name = if self.limiter.check().is_ok() {
                    if let Ok(v) = read(format!("/proc/{}/environ", pid)) {
                        let envs = v.split(|c| *c == b'\0').map(|s| s.split(|c| *c == b'='));
                        let mut pod_name = Vec::new();
                        for mut env in envs {
                            if let Some(env_name) = env.next() {
                                if let Some(env_value) = env.next() {
                                    match env_name {
                                        b"MY_POD_NAME" | b"POD_NAME" => {
                                            pod_name.extend_from_slice(env_value);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            if pod_name.len() != 0 {
                                break;
                            }
                        }
                        if pod_name.len() == 0 {
                            return pod_name;
                        }
                        pod_name
                    } else {
                        return b"-3".to_vec();
                    }
                } else {
                    return b"-4".to_vec();
                };
                self.put(pns.to_vec(), pod_name.clone());
                pod_name
            }
        };
    }
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.cache.insert(key, value);
    }
}
pub struct ArgvCache {
    cache: LruCache<Vec<u8>, Vec<u8>>,
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}
impl ArgvCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: LruCache::new(cap),
            limiter: RateLimiter::direct(Quota::per_second(NonZeroU32::new(25).unwrap())),
        }
    }
    pub fn get(&mut self, pid: &[u8]) -> Vec<u8> {
        let pidnum = match str::from_utf8(pid).unwrap_or_default().parse::<usize>() {
            Ok(pid) => pid,
            Err(_) => {
                return b"-3".to_vec();
            }
        };
        return match self.cache.get_mut(pid) {
            Some(v) => v.to_owned(),
            None => {
                let cmdline = if self.limiter.check().is_ok() {
                    if let Ok(mut v) = read(format!("/proc/{}/cmdline", pidnum)) {
                        if v.len() > 256 {
                            v.truncate(256);
                        }
                        for v in v.iter_mut() {
                            if *v == b'\0' {
                                *v = b' ';
                            }
                        }
                        let offset = v
                            .iter()
                            .rposition(|x| !x.is_ascii_whitespace())
                            .unwrap_or_default();
                        v.truncate(offset + 1);
                        v
                    } else {
                        return b"-3".to_vec();
                    }
                } else {
                    return b"-4".to_vec();
                };
                self.put(pid.to_vec(), cmdline.clone());
                cmdline
            }
        };
    }
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.cache.insert(key, value);
    }
}
pub struct HashCache {
    cache: LruCache<Vec<u8>, Vec<u8>>,
    buffer: Vec<u8>,
}
impl HashCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: LruCache::new(cap),
            buffer: Vec::with_capacity(32 * 1024),
        }
    }
    pub fn get(&mut self, exe: &[u8]) -> Vec<u8> {
        if exe.len() > 1024 {
            return b"-3".to_vec();
        }
        let mut hasher = XxHash64::default();
        return match self.cache.get_mut(exe) {
            Some(v) => v.to_owned(),
            None => {
                if let Ok(path) = str::from_utf8(exe) {
                    if let Ok(file) = File::open(path) {
                        if let Ok(metadata) = file.metadata() {
                            hasher.write_u64(metadata.len());
                            self.buffer.clear();
                            if let Err(err) = file.take(32 * 1024).read_to_end(&mut self.buffer) {
                                if err.kind() != ErrorKind::UnexpectedEof {
                                    return b"-3".to_vec();
                                }
                            }
                            hasher.write(&self.buffer);
                            let hash = encode(hasher.finish().to_be_bytes()).into_bytes();
                            self.put(exe.to_vec(), hash.clone());
                            hash
                        } else {
                            return b"-3".to_vec();
                        }
                    } else {
                        return b"-3".to_vec();
                    }
                } else {
                    return b"-3".to_vec();
                }
            }
        };
    }
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.cache.insert(key, value);
    }
}
pub struct UserCache {
    cache: LruCache<Vec<u8>, Vec<u8>>,
}
impl UserCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: LruCache::new(cap),
        }
    }
    pub fn get(&mut self, uid_s: &[u8]) -> Vec<u8> {
        return match self.cache.get_mut(uid_s) {
            Some(v) => v.to_owned(),
            None => {
                if let Ok(uid) = str::from_utf8(uid_s).unwrap_or_default().parse::<u32>() {
                    unsafe {
                        let rt = libc::getpwuid(uid);
                        if !rt.is_null() {
                            let mut v = vec![0; libc::strlen((*rt).pw_name)];
                            copy(
                                (*rt).pw_name,
                                v.as_mut_ptr() as *mut i8,
                                libc::strlen((*rt).pw_name),
                            );
                            self.put(uid_s.to_vec(), v.clone());
                            v
                        } else {
                            b"-3".to_vec()
                        }
                    }
                } else {
                    b"-3".to_vec()
                }
            }
        };
    }
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.cache.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use libc;
    use std::{ffi::CString, intrinsics::copy};

    use super::ArgvCache;
    #[test]
    fn test_getpwuid() {
        unsafe {
            let rt = libc::getpwuid(0);
            if !rt.is_null() {
                println!("{:?}", CString::from_raw((*rt).pw_name));
            }
        }
    }
    #[test]
    fn test_loop_getpwuid() {
        unsafe {
            for i in 0..10 {
                let rt = libc::getpwuid(i);
                if !rt.is_null() {
                    let mut buf = Vec::<u8>::with_capacity(libc::strlen((*rt).pw_name));
                    copy(
                        (*rt).pw_name,
                        buf.as_mut_ptr() as *mut i8,
                        libc::strlen((*rt).pw_name),
                    );
                    buf.set_len(libc::strlen((*rt).pw_name));
                    println!("{:?}", CString::from_vec_unchecked(buf));
                }
            }
        }
    }
    #[test]
    fn test_get_argv() {
        let mut cache = ArgvCache::new(10);
        let res = String::from_utf8(cache.get(b"1907813")).unwrap();
        println!("{} {}", res, res.len());
    }
}
