use std::{
    fs::{read, File},
    hash::Hasher,
    intrinsics::copy,
    io::Read,
    str,
};

use hex::encode;
use lru_cache::LruCache;
use twox_hash::XxHash64;
pub struct NsCache {
    cache: LruCache<Vec<u8>, Vec<u8>>,
}
impl NsCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: LruCache::new(cap),
        }
    }
    pub fn get(&mut self, pns: &[u8], pid: &[u8]) -> Vec<u8> {
        return match self.cache.get_mut(pns) {
            Some(v) => v.to_owned(),
            None => {
                let pod_name = if let Ok(v) = read(format!(
                    "/proc/{}/environ",
                    str::from_utf8(pid).unwrap_or_default()
                )) {
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
                    pod_name
                } else {
                    b"-3".to_vec()
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
}
impl ArgvCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: LruCache::new(cap),
        }
    }
    pub fn get(&mut self, pid: &[u8]) -> Vec<u8> {
        return match self.cache.get_mut(pid) {
            Some(v) => v.to_owned(),
            None => {
                let cmdline = if let Ok(mut v) = read(format!(
                    "/proc/{}/cmdline",
                    str::from_utf8(pid).unwrap_or_default()
                )) {
                    if v.len() > 256 {
                        v.truncate(256);
                    }
                    for v in v.iter_mut() {
                        if v == &b'\0' {
                            *v = b' ';
                        }
                    }
                    let mut last = v.len();
                    for (i, v) in v.iter_mut().rev().enumerate() {
                        if !v.is_ascii_whitespace() {
                            last = i;
                        }
                    }
                    v.truncate(last);
                    v
                } else {
                    b"-3".to_vec()
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
    buffer: [u8; 32 * 1024],
    hasher: XxHash64,
}
impl HashCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: LruCache::new(cap),
            buffer: [0; 32 * 1024],
            hasher: XxHash64::default(),
        }
    }
    pub fn get(&mut self, exe: &[u8]) -> Vec<u8> {
        let mut path = exe.to_vec();
        if path.len() > 256 {
            path.truncate(256);
        }
        return match self.cache.get_mut(&path) {
            Some(v) => v.to_owned(),
            None => {
                let hash =
                    if let Ok(mut file) = File::open(str::from_utf8(&path).unwrap_or_default()) {
                        let _ = file.read_exact(&mut self.buffer[..]);
                        self.hasher.write(&mut self.buffer[..]);
                        let v = encode(self.hasher.finish().to_be_bytes()).into_bytes();
                        v
                    } else {
                        b"-3".to_vec()
                    };
                self.put(path, hash.clone());
                hash
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
}
