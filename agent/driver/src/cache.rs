use clru::CLruCache;
use fnv::FnvBuildHasher;
use hex::encode;
use std::fs::read_to_string;
use std::fs::File;
use std::hash::Hasher;
use std::io::{Error, Read};
use twox_hash::{RandomXxh3HashBuilder64, XxHash64};

const XXHASH_BUFF_SIZE: usize = 32 * 1024;

pub struct ArgvCache {
    i: CLruCache<u32, String, FnvBuildHasher>,
}

impl ArgvCache {
    pub fn new(cap: usize) -> Self {
        Self {
            i: CLruCache::<_, _, FnvBuildHasher>::with_hasher(cap, FnvBuildHasher::default()),
        }
    }

    pub fn get(&mut self, key: &u32) -> String {
        return match self.i.get(key) {
            Some(v) => v.to_owned(),
            None => {
                if let Ok(v) = read_to_string(format!("/proc/{}/cmdline", key)) {
                    let normalized = v.replace('\0', " ");
                    self.i.put(*key, normalized.clone());
                    normalized
                } else {
                    "-3".to_owned()
                }
            }
        };
    }

    pub fn put(&mut self, key: u32, value: String) {
        self.i.put(key, value);
    }
}

pub struct FileHashCache {
    i: CLruCache<String, String, RandomXxh3HashBuilder64>,
}

impl FileHashCache {
    pub fn new(cap: usize) -> Self {
        Self {
            i: CLruCache::<_, _, RandomXxh3HashBuilder64>::with_hasher(
                cap,
                Default::default(),
            ),
        }
    }

    pub fn get<T: AsRef<str>>(&mut self, key: T) -> String {
        match self.i.get(key.as_ref()) {
            Some(h) => h.to_owned(),
            None => {
                let mut buffer = [0; XXHASH_BUFF_SIZE];

                File::open(key.as_ref())
                    .map(|mut f| (f.metadata(), f.read(&mut buffer[..])))
                    .and_then(|stat| match stat {
                        (Ok(l), Ok(_)) => Ok(l.len()),
                        (_, _) => Err(Error::last_os_error()),
                    })
                    .map(|len| {
                        let mut hasher = XxHash64::default();
                        hasher.write(&buffer[..XXHASH_BUFF_SIZE]);
                        hasher.write(&len.to_be_bytes());
                        let hash = encode(hasher.finish().to_be_bytes());
                        self.i.put(key.as_ref().to_owned(), hash.to_owned());
                        hash
                    })
                    .unwrap_or_else(|_| "-3".to_string())
            }
        }
    }
}
