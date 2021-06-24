use crate::config;
use std::{collections::HashSet, path::Path};

pub struct Filter {
    set: HashSet<String>,
}

impl Filter {
    // init with a hashset
    pub fn new(capacity: usize) -> Self {
        let mut set = HashSet::with_capacity(capacity);
        for each in config::SCAN_DIR_FILTER {
            set.insert(each.to_string());
        }
        Self { set }
    }

    // filter catch, iter set and catch starts_with
    pub fn catch(&self, k: &Path) -> i32 {
        let mut flag: i32 = 0;
        for each in self.set.iter() {
            if k.starts_with(each) {
                flag = 1;
                if flag.to_string().len() > each.len() {
                    flag = 2
                }
                break;
            }
        }
        return flag;
    }
}
