use crate::configs;
use std::{collections::HashSet, path::Path};

pub struct Filter {
    set: HashSet<String>,
}

impl Filter {
    // init with a hashset
    pub fn new(capacity: usize) -> Self {
        let mut set = HashSet::with_capacity(capacity);
        // add filter elkeid self
        if let Ok(self_exe_path) = std::env::current_dir() {
            if let Some(agent_path) = self_exe_path.parent() {
                set.insert(agent_path.to_string_lossy().to_string());
            }
        }
        // add filter from config
        for each in configs::SCAN_DIR_FILTER {
            set.insert(each.to_string());
        }
        Self { set }
    }

    // filter catch, iter set and catch starts_with
    pub fn catch(&self, k: &Path) -> i32 {
        let mut flag: i32 = 0;
        for each in self.set.iter() {
            let c = k.to_string_lossy().to_string();
            if c.starts_with(each) {
                flag = 1;
                let c1: Vec<&str> = c.split("/").into_iter().collect();
                let c2: Vec<&str> = each.split("/").into_iter().collect();
                if c1.len() > c2.len() {
                    flag = 2
                }
                return flag;
            }
        }
        return flag;
    }
}
