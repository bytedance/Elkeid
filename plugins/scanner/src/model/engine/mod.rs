pub mod clamav;

use anyhow::{anyhow, Result};
use clamav::Clamav;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/*
    General DBManager
*/
trait DBManager {
    fn new(version: &str, sha256: &str, passwd: &str, urls: &[&str]);
    fn load_db(&mut self, db_path: &str);
    fn update(&mut self);
}

/*
    General Scan Enine
*/
pub trait ScanEngine {
    fn new(db_path: &str) -> Result<Self>
    where
        Self: Sized;
    fn scan_file(&mut self, fpath: &str) -> Result<(String, Option<Vec<String>>)>;
    fn scan_mem(&mut self, fname: &str, buf: &[u8]) -> Result<String>;
}

pub struct Scanner {
    engine_clamav: Option<Clamav>,
}
