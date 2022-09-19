use std::str::FromStr;
use crate::config::{settings_bool, settings_vec_string};
use anyhow::Result as Anyhow;
use regex::Regex;

#[derive(Debug)]
pub struct Filters {
    pub ignore_exe_path: Vec<String>,
    pub ignore_exe_name: Vec<String>,
    pub ignore_argv_regex: Vec<Regex>,
    pub collect_env: Vec<String>,
    pub collect_all_env: bool,
    pub auto_attach_runtime: Vec<String>,
}

pub fn load_local_filter() -> Anyhow<Filters> {
    let ignore_argv_regex_strings = settings_vec_string("filter", "ignore_argv_regex")?;
    let mut ignore_argv_regex = Vec::new();
    for s in ignore_argv_regex_strings.iter() {
        ignore_argv_regex.push(Regex::from_str(s.as_str())?);
    }
    Ok(Filters {
        ignore_exe_path: settings_vec_string("filter", "ignore_exe_path")?,
        ignore_exe_name: settings_vec_string("filter", "ignore_exe_name")?,
        ignore_argv_regex,
        collect_env: settings_vec_string("filter", "collect_env")?,
        collect_all_env: settings_bool("filter", "collect_all_env")?,
        auto_attach_runtime: settings_vec_string("filter", "auto_attach_runtime")?,
    })
}
