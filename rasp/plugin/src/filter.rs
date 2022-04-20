use crate::config::{settings_bool, settings_vec_string};
use anyhow::Result as Anyhow;

#[derive(Debug)]
pub struct Filters {
    pub ignore_exe_path: Vec<String>,
    pub ignore_exe_name: Vec<String>,
    pub collect_env: Vec<String>,
    pub collect_all_env: bool,
    pub auto_attach_runtime: Vec<String>,
}

pub fn load_local_filter() -> Anyhow<Filters> {
    Ok(Filters {
        ignore_exe_path: settings_vec_string("filter", "ignore_exe_path")?,
        ignore_exe_name: settings_vec_string("filter", "ignore_exe_name")?,
        collect_env: settings_vec_string("filter", "collect_env")?,
        collect_all_env: settings_bool("filter", "collect_all_env")?,
        auto_attach_runtime: settings_vec_string("filter", "auto_attach_runtime")?,
    })
}
