use anyhow::Result as AnyhowResult;
use config::{Config, File};
use lazy_static;
use log::debug;

lazy_static::lazy_static!(
    pub static ref SETTINGS: Config = load_config("settings").unwrap();
);


pub fn load_config(path: &'static str) -> AnyhowResult<Config> {
    let mut settings = Config::default();
    settings.merge(File::with_name(path))?;
    // println!("{:?}", settings);
    Ok(settings)
}

#[inline]
pub fn settings_string(table: &'static str, key: &'static str) -> AnyhowResult<String> {
    debug!("load settings: [{}] {}", table, key);
    let service = SETTINGS.get_table(table)?;
    let value = service.get(key);
    if value.is_none() {
	return Err(anyhow::anyhow!("missing key `{}` in `[{}]`", key, table));
    }
    let value: String = value.unwrap().to_string();
    Ok(value)
}

#[inline]
pub fn settings_vec_string(table: &'static str, key: &'static str) -> AnyhowResult<Vec<String>> {
    debug!("load settings: [{}] {}", table, key);
    let service = SETTINGS.get_table(table)?;
    let values = service.get(key);
    if values.is_none() {
	return Err(anyhow::anyhow!("missing key `{}` in `[{}]`", key, table));
    }
    let mut v = Vec::new();
    for value in values.unwrap().clone().into_array()? {
	v.push(value.into_str()?);
    }
    Ok(v)
}

#[inline]
pub fn settings_bool(table: &'static str, key: &'static str) -> AnyhowResult<bool> {
    debug!("load settings: [{}] {}", table, key);
    let service = SETTINGS.get_table(table)?;
    let value = service.get(key);
    if value.is_none() {
	return Err(anyhow::anyhow!("missing key `{}` in `[{}]`", key, table));
    }
    let value: bool = value.unwrap().clone().into_bool()?;
    Ok(value)
}
#[inline]
pub fn settings_int(table: &'static str, key: &'static str) -> AnyhowResult<i64> {
    debug!("load settings: [{}] {}", table, key);
    let service = SETTINGS.get_table(table)?;
    let value = service.get(key);
    if value.is_none() {
	return Err(anyhow::anyhow!("missing key `{}` in `[{}]`", key, table));
    }
    let value: i64 = value.unwrap().clone().into_int()?;
    Ok(value)
}
