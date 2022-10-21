use anyhow::{anyhow, Result};
use log::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, path::Path};

pub const DB_URLS: &'static [&'static str] = &[
    "http://lf26-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817",
    "http://lf3-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817",
    "http://lf6-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817",
    "http://lf9-elkeid.bytetos.com/obj/elkeid-download/18249e0cbe7c6aca231f047cb31d753fa4604434fcb79f484ea477f6009303c3/archive_db_default_20220817",
];

pub const ARCHIVE_DB_PWD: &str = &"clamav_default_passwd";
pub const ARCHIVE_DB_HASH: &str =
    &"290c9a6db172d1f709e8840753568218d8d96c40dec444376fa524f88a5b2ff9";
pub const ARCHIVE_DB_VERSION: &str = &"20220817";

pub const ARCHIVE_DB_VERSION_FILE: &str = &"version";
pub const DB_PATH: &str = "./dat";
pub const TMP_PATH: &str = "./tmp";

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DBManager {
    pub version: String,
    pub dbname: String,
    pub url: Vec<String>,
    pub sha256: String,
    pub passwd: String,
}

impl DBManager {
    pub fn new(version: &str, sha256: &str, passwd: &str, urls: &[&str]) -> Result<Self> {
        if let Some(filename) = urls[0].split('/').last() {
            return Ok(DBManager {
                version: version.to_string(),
                sha256: sha256.to_string(),
                dbname: filename.to_string(),
                url: urls.iter().map(|url| url.to_string()).collect(),
                passwd: passwd.to_string(),
            });
        }
        return Err(anyhow!("db init error, plugin shutdown"));
    }

    pub fn load(&self) -> Result<()> {
        std::fs::remove_dir_all(DB_PATH);
        extract(
            &format!("{}/{}.zip", TMP_PATH, self.dbname),
            DB_PATH,
            &self.passwd,
        )?;
        let version: String =
            std::fs::read_to_string(format!("{}/{}", DB_PATH, ARCHIVE_DB_VERSION_FILE))?;
        if &version.trim() != &self.version {
            return Err(anyhow!(
                "version {} != {} mismatch",
                &version.trim(),
                &self.version,
            ));
        }
        let sha256sum = crate::get_file_sha256(&format!("{}/{}.zip", TMP_PATH, self.dbname));
        if &sha256sum != &self.sha256 {
            return Err(anyhow!(
                "sha256sum {} != {} mismatch",
                &sha256sum,
                &self.sha256
            ));
        }
        return Ok(());
    }

    pub fn load_into(&self, db_path: &str) -> Result<()> {
        std::fs::remove_dir_all(DB_PATH);
        extract(
            &format!("{}/{}.zip", TMP_PATH, self.dbname),
            db_path,
            &self.passwd,
        )?;
        let version: String =
            std::fs::read_to_string(format!("{}/{}", db_path, ARCHIVE_DB_VERSION_FILE))?;
        if &version.trim() != &self.version {
            return Err(anyhow!(
                "version {} != {} mismatch",
                &version.trim(),
                &self.version,
            ));
        }
        let sha256sum = crate::get_file_sha256(&format!("{}/{}.zip", TMP_PATH, self.dbname));
        if &sha256sum != &self.sha256 {
            return Err(anyhow!(
                "sha256sum {} != {} mismatch",
                &sha256sum,
                &self.sha256
            ));
        }
        return Ok(());
    }

    pub fn get(&self) -> Result<()> {
        if let Ok(_) = self.load() {
            return Ok(());
        }
        std::fs::remove_dir_all(TMP_PATH);
        download(TMP_PATH, &self.url.iter().map(|url| url as &str).collect())?;
        std::fs::remove_dir_all(DB_PATH);
        extract(
            &format!("{}/{}.zip", TMP_PATH, self.dbname),
            DB_PATH,
            &self.passwd,
        )?;
        return Ok(());
    }

    pub fn update(
        &mut self,
        version: &str,
        sha256sum: &str,
        passwd: &str,
        urls: &Vec<&str>,
    ) -> Result<()> {
        if version == self.version && sha256sum == self.sha256 {
            info!("db already updated! version={},hash={}", version, sha256sum);
            return Ok(());
        }
        std::fs::remove_dir_all(TMP_PATH);
        download(TMP_PATH, &urls.iter().map(|url| url as &str).collect())?;
        std::fs::remove_dir_all(DB_PATH);
        extract(
            &format!("{}/{}.zip", TMP_PATH, self.dbname),
            DB_PATH,
            &self.passwd,
        )?;
        self.url = urls.iter().map(|url| url.to_string()).collect();
        self.sha256 = sha256sum.to_string();
        self.version = version.to_string();
        self.passwd = passwd.to_string();
        return Ok(());
    }
}

fn download(dst: &str, urls: &Vec<&str>) -> Result<()> {
    if urls.len() == 0 {
        return Err(anyhow!("urls.len() == 0"));
    }
    let db_path = std::path::Path::new(dst);
    if !db_path.exists() {
        std::fs::create_dir_all(db_path)?;
    }
    let client_builder = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(300))
        // download total 300 second timeout
        .build()?;
    let mut np = db_path.to_path_buf();
    if let Some(filename) = urls[0].split('/').last() {
        np.push(&format!("{}.zip", filename));
    } else {
        return Err(anyhow!("urls[0] illegal {:?}", urls[0]));
    }

    let mut hasher = Sha256::new();
    for host in urls {
        info!("download {}.zip", host);
        match client_builder
            .get(format!("{}.zip", host))
            .send()
            .and_then(|db_response| {
                client_builder
                    .get(format!("{}.sign", host))
                    .send()
                    .map(|sign_response| (db_response, sign_response))
            }) {
            Ok((db_response, sign_response)) => {
                if db_response.status().is_success() && sign_response.status().is_success() {
                    if let Ok((db_response, sign_response)) =
                        db_response.bytes().and_then(|db_response| {
                            sign_response
                                .text()
                                .map(|sign_response| (db_response, sign_response))
                        })
                    {
                        hasher.update(&db_response);
                        let res = hasher.finalize_reset();
                        let sign_response = hex::decode(sign_response.trim()).unwrap_or_default();
                        if res.as_slice().eq(&sign_response) {
                            let mut file = File::create(&np)?;
                            file.write_all(&db_response)?;
                            file.sync_all()?;
                            return Ok(());
                        }
                    };
                }
            }
            Err(_) => {}
        }
    }
    Err(anyhow!("download failed"))
}

fn extract(src: &str, dst: &str, passwd: &str) -> Result<()> {
    let db_path = std::path::Path::new(src);
    if !db_path.exists() {
        return Err(anyhow!("Err db path not found"));
    }

    let file = std::fs::File::open(&db_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index_decrypt(i, passwd.as_bytes())??;
        let zfilename = match file.enclosed_name() {
            Some(path) => match path.file_name() {
                Some(fname) => fname.to_owned().to_string_lossy().to_string(),
                None => continue,
            },
            None => continue,
        };
        let outpath = Path::new(&format!("{}/{}", dst, zfilename)).to_owned();
        if let Some(p) = outpath.parent() {
            if !p.exists() {
                std::fs::create_dir_all(&p)?;
            }
        }
        let mut outfile = std::fs::File::create(&outpath)?;
        std::io::copy(&mut file, &mut outfile)?;
    }
    return Ok(());
}
