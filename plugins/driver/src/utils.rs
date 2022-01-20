use crate::config::*;
use anyhow::{anyhow, Result};
use reqwest::blocking;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, path::Path};
pub fn download<P: AsRef<Path>>(src: P, dst: P) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut err = anyhow!("unavailable url");
    for host in DOWNLOAD_HOSTS {
        match blocking::get(format!("{}{}", host, src.as_ref().display())).and_then(|content| {
            blocking::get(format!(
                "{}{}",
                host,
                src.as_ref().with_extension("sign").display()
            ))
            .map(|sign_content| (content, sign_content))
        }) {
            Ok((content, sign_content)) => {
                if content.status().is_success() && sign_content.status().is_success() {
                    match content.bytes().and_then(|contents| {
                        sign_content
                            .text()
                            .map(|sign_content| (contents, sign_content))
                    }) {
                        Ok((contents, sign_content)) => {
                            hasher.update(&contents);
                            let res = hasher.finalize_reset();
                            let sign_contents =
                                hex::decode(sign_content.trim()).unwrap_or_default();
                            if res.as_slice().eq(&sign_contents) {
                                let mut file = File::create(dst.as_ref())?;
                                file.write_all(&contents)?;
                                file.sync_all()?;
                                return Ok(());
                            } else {
                                err = anyhow!("checksum doesn't match");
                            }
                        }
                        Err(e) => {
                            err = e.into();
                        }
                    };
                } else {
                    err = content.error_for_status().unwrap_err().into();
                }
            }
            Err(e) => {
                err = e.into();
            }
        }
    }
    Err(err)
}
