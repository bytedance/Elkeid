use crate::config::*;
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
pub fn download<P: AsRef<Path>>(src: P, dst: P) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut err = anyhow!("unavailable url");
    for host in DOWNLOAD_HOSTS {
        match ureq::get(&format!("{}{}", host, src.as_ref().display()))
            .call()
            .and_then(|content| {
                ureq::get(&format!(
                    "{}{}",
                    host,
                    src.as_ref().with_extension("sign").display()
                ))
                .call()
                .map(|sign_content| (content, sign_content))
            }) {
            Ok((resp, sign_resp)) => {
                let mut bytes: Vec<u8>;
                if let Some(len) = resp
                    .header("Content-Length")
                    .and_then(|l| l.parse::<usize>().ok())
                {
                    bytes = Vec::with_capacity(len);
                } else {
                    bytes = Vec::new();
                }
                let _ = resp.into_reader().read_to_end(&mut bytes);
                hasher.update(&bytes);
                let res = hasher.finalize_reset();
                let sign = hex::decode(sign_resp.into_string().unwrap().trim()).unwrap_or_default();
                if res.as_slice().eq(&sign) {
                    let mut file = File::create(dst.as_ref())?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    return Ok(());
                } else {
                    err = anyhow!("checksum doesn't match");
                }
            }
            Err(e) => {
                err = e.into();
            }
        }
    }
    Err(err)
}
