use anyhow::{anyhow, Result};
use libsystemd_sys::journal::{
    sd_journal, sd_journal_add_match, sd_journal_close, sd_journal_get_data, sd_journal_next,
    sd_journal_open, sd_journal_wait, SD_JOURNAL_SYSTEM,
};
use log::error;
use serde::Serialize;
use std::cmp::Ordering;
use std::ffi::CString;
use std::io::Error;
use std::mem::MaybeUninit;

#[derive(Serialize, Debug)]
struct SshEvent {
    data_type: String,
    timestamp: String,
    status: String,
    types: String,
    invalid: String,
    user: String,
    sip: String,
    sport: String,
    rawlog: String,
}

#[derive(Serialize, Debug)]
struct Krb5Event {
    data_type: String,
    timestamp: String,
    authorized: String,
    principal: String,
    rawlog: String,
}

pub struct JournalWatcher {
    journal_context: *mut sd_journal,
    sender: plugin::Sender,
}

impl Drop for JournalWatcher {
    fn drop(&mut self) {
        if !self.journal_context.is_null() {
            let _ = unsafe { sd_journal_close(self.journal_context) };
            self.sender.close();
        }
    }
}

impl JournalWatcher {
    pub fn new(sender: plugin::Sender) -> Result<Self> {
        let mut p = MaybeUninit::uninit();
        let r = unsafe { sd_journal_open(p.as_mut_ptr(), SD_JOURNAL_SYSTEM) };
        if r != 0 {
            return Err(anyhow!(Error::last_os_error()));
        }
        let journal_context = unsafe { p.assume_init() };
        let inf_cstr = CString::new("_SYSTEMD_UNIT=ssh.service")?;
        let r = unsafe { sd_journal_add_match(journal_context, inf_cstr.as_ptr() as _, 0) };
        if r != 0 {
            Err(anyhow!(Error::last_os_error()))
        } else {
            Ok(Self {
                journal_context,
                sender,
            })
        }
    }

    pub fn parse(&mut self) -> Result<()> {

        let r = unsafe { sd_journal_next(self.journal_context) };

        match r.cmp(&0) {
            Ordering::Less => Err(anyhow!(Error::last_os_error())), // 没有
            Ordering::Equal => {

                let r = unsafe { sd_journal_wait(self.journal_context, 1_000_000) };
                if r < 0 {
                    Err(anyhow!(Error::last_os_error()))

                } else {
                    Ok(())
                }
            }
            Ordering::Greater => {

                let message = self.get_field("MESSAGE")?;
                let mut timestamp = self.get_field("_SOURCE_REALTIME_TIMESTAMP")?;
                timestamp.truncate(10);
                let fields: Vec<&str> = message.split_whitespace().collect();
                if fields.len() < 4 {
                    error!("Unexpected len. Raw message: {}", message);
                    return Ok(());
                }
                match fields[0] {
                    "Authorized" => {
                        if fields.len() < 6 {
                            error!("Unexpected len. Raw message: {}", message);
                            return Ok(());
                        }
                        self.sender.send(&Krb5Event {
                            timestamp,
                            data_type: "4001".to_owned(),
                            authorized: fields[2].replace(",", ""),
                            principal: fields[5].to_string(),
                            rawlog: message,
                        })
                    }
                    "Accepted" => {
                        if fields.len() < 8 {
                            error!("Parse len is unexpected,raw message: {}", message);
                            return Ok(());
                        }
                        self.sender.send(&SshEvent {
                            timestamp,
                            data_type: "4000".to_owned(),
                            status: "true".to_string(),
                            types: fields[1].to_string(),
                            invalid: "false".to_string(),
                            user: fields[3].to_string(),
                            sip: fields[5].to_string(),
                            sport: fields[7].to_string(),
                            rawlog: message,
                        })
                    }
                    "Failed" => match fields[3] {
                        "invalid" => {
                            if fields.len() < 10 {
                                error!("Parse len is unexpected,raw message: {}", message);
                                return Ok(());
                            }
                            self.sender.send(&SshEvent {
                                timestamp,
                                data_type: "4000".to_owned(),
                                status: "false".to_owned(),
                                types: fields[1].to_string(),
                                invalid: "true".to_owned(),
                                user: fields[5].to_string(),
                                sip: fields[7].to_string(),
                                sport: fields[9].to_string(),
                                rawlog: message,
                            })
                        }
                        _ => {
                            if fields.len() < 8 {
                                error!("Unexpected len. Raw message: {}", message);
                                return Ok(());
                            }
                            self.sender.send(&SshEvent {
                                timestamp,
                                data_type: "4000".to_owned(),
                                status: "false".to_owned(),
                                types: fields[1].to_string(),
                                invalid: "false".to_owned(),
                                user: fields[3].to_string(),
                                sip: fields[5].to_string(),
                                sport: fields[7].to_string(),
                                rawlog: message,
                            })
                        }
                    },
                    _ => Ok(()),
                }
            }
        }
    }

    fn get_field(&self, field: &str) -> Result<String> {
        let mut d = MaybeUninit::uninit();
        let mut l = MaybeUninit::uninit();
        let field_c = CString::new(field)?;
        let r = unsafe {
            sd_journal_get_data(
                self.journal_context,
                field_c.as_ptr(),
                d.as_mut_ptr(),
                l.as_mut_ptr(),
            )
        };
        if r != 0 {
            return Err(anyhow!(Error::last_os_error()));
        }
        let s = unsafe { std::slice::from_raw_parts(d.assume_init(), l.assume_init()) };
        Ok(std::str::from_utf8(s)?
            .to_string()
            .splitn(2, '=')
            .last()
            .unwrap_or_default()
            .to_owned())
    }
}
