use anyhow::Result;
use serde::{Deserialize, Serialize};

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
#[derive(Deserialize)]
pub struct Record {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime_timestamp: String,
    #[serde(rename = "MESSAGE")]
    message: String,
}
pub struct JournalWatcher {
    sender: plugin::Sender,
}

impl JournalWatcher {
    pub fn new(sender: plugin::Sender) -> Self {
        Self { sender }
    }

    pub fn parse(&mut self, mut r: Record) -> Result<()> {
        r.realtime_timestamp.truncate(10);
        let fields: Vec<&str> = r.message.split_whitespace().collect();
        if fields.len() < 4 {
            return Ok(());
        }
        match fields[0] {
            "Authorized" => {
                if fields.len() < 6 {
                    return Ok(());
                }
                self.sender.send(&Krb5Event {
                    timestamp: r.realtime_timestamp,
                    data_type: "4001".to_owned(),
                    authorized: fields[2].replace(",", ""),
                    principal: fields[5].to_string(),
                    rawlog: r.message,
                })
            }
            "Accepted" => {
                if fields.len() < 8 {
                    return Ok(());
                }
                self.sender.send(&SshEvent {
                    timestamp: r.realtime_timestamp,
                    data_type: "4000".to_owned(),
                    status: "true".to_string(),
                    types: fields[1].to_string(),
                    invalid: "false".to_string(),
                    user: fields[3].to_string(),
                    sip: fields[5].to_string(),
                    sport: fields[7].to_string(),
                    rawlog: r.message,
                })
            }
            "Failed" => match fields[3] {
                "invalid" => {
                    if fields.len() < 10 {
                        return Ok(());
                    }
                    self.sender.send(&SshEvent {
                        timestamp: r.realtime_timestamp,
                        data_type: "4000".to_owned(),
                        status: "false".to_owned(),
                        types: fields[1].to_string(),
                        invalid: "true".to_owned(),
                        user: fields[5].to_string(),
                        sip: fields[7].to_string(),
                        sport: fields[9].to_string(),
                        rawlog: r.message,
                    })
                }
                _ => {
                    if fields.len() < 8 {
                        return Ok(());
                    }
                    self.sender.send(&SshEvent {
                        timestamp: r.realtime_timestamp,
                        data_type: "4000".to_owned(),
                        status: "false".to_owned(),
                        types: fields[1].to_string(),
                        invalid: "false".to_owned(),
                        user: fields[3].to_string(),
                        sip: fields[5].to_string(),
                        sport: fields[7].to_string(),
                        rawlog: r.message,
                    })
                }
            },
            _ => Ok(()),
        }
    }
}
