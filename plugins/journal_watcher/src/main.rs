use chrono::DateTime;
use log::*;
use parking_lot::Mutex;
use pest::Parser;
use pest_derive::Parser;
use plugins::{logger::*, Client, Record};
use serde::Deserialize;
use std::{
    env, fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[grammar = "sshd.pest"]
pub struct SSHDParser;
#[derive(Deserialize)]
pub struct Entry {
    #[serde(rename = "MESSAGE")]
    message: String,
    #[serde(rename = "_PID")]
    pid: String,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    timestamp: String,
}
enum LogFormat {
    Json,
    Log,
}
fn find_command<P>(exe_name: P) -> Option<PathBuf>
where
    P: AsRef<Path>,
{
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .filter_map(|dir| {
                let full_path = dir.join(&exe_name);
                if full_path.is_file() {
                    Some(full_path)
                } else {
                    None
                }
            })
            .next()
    })
}
fn main() {
    let mut client = Client::new(true);
    let logger = Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from("./journal_watcher.log"),
        file_level: LevelFilter::Info,
        remote_level: LevelFilter::Error,
        max_backups: 10,
        compress: true,
        client: Some(client.clone()),
    });
    set_boxed_logger(Box::new(logger)).unwrap();
    info!("journal_watcher startup");

    let journalctl: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let journalctl_c = journalctl.clone();
    let mut client_c = client.clone();
    let _ = thread::Builder::new()
        .name("send_record".to_owned())
        .spawn(move || loop {
            let mut cmd: Command;
            let format: LogFormat;
            if find_command("journalctl").is_some() {
                cmd = Command::new("journalctl");
                cmd.args(&["-f", "_COMM=sshd", "-o", "json"]);
                format = LogFormat::Json;
            } else if fs::metadata("/var/log/auth.log").is_ok() {
                cmd = Command::new("tail");
                cmd.args(&["-F", "/var/log/auth.log"]);
                format = LogFormat::Log;
            } else if fs::metadata("/var/log/secure").is_ok() {
                cmd = Command::new("tail");
                cmd.args(&["-F", "/var/log/secure"]);
                format = LogFormat::Log;
            } else {
                error!("no supported log source");
                return;
            }
            cmd.stdout(Stdio::piped());
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(err) => {
                    error!("spawn subprocess failed: {}", err);
                    return;
                }
            };
            let stdout = child.stdout.take().unwrap();
            {
                let mut journalctl = journalctl_c.lock();
                *journalctl = Some(child);
            }
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(err) => {
                        error!("when reading a line, an error occurred: {}", err);
                        break;
                    }
                };
                debug!("{}", line);
                let entry = match format {
                    LogFormat::Json => match serde_json::from_str::<Entry>(&line) {
                        Ok(mut entry) => {
                            // microsec -> sec
                            if entry.timestamp.len() > 6 {
                                entry.timestamp.truncate(entry.timestamp.len() - 6);
                            } else {
                                entry.timestamp = "0".into();
                            }
                            entry
                        }
                        Err(err) => {
                            warn!("when parsing a line, an error occurred: {}", err);
                            continue;
                        }
                    },
                    LogFormat::Log => {
                        let fields = line.split_whitespace().collect::<Vec<&str>>();
                        if fields.len() < 6 || !fields[4].starts_with("sshd[") {
                            continue;
                        }
                        if let Ok(date) = DateTime::parse_from_str(
                            format!("{} {} {}", fields[0], fields[1], fields[2]).as_str(),
                            "%b %e %T",
                        ) {
                            Entry {
                                pid: fields[4][4..].trim_end_matches("]").to_string(),
                                message: fields[5..].join(" "),
                                timestamp: date.timestamp().to_string(),
                            }
                        } else {
                            Entry {
                                pid: fields[4][4..].trim_end_matches("]").to_string(),
                                message: fields[5..].join(" "),
                                timestamp: "".into(),
                            }
                        }
                    }
                };
                let mut rec = if let Ok(mut event) = SSHDParser::parse(Rule::event, &entry.message)
                {
                    let event = event.next().unwrap().into_inner().next().unwrap();
                    match event.as_rule() {
                        Rule::login => {
                            let mut login = event.into_inner();
                            debug!("{}", login);
                            let mut rec = Record::new();
                            rec.set_data_type(4000);
                            let fields = rec.mut_data().mut_fields();
                            fields.insert(
                                "status".to_owned(),
                                match login.next().unwrap().as_str() {
                                    "Accepted" => "true",
                                    _ => "false",
                                }
                                .to_owned(),
                            );
                            fields.insert(
                                "types".to_owned(),
                                login.next().unwrap().as_str().to_owned(),
                            );
                            fields.insert(
                                "invalid".to_owned(),
                                match login.next().unwrap().as_str() {
                                    "invalid user" => "true",
                                    _ => "false",
                                }
                                .to_owned(),
                            );
                            fields.insert(
                                "user".to_owned(),
                                login.next().unwrap().as_str().to_owned(),
                            );
                            fields.insert(
                                "sip".to_owned(),
                                login.next().unwrap().as_str().to_owned(),
                            );
                            fields.insert(
                                "sport".to_owned(),
                                login.next().unwrap().as_str().to_owned(),
                            );
                            fields.insert(
                                "extra".to_owned(),
                                login.next().unwrap().as_str().to_owned(),
                            );
                            rec
                        }
                        Rule::certify => {
                            let mut certify = event.into_inner();
                            debug!("{}", certify);
                            let mut rec = Record::new();
                            rec.set_data_type(4001);
                            let fields = rec.mut_data().mut_fields();
                            fields.insert(
                                "authorized".to_owned(),
                                certify.next().unwrap().as_str().to_owned(),
                            );
                            fields.insert(
                                "principal".to_owned(),
                                certify.next().unwrap().as_str().to_owned(),
                            );
                            rec
                        }
                        _ => {
                            warn!("unknown event type: {}", event);
                            continue;
                        }
                    }
                } else {
                    continue;
                };
                if let Ok(timestamp) = entry.timestamp.parse::<i64>() {
                    rec.set_timestamp(timestamp);
                } else {
                    rec.set_timestamp(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64,
                    );
                }
                rec.mut_data()
                    .mut_fields()
                    .insert("pid".to_owned(), entry.pid);
                rec.mut_data()
                    .mut_fields()
                    .insert("rawlog".to_owned(), entry.message);
                if client_c.send_record(&rec).is_err() {
                    let mut journalctl = journalctl_c.lock();
                    if let Some(journalctl) = journalctl.as_mut() {
                        let _ = journalctl.kill();
                    }
                    *journalctl = None;
                    return;
                };
            }
            let mut journalctl = journalctl_c.lock();
            if let Some(journalctl) = journalctl.as_mut() {
                let _ = journalctl.kill();
                let res = journalctl.wait();
                match res {
                    Ok(res) => {
                        info!("journalctl has exited with code: {}", res);
                    }
                    Err(res) => {
                        error!("journalctl has exited with error: {}", res);
                    }
                }
            } else {
                info!("journalctl was none,exit now");
                return;
            }
            thread::sleep(Duration::from_secs(10));
        });
    thread::Builder::new()
        .name("task_receive".to_owned())
        .spawn(move || loop {
            match client.receive() {
                Ok(_) => {
                    // handle task
                }
                Err(e) => {
                    let mut journalctl = journalctl.lock();
                    if let Some(journalctl) = journalctl.as_mut() {
                        let _ = journalctl.kill();
                    }
                    *journalctl = None;
                    error!("when receiving task,an error occurred:{}", e);
                    return;
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
    info!("journal_watcher exited");
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_login() {
        SSHDParser::parse(
            Rule::login,
            "Accepted publickey for zhanglei.sec from 10.87.61.221 port 50998 ssh2: RSA SHA256:l9nMCPKgwkWtfRKH4INyvpU3e+PIXtdKsm3jrvXRuMo",
        )
        .unwrap();
        SSHDParser::parse(
            Rule::login,
            "Accepted gssapi-with-mic for zhanglei.sec from 10.2.222.166 port 57302 ssh2",
        )
        .unwrap();
        SSHDParser::parse(
            Rule::login,
            "Failed password for zhanglei.sec from 10.2.222.166 port 57294 ssh2",
        )
        .unwrap();
        SSHDParser::parse(
            Rule::login,
            "Failed none for  from 10.2.222.166 port 57294 ssh2",
        )
        .unwrap();
        SSHDParser::parse(
            Rule::login,
            "Failed password for invalid user zhanglei.sec from 10.2.222.166 port 57294 ssh2",
        )
        .unwrap();
    }
    #[test]
    fn parse_certify() {
        SSHDParser::parse(
            Rule::certify,
            "Authorized to zhanglei.sec, krb5 principal zhanglei.sec@BYTEDANCE.COM (krb5_kuserok)",
        )
        .unwrap();
        SSHDParser::parse(
            Rule::certify,
            "Authorized to tiger, krb5 principal zhanglei.sec@BYTEDANCE.COM (krb5_kuserok)",
        )
        .unwrap();
    }
}
