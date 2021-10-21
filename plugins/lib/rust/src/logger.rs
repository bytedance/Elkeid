use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs::{create_dir_all, read_dir, remove_file, rename, File, OpenOptions},
    io::{BufReader, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process,
    sync::{Mutex, MutexGuard},
    thread::spawn,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Local};
use crossbeam::channel::{bounded, Sender};
use flate2::{bufread::GzEncoder, Compression};
use log::{set_max_level, LevelFilter, Log};

use crate::{Client, Payload, Record};
trait OsStrExt {
    fn starts_with(&self, pat: &Self) -> bool;
}
impl OsStrExt for OsStr {
    fn starts_with(&self, pat: &Self) -> bool {
        if let Some((p1, p2)) = self.to_str().zip(pat.to_str()) {
            p1.starts_with(p2)
        } else {
            false
        }
    }
}
pub struct Config {
    pub max_size: u64,
    pub path: PathBuf,
    pub file_level: LevelFilter,
    pub remote_level: LevelFilter,
    pub max_backups: usize,
    pub compress: bool,
    pub client: Option<Client>,
}
pub struct Logger {
    max_size: u64,
    size: Mutex<u64>,
    dir: PathBuf,
    filename: OsString,
    file: Mutex<Option<File>>,
    file_level: LevelFilter,
    remote_level: LevelFilter,
    tx_mill: Sender<()>,
    client: Mutex<Option<Client>>,
}
impl Logger {
    pub fn new(config: Config) -> Self {
        let dir = config.path.parent().unwrap_or(Path::new("/tmp")).to_owned();
        let _ = create_dir_all(&dir);
        let filename = config
            .path
            .file_name()
            .unwrap_or(OsStr::new(&format!("{}.log", process::id())))
            .to_owned();
        let mut size = 0;
        let file = match OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(dir.join(&filename))
        {
            Ok(f) => {
                size = f.metadata().unwrap().len();
                Some(f)
            }
            Err(err) => {
                println!("create file failed: {}", err);
                None
            }
        };
        set_max_level(if config.remote_level > config.file_level {
            config.remote_level
        } else {
            config.file_level
        });
        let (tx_mill, rx_mill) = bounded::<()>(1);
        let max_backups = config.max_backups;
        let compress = config.compress;
        let dir_c = dir.clone();
        let filename_c = filename.clone();
        // cleanup & compress thread
        spawn(move || {
            for _ in rx_mill {
                if let Ok(dir) = read_dir(&dir_c) {
                    let mut files = Vec::new();
                    for file in dir {
                        if let Ok(file) = file {
                            if !file.file_name().starts_with(&filename_c) {
                                continue;
                            }
                            if let Some(n) = file.file_name().to_str() {
                                let to_parse = n[filename_c.len()..]
                                    .trim_start_matches("-")
                                    .trim_end_matches(".gz");
                                if let Ok(datetime) = DateTime::parse_from_rfc3339(to_parse) {
                                    files.push((file.path(), datetime))
                                }
                            }
                        }
                    }
                    files.sort_by(|a, b| a.1.cmp(&b.1));
                    if max_backups > 0 && files.len() > max_backups {
                        for (file, _) in &files[..files.len() - max_backups] {
                            let _ = remove_file(file);
                        }
                    }
                    if compress {
                        for (file, _) in &files[..] {
                            if file.extension().map_or(false, |ext| ext != "gz") {
                                if let Ok(f) = File::open(file) {
                                    let b = BufReader::new(f);
                                    let mut gz = GzEncoder::new(b, Compression::fast());
                                    let mut buffer = Vec::new();
                                    if gz.read_to_end(&mut buffer).is_ok() {
                                        let mut compressed_filepath = file.clone();
                                        let mut compressed_filename = compressed_filepath
                                            .file_name()
                                            .unwrap_or_default()
                                            .to_owned();
                                        compressed_filename.push(".gz");
                                        compressed_filepath.set_file_name(compressed_filename);
                                        if let Ok(mut wf) = File::create(compressed_filepath) {
                                            let _ = wf.write_all(&buffer);
                                            let _ = remove_file(file);
                                        };
                                    };
                                }
                            }
                        }
                    }
                }
            }
        });
        Self {
            max_size: config.max_size,
            size: Mutex::new(size),
            dir: dir.to_owned(),
            filename: filename.to_owned(),
            file: Mutex::new(file),
            file_level: config.file_level,
            remote_level: config.remote_level,
            tx_mill,
            client: Mutex::new(config.client),
        }
    }
    fn mill(&self) {
        let _ = self.tx_mill.try_send(());
    }
    fn rotate(&self, file: &mut MutexGuard<'_, Option<File>>, size: &mut MutexGuard<'_, u64>) {
        if !self.dir.exists() {
            let _ = create_dir_all(&self.dir);
        }
        let file_path = self.dir.join(&self.filename);
        if file.is_some() {
            let datetime: DateTime<Local> = SystemTime::now().into();
            let mut new_name = self.filename.clone();
            new_name.push("-");
            new_name.push(datetime.to_rfc3339());
            if let Err(_) = rename(&file_path, self.dir.join(new_name)) {
                **file = None;
            } else {
                match OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .mode(0o600)
                    .open(&file_path)
                {
                    Ok(f) => {
                        **file = Some(f);
                    }
                    Err(_) => {
                        **file = None;
                    }
                };
            }
        }
        **size = 0;
        self.mill();
    }
}
impl Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level()
            <= if self.file_level < self.remote_level {
                self.file_level
            } else {
                self.remote_level
            }
    }
    fn log(&self, record: &log::Record<'_>) {
        let current = SystemTime::now();
        if record.level() <= self.file_level {
            let mut file = self.file.lock().unwrap();
            let mut size = self.size.lock().unwrap();
            let datetime: DateTime<Local> = current.into();
            let mut buf = Vec::new();
            let _ = writeln!(
                buf,
                "{}\t{}\t{}\t{}:{}\t{}",
                datetime.format("%+"),
                record.level().as_str(),
                record.target(),
                record
                    .file()
                    .or(record.file_static())
                    .unwrap_or_default()
                    .to_owned(),
                record.line().unwrap_or_default(),
                record.args()
            );
            if buf.len() as u64 + *size > self.max_size {
                self.rotate(&mut file, &mut size);
            }
            if let Some(ref mut file) = *file {
                let _ = file.write_all(&buf);
                *size += buf.len() as u64;
            }
        }
        if let Some(client) = self.client.lock().unwrap().as_mut() {
            if record.level() <= self.remote_level {
                let mut fields = HashMap::with_capacity(6);
                fields.insert("level".to_owned(), record.level().as_str().to_owned());
                fields.insert("target".to_owned(), record.target().to_owned());
                fields.insert(
                    "file".to_owned(),
                    record
                        .file()
                        .or(record.file_static())
                        .unwrap_or_default()
                        .to_owned(),
                );
                fields.insert(
                    "line".to_owned(),
                    record.line().unwrap_or_default().to_string(),
                );
                fields.insert("msg".to_owned(), record.args().to_string());
                let mut rec = Record::default();
                rec.set_data_type(1010);
                rec.set_timestamp(current.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64);
                let mut pld = Payload::default();
                pld.set_fields(fields);
                rec.set_data(pld);
                let _ = client.send_record(&rec);
            }
        }
    }
    fn flush(&self) {
        let mut file = self.file.lock().unwrap();
        if let Some(ref mut file) = *file {
            let _ = file.flush();
        }
    }
}
