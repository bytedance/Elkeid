use std::{
    env,
    fs::File,
    io::{BufReader, BufWriter, Error, Read, Write},
    sync::Arc,
    thread,
    time::Duration,
};

use crossbeam::channel::{select, tick};
use log::debug;
use parking_lot::Mutex;
use protobuf::Message;

pub mod logger;

pub mod bridge;
pub use bridge::*;

pub mod sys;

#[derive(Clone)]
pub enum EncodeType {
    Protobuf,
    Json,
}
#[derive(Clone)]
pub struct Client {
    high_writer: Arc<Mutex<BufWriter<File>>>,
    writer: Arc<Mutex<BufWriter<File>>>,
    reader: Arc<Mutex<BufReader<File>>>,
}

impl Client {
    pub fn can_use_high() -> bool {
        match env::var("ELKEID_PLUGIN_HIGH_PRIORITY_PIPE") {
            Ok(value) => {
                if !value.is_empty() {
                    return true;
                }
            }
            Err(_) => {
                return false;
            }
        }
        false
    }
    pub fn new(ignore_terminate: bool) -> Self {
        let writer = sys::get_writer();
        let mut high_writer = writer.clone();
        if Self::can_use_high() {
            high_writer = sys::get_high_writer();
            let high_writer_c = high_writer.clone();
            thread::spawn(move || {
                let ticker = tick(Duration::from_millis(200));
                loop {
                    select! {
                    recv(ticker)->_=>{
                        let mut w = high_writer_c.lock();
                            if w.flush().is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        let reader = sys::get_reader();

        let writer_c = writer.clone();
        thread::spawn(move || {
            let ticker = tick(Duration::from_millis(200));
            loop {
                select! {
                recv(ticker)->_=>{
                    let mut w = writer_c.lock();
                        if w.flush().is_err() {
                            break;
                        }
                    }
                }
            }
        });

        sys::regist_exception_handler();

        if ignore_terminate {
            sys::ignore_terminate()
        }

        Self {
            high_writer,
            writer,
            reader,
        }
    }
    pub fn send_record(&mut self, rec: &Record) -> Result<(), Error> {
        let mut w = self.writer.lock();
        #[cfg(not(feature = "debug"))]
        {
            w.write_all(&rec.compute_size().to_le_bytes()[..])?;
            rec.write_to_writer(&mut (*w)).map_err(|err| err.into())
        }
        #[cfg(feature = "debug")]
        {
            w.write_all(b"{\"data_type\":")?;
            w.write_all(rec.data_type.to_string().as_bytes())?;
            w.write_all(b",\"timestamp\":")?;
            w.write_all(rec.timestamp.to_string().as_bytes())?;
            w.write_all(b",\"data\":")?;
            serde_json::to_writer(w.by_ref(), rec.get_data().get_fields())?;
            w.write_all(b"}\n")
        }
    }
    pub fn send_record_high_priority(&mut self, rec: &Record) -> Result<(), Error> {
        let mut w = self.high_writer.lock();
        #[cfg(not(feature = "debug"))]
        {
            w.write_all(&rec.compute_size().to_le_bytes()[..])?;
            rec.write_to_writer(&mut (*w)).map_err(|err| err.into())
        }
        #[cfg(feature = "debug")]
        {
            w.write_all(b"{\"data_type\":")?;
            w.write_all(rec.data_type.to_string().as_bytes())?;
            w.write_all(b",\"timestamp\":")?;
            w.write_all(rec.timestamp.to_string().as_bytes())?;
            w.write_all(b",\"data\":")?;
            serde_json::to_writer(w.by_ref(), rec.get_data().get_fields())?;
            w.write_all(b"}\n")
        }
    }

    pub fn send_records_high_priority(&mut self, recs: &Vec<Record>) -> Result<(), Error> {
        let mut w = self.high_writer.lock();
        #[cfg(not(feature = "debug"))]
        {
            for rec in recs.iter() {
                println!("send: {:?}", rec);
                w.write_all(&rec.compute_size().to_le_bytes()[..])?;
                rec.write_to_writer(&mut (*w))
                    .map_err(|err| -> std::io::Error { err.into() })?;
            }
            Ok(())
        }
        #[cfg(feature = "debug")]
        {
            for rec in recs.iter() {
                w.write_all(b"{\"data_type\":")?;
                w.write_all(rec.data_type.to_string().as_bytes())?;
                w.write_all(b",\"timestamp\":")?;
                w.write_all(rec.timestamp.to_string().as_bytes())?;
                w.write_all(b",\"data\":")?;
                serde_json::to_writer(w.by_ref(), rec.get_data().get_fields())?;
                w.write_all(b"}\n")?
            }
            Ok(())
        }
    }

    pub fn send_records(&mut self, recs: &Vec<Record>) -> Result<(), Error> {
        let mut w = self.writer.lock();
        #[cfg(not(feature = "debug"))]
        {
            for rec in recs.iter() {
                w.write_all(&rec.compute_size().to_le_bytes()[..])?;
                rec.write_to_writer(&mut (*w))
                    .map_err(|err| -> std::io::Error { err.into() })?;
            }
            Ok(())
        }
        #[cfg(feature = "debug")]
        {
            for rec in recs.iter() {
                w.write_all(b"{\"data_type\":")?;
                w.write_all(rec.data_type.to_string().as_bytes())?;
                w.write_all(b",\"timestamp\":")?;
                w.write_all(rec.timestamp.to_string().as_bytes())?;
                w.write_all(b",\"data\":")?;
                serde_json::to_writer(w.by_ref(), rec.get_data().get_fields())?;
                w.write_all(b"}\n")?
            }
            Ok(())
        }
    }
    pub fn receive(&mut self) -> Result<Task, std::io::Error> {
        let mut r = self.reader.lock();
        let mut bytes = [0; 4];
        r.read_exact(&mut bytes[..])?;
        let length = u32::from_le_bytes(bytes);
        let mut buf = vec![0; length as usize];
        r.read_exact(&mut buf[..])?;
        Task::parse_from_bytes(&buf).map_err(|err| err.into())
    }
    pub fn raw_write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        let mut w = self.writer.lock();
        w.write_all(buf)
    }
    pub fn raw_flush(&mut self) -> Result<(), Error> {
        let mut w = self.writer.lock();
        w.flush()
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.raw_flush();
        let trd = thread::current();
        debug!(
            "has drpooed client from thread, id: {:?}, name: {:?}",
            trd.id(),
            trd.name()
        );
    }
}
