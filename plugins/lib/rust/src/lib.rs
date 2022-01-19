pub mod bridge;
pub mod logger;

pub use bridge::*;
use crossbeam::channel::{select, tick};
use log::{debug, info};
use parking_lot::Mutex;
use protobuf::Message;
use signal_hook::{
    consts::{SIGTERM, SIGUSR1},
    iterator::Signals,
};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Error, Read, Write},
    os::unix::prelude::FromRawFd,
    sync::Arc,
    thread,
    time::Duration,
};
#[derive(Clone)]
pub enum EncodeType {
    Protobuf,
    Json,
}
#[derive(Clone)]
pub struct Client {
    writer: Arc<Mutex<BufWriter<File>>>,
    reader: Arc<Mutex<BufReader<File>>>,
}
#[cfg(feature = "debug")]
const READ_PIPE_FD: i32 = 0;
#[cfg(not(feature = "debug"))]
const READ_PIPE_FD: i32 = 3;
#[cfg(feature = "debug")]
const WRITE_PIPE_FD: i32 = 1;
#[cfg(not(feature = "debug"))]
const WRITE_PIPE_FD: i32 = 4;

impl Client {
    pub fn new(ignore_terminate: bool) -> Self {
        let writer = Arc::new(Mutex::new(BufWriter::with_capacity(512 * 1024, unsafe {
            File::from_raw_fd(WRITE_PIPE_FD)
        })));
        let reader = Arc::new(Mutex::new(BufReader::new(unsafe {
            File::from_raw_fd(READ_PIPE_FD)
        })));
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
        if ignore_terminate {
            let mut signals = Signals::new(&[SIGTERM, SIGUSR1]).unwrap();
            thread::spawn(move || {
                for sig in signals.forever() {
                    if sig == SIGTERM {
                        info!("received signal: {:?}, wait 3 secs to exit", sig);
                        thread::sleep(Duration::from_secs(3));
                        unsafe {
                            libc::close(WRITE_PIPE_FD);
                            libc::close(READ_PIPE_FD);
                        }
                    }
                }
            });
        }
        Self { writer, reader }
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
