use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::{BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::sync::{atomic, Arc};

const DEFAULT_SENDER_BUF_SIZE: usize = 10240;
/// Task defined control message
#[derive(Debug, PartialEq, Deserialize)]
pub struct Task {
    pub id: u32,
    pub content: String,
    pub token: String,
}
/// Sender is used by plugin to send data
#[derive(Clone)]
pub struct Sender {
    buffer: Arc<Mutex<Vec<u8>>>,
    signal: Arc<atomic::AtomicBool>,
}

impl Sender {
    pub fn new(signal: Arc<atomic::AtomicBool>, stream: UnixStream) -> Self {
        let thread_signal = signal.clone();
        let mut buf = Vec::<u8>::with_capacity(DEFAULT_SENDER_BUF_SIZE);
        buf.push(0xdc);
        buf.push(0);
        buf.push(0);
        let rbuffer = Arc::new(Mutex::new(buf));
        let wbuffer = rbuffer.clone();
        let mut w = BufWriter::new(stream);
        std::thread::spawn(move || loop {
            if thread_signal.load(atomic::Ordering::Relaxed) {
                if let Ok(inner) = w.into_inner() {
                    let _ = inner.shutdown(std::net::Shutdown::Both);
                }
                return;
            }
            let mut buf = wbuffer.lock();
            if ((buf[1] as u16) << 8) + (buf[2] as u16) != 0 {
                match w.write(buf.as_slice()).and(w.flush()) {
                    Err(e) => {
                        thread_signal.store(true, atomic::Ordering::Relaxed);
                        println!("{:?}", e);
                        return;
                    }
                    Ok(_) => {}
                }
                buf.clear();
                buf.push(0xdc);
                buf.push(0);
                buf.push(0);
            }
            drop(buf);
            std::thread::sleep(std::time::Duration::from_millis(125));
        });
        Self {
            buffer: rbuffer,
            signal,
        }
    }
    pub fn send<T: Serialize>(&self, data: &T) -> Result<()> {
        if self.signal.load(atomic::Ordering::Relaxed) {
            return Err(anyhow!("Send error. Must exit."));
        }
        let mut buf = self.buffer.lock();
        buf.extend(rmp_serde::encode::to_vec_named(data)?);
        let mut len = ((buf[1] as u16) << 8) + (buf[2] as u16);
        if len == u16::MAX {
            return Err(anyhow!("Reached maximum length. Cannot send."));
        }
        len += 1;
        buf[1] = (len >> 8) as u8;
        buf[2] = len as u8;

        Ok(())
    }
    pub fn get_ctrl(&self) -> Arc<atomic::AtomicBool> {
        self.signal.clone()
    }
    pub fn close(&self) {
        self.signal.store(true, atomic::Ordering::Relaxed)
    }
}
/// Receiver is used by plugin to receive task
pub struct Receiver {
    stream: UnixStream,
    signal: Arc<atomic::AtomicBool>,
}

impl Receiver {
    pub fn new(signal: Arc<atomic::AtomicBool>, stream: UnixStream) -> Self {
        Self { signal, stream }
    }
    pub fn receive(&self) -> Result<Task> {
        if self.signal.load(atomic::Ordering::Relaxed) {
            return Err(anyhow!("Should exit."));
        }
        rmp_serde::decode::from_read(&self.stream).map_err(|e| {
            self.signal.store(true, atomic::Ordering::Relaxed);
            anyhow!(e)
        })
    }
}
