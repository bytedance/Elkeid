use anyhow::{anyhow, Result};
use flexi_logger::{Age, Cleanup, Criterion, Logger, Naming};
use plugin::{Receiver, Sender};
use serde::Serialize;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::{atomic, Arc};
/// Use this struct to send a regist request.
#[derive(Debug, PartialEq, Serialize)]
struct RegistRequest {
    pid: u32,
    name: &'static str,
    version: &'static str,
}
/// Builder is used to build a framework to work with the plugin.
pub struct Builder {
    stream: UnixStream,
    logger: Logger,
}

impl Builder {
    /// TODO: we need doc comment here
    pub fn new(
        socket_path: &'static str,
        name: &'static str,
        version: &'static str,
    ) -> Result<Self> {
        let mut stream = match UnixStream::connect(socket_path) {
            Ok(s) => s,
            Err(e) => return Err(anyhow!(e)),
        };

        let req = RegistRequest {
            pid: std::process::id(),
            name,
            version,
        };
        rmp_serde::encode::write_named(&mut stream, &req)?;
        stream.flush()?;
        // TODO: make the immediate numbers as constants
        // TODO: default directory need to be documented
        Ok(Self {
            stream,
            logger: Logger::with_str("info")
                .rotate(
                    Criterion::AgeOrSize(Age::Day, 1024 * 1024 * 10),
                    Naming::Numbers,
                    Cleanup::KeepLogAndCompressedFiles(5, 10),
                )
                .cleanup_in_background_thread(true)
                .log_to_file()
                .format(flexi_logger::colored_detailed_format)
                .directory("./"),
        })
    }

    /// set_logger is used to set a custom logger.
    pub fn set_logger(mut self, logger: Logger) -> Self {
        self.logger = logger;
        self
    }
    /// set_name is used to set a plugin name for logger,default value is "default".
    pub fn set_name(mut self, name: String) -> Self {
        self.logger = self.logger.plugin_name(name);
        self
    }

    // Complete building,get a couple of (Sender, Receiver)
    pub fn build(self) -> (Sender, Receiver) {
        let signal = Arc::new(atomic::AtomicBool::new(false));
        let sender = Sender::new(signal.clone(), self.stream.try_clone().unwrap());
        self.logger.send_handler(sender.clone()).start().unwrap();
        (sender, Receiver::new(signal, self.stream))
    }
}
