use driver::{kmod::Kmod, transformer::Transformer};
use log::*;
use plugins::{logger::*, Client};
use ringslot::{Handler, RingSlot};
use std::{path::PathBuf, thread};

fn main() {
    let mut client = Client::new(true);
    // set logger
    let logger = Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from("./driver.log"),
        #[cfg(not(feature = "debug"))]
        file_level: LevelFilter::Info,
        #[cfg(feature = "debug")]
        file_level: LevelFilter::Debug,
        remote_level: LevelFilter::Error,
        max_backups: 10,
        compress: true,
        client: Some(client.clone()),
    });
    set_boxed_logger(Box::new(logger)).unwrap();
    let kmod = match Kmod::new() {
        Ok(kmod) => {
            info!("init kmod successfully");
            kmod
        }
        Err(err) => {
            error!("{}", err);
            return;
        }
    };
    let handler = Handler::new();
    let control = handler.get_inner();
    let mut client_c = client.clone();
    let _ = thread::Builder::new()
        .name("task_receive".to_owned())
        .spawn(move || loop {
            match client_c.receive() {
                Ok(_) => {
                    // handle task
                }
                Err(e) => {
                    error!("when receiving task,an error occurred:{}", e);
                    handler.close();
                    return;
                }
            }
        });
    info!("task receive handler is running");
    // set record_send thread
    let record_send = thread::Builder::new()
        .name("record_send".to_string())
        .spawn(move || {
            let mut ringslot = match RingSlot::new(control) {
                Ok(r) => r,
                Err(e) => {
                    error!("when open ringslot, an error occurred: {}", e);
                    return;
                }
            };
            info!("init ringslot successfully");
            let mut transformer = Transformer::new();
            let mut buf = vec![0; 1024 * 1024];
            loop {
                match ringslot.read_rec() {
                    Ok(rec) => {
                        match transformer.transform(rec, &mut buf[..]) {
                            Ok(written) => {
                                debug!("write to writer: {:?}", &buf[..written]);
                                if let Err(err) = client.raw_write_all(&buf[..written]) {
                                    error!("when sending record,an error occurred:{}", err);
                                    return;
                                };
                            }
                            Err(err) => {
                                error!("transform data failed: {}", err);
                                continue;
                            }
                        };
                    }
                    Err(err) => {
                        error!("read ringslot failed:{}", err);
                        return;
                    }
                }
            }
        })
        .unwrap();
    let _ = record_send.join();
    info!("plugin will exit");
}
