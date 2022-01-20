use driver::{config::PIPE_PATH, kmod::Kmod, transformer::Transformer};
use log::*;
use plugins::{logger::*, Client};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

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
    // set task_receive thread
    let mut kmod = match Kmod::new(client.clone()) {
        Ok(kmod) => kmod,
        Err(err) => {
            error!("when loading kernel module,an error occurred: {}", err);
            return;
        }
    };
    info!("init kmod successfully");
    let control_s = Arc::new(AtomicBool::new(false));
    let control_l = control_s.clone();
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
                    control_s.store(true, Ordering::Relaxed);
                    return;
                }
            }
        });
    info!("task receive handler is running");
    // set record_send thread
    let record_send = thread::Builder::new()
        .name("record_send".to_string())
        .spawn(move || {
            let ringbuf = BufReader::new(File::open(PIPE_PATH).unwrap()).split(0x17);
            info!("init ringbuf successfully");
            let mut transformer = Transformer::new();
            let mut buf = vec![0; 1024 * 1024];
            for rec in ringbuf {
                if control_l.load(Ordering::Relaxed) {
                    break;
                }
                match rec {
                    Ok(rec) => {
                        match transformer.transform(&rec, &mut buf[..], &mut kmod) {
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
                if control_l.load(Ordering::Relaxed) {
                    break;
                }
            }
        })
        .unwrap();
    let _ = record_send.join();
    info!("plugin will exit");
}
