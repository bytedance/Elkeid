use std::os::unix::prelude::FromRawFd;

#[cfg(feature = "debug")]
const READ_PIPE_FD: i32 = 0;
#[cfg(not(feature = "debug"))]
const READ_PIPE_FD: i32 = 3;
#[cfg(feature = "debug")]
const WRITE_PIPE_FD: i32 = 1;
#[cfg(not(feature = "debug"))]
const WRITE_PIPE_FD: i32 = 4;
const HIGH_PRIORIT_FD: i32 = 5;

use std::{
    fs::File,
    io::{BufReader, BufWriter},
    sync::Arc,
};

use parking_lot::Mutex;

pub fn get_writer() -> Arc<Mutex<BufWriter<File>>> {
    Arc::new(Mutex::new(BufWriter::with_capacity(512 * 1024, unsafe {
        File::from_raw_fd(WRITE_PIPE_FD)
    })))
}

pub fn get_high_writer() -> Arc<Mutex<BufWriter<File>>> {
    Arc::new(Mutex::new(BufWriter::with_capacity(512 * 1024, unsafe {
        File::from_raw_fd(WRITE_PIPE_FD)
    })))
}

pub fn get_reader() -> Arc<Mutex<BufReader<File>>> {
    Arc::new(Mutex::new(BufReader::with_capacity(512 * 1024, unsafe {
        File::from_raw_fd(READ_PIPE_FD)
    })))
}

extern "C" fn signal_handler(signal: i32) {
    eprintln!("catched signal {:?}, exit", signal);
    unsafe {
        libc::sleep(3);
        libc::close(WRITE_PIPE_FD);
        libc::close(READ_PIPE_FD);
        if libc::fcntl(HIGH_PRIORIT_FD, libc::F_GETFD) != -1
            || std::io::Error::last_os_error().kind() != std::io::ErrorKind::InvalidInput
        {
            libc::close(READ_PIPE_FD);
        }
    }
}

pub fn ignore_terminate() {
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, signal_handler as _);
    }
}

pub fn regist_exception_handler() {}
