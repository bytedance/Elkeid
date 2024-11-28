use std::{
    env,
    fs::File,
    io::{BufReader, BufWriter, Error, Read, Write},
    os::windows::{
        io::AsRawHandle,
        prelude::{FromRawHandle, RawHandle},
        raw::HANDLE,
    },
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::Result;
use libc::{signal, SIGABRT, SIGINT, SIGSEGV, SIG_IGN};
use parking_lot::Mutex;
use zip;

use windows::Win32::{
    Foundation::FALSE,
    System::{
        Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        Diagnostics::Debug::{
            MiniDumpNormal, MiniDumpWithFullMemory, MiniDumpWithHandleData,
            MiniDumpWithIndirectlyReferencedMemory, MiniDumpWithThreadInfo, MiniDumpWriteDump,
            SetUnhandledExceptionFilter, EXCEPTION_EXECUTE_HANDLER, EXCEPTION_POINTERS,
            MINIDUMP_EXCEPTION_INFORMATION,
        },
        Threading::{ExitProcess, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId},
    },
};

pub fn get_writer() -> Arc<Mutex<BufWriter<File>>> {
    Arc::new(Mutex::new(BufWriter::with_capacity(512 * 1024, unsafe {
        let raw_handle = GetStdHandle(STD_OUTPUT_HANDLE).unwrap();
        File::from_raw_handle(raw_handle.0 as _)
    })))
}

pub fn get_high_writer() -> Arc<Mutex<BufWriter<File>>> {
    Arc::new(Mutex::new(BufWriter::with_capacity(512 * 1024, unsafe {
        let raw_handle = GetStdHandle(STD_OUTPUT_HANDLE).unwrap();
        File::from_raw_handle(raw_handle.0 as _)
    })))
}

pub fn get_reader() -> Arc<Mutex<BufReader<File>>> {
    Arc::new(Mutex::new(BufReader::with_capacity(512 * 1024, unsafe {
        let raw_handle = GetStdHandle(STD_INPUT_HANDLE).unwrap();
        File::from_raw_handle(raw_handle.0 as _)
    })))
}

fn guess_crash_dump_name() -> String {
    match env::current_exe() {
        Ok(path) => {
            if let Some(file_name) = path.file_name() {
                if let Some(name_str) = file_name.to_str() {
                    return format!("{}", name_str.replace(".exe", ".dmp"));
                } else {
                    return "crash_dump.dmp".to_string();
                }
            } else {
                return "crash_dump.dmp".to_string();
            }
        }
        Err(e) => {
            return "crash_dump.dmp".to_string();
        }
    }
}

fn create_dump(exception_info: *const EXCEPTION_POINTERS, dump_path: &str) -> Result<()> {
    unsafe {
        let dump_file = File::create(dump_path)?;
        let dump_file_handle = dump_file.as_raw_handle() as HANDLE;

        let mut dump_info: MINIDUMP_EXCEPTION_INFORMATION = std::mem::zeroed();
        dump_info.ThreadId = GetCurrentThreadId();
        dump_info.ExceptionPointers = exception_info as _;
        dump_info.ClientPointers = FALSE;

        MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            windows::Win32::Foundation::HANDLE(dump_file_handle),
            MiniDumpNormal
                | MiniDumpWithThreadInfo
                | MiniDumpWithHandleData
                | MiniDumpWithIndirectlyReferencedMemory
                | MiniDumpWithFullMemory,
            Some(&dump_info),
            None,
            None,
        )?;
    }
    return Ok(());
}

extern "system" fn exception_handler(exception_info: *const EXCEPTION_POINTERS) -> i32 {
    let dump_path = guess_crash_dump_name();
    let dumpzip_path = dump_path.replace("dmp", "zip");

    unsafe {
        eprintln!("Exception occurred! Generating dump...");
        if let Err(e) = create_dump(exception_info, &dump_path) {
            eprintln!("Failed to generate crash_dump :{}.", e);
        }
        eprintln!("crash_dump.dmp Generated.");
        if let Err(e) = zip_minidump(&dump_path, &dumpzip_path) {
            eprintln!("Failed to zip crash_dump :{}.", e);
        } else {
            let _ = std::fs::remove_file(dump_path);
        }
    }
    EXCEPTION_EXECUTE_HANDLER
}

extern "C" fn signal_handler(signal: i32) {
    eprintln!("catched signal {}", signal);
    unsafe {
        ExitProcess(0);
    }
}

fn zip_minidump(dump_path: &str, zip_path: &str) -> Result<()> {
    let dump_file = File::open(dump_path)?;
    let zip_file = File::create(zip_path)?;
    let mut zip_writer = zip::ZipWriter::new(zip_file);

    // 设置压缩选项
    zip_writer.start_file(
        dump_path,
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Bzip2),
    )?;

    // 将 Minidump 内容写入 ZIP
    std::io::copy(&mut &dump_file, &mut zip_writer)?;
    zip_writer.finish()?;

    Ok(())
}

pub fn regist_exception_handler() {
    unsafe {
        SetUnhandledExceptionFilter(Some(exception_handler));
        //signal(SIGABRT, signal_handler as _);
        //signal(SIGSEGV, signal_handler as _);
    }
}

pub fn ignore_terminate() {
    unsafe {
        signal(SIGINT, SIG_IGN); // Ingore nssm restart agent
    }
}
