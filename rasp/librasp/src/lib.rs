pub mod comm;
pub mod cpython;
pub mod golang;
pub mod jvm;
pub mod manager;
pub mod nodejs;
pub mod php;
pub mod process;
pub mod runtime;
#[allow(non_snake_case)]
pub mod settings;
pub mod parse_elf;

pub mod async_command {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, ExitStatus, Stdio};
    use std::thread::{sleep, Builder};
    use std::time::Duration;

    use anyhow::{anyhow, Result};
    use libc::{kill, SIGKILL};
    use log::*;

    use crate::comm::Control;

    pub fn run_async_process(command: &mut Command) -> Result<(ExitStatus, String, String)> {
        // start
        let mut child = match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("spawn command failed: {}", e.to_string());
                return Err(anyhow!(msg));
            }
        };
        let pid = child.id();
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let child_ctrl = Control::new();
        let mut wait_child_ctrl = child_ctrl.clone();
        let mut kill_child_ctrl = child_ctrl.clone();
        let mut wait_count = 0;
        let wait = Builder::new()
            .name(format!("async_run_{}", child.id()))
            .spawn(move || -> Result<ExitStatus> {
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            info!("command wait exited with: {}", status);
                            let _ = wait_child_ctrl.stop();
                            return Ok(status);
                        }
                        Ok(None) => {
                            info!("command wait not exited yet");
                            sleep(Duration::from_millis(100));
                        }
                        Err(e) => {
                            warn!("attempting wait failed: {}", e);
                            let _ = wait_child_ctrl.stop();
                            let err = format!("wait failed: {}", e);
                            return Err(anyhow!(err));
                        }
                    };
                }
            })
            .unwrap();
        let kill = Builder::new()
            .name(format!("kill_{}", pid))
            .spawn(move || loop {
                if !kill_child_ctrl.check() {
                    break;
                }
                wait_count += 1;
                if wait_count >= 60 {
                    warn!("kill child: {}", pid);
                    // send signal
                    kill_child(pid as i32);
                    return;
                }
                info!("wait count: {}", wait_count);
                sleep(Duration::from_secs(1));
            })
            .unwrap();

        let stdout_thread = Builder::new()
            .name(format!("child_stdout_{}", pid))
            .spawn(move || -> String {
                let mut stdout_string = String::new();
                if stdout.is_none() {
                    return stdout_string;
                }
                let mut stdout_buff_reader = BufReader::new(stdout.unwrap());
                loop {
                    let mut buf = String::new();
                    match stdout_buff_reader.read_line(&mut buf) {
                        Ok(size) => {
                            if size == 0 {
                                // EOF
                                debug!("stdout EOF");
                                break;
                            }
                            stdout_string.push_str(&buf);
                        }
                        Err(e) => {
                            error!("read line failed: {}", e);
                            break;
                        }
                    };
                }
                return stdout_string;
            })
            .unwrap();
        let stderr_thread = Builder::new()
            .name(format!("child_stderr_{}", pid))
            .spawn(move || -> String {
                let mut stderr_string = String::new();
                if stderr.is_none() {
                    return stderr_string;
                }
                let mut stderr_buff_reader = BufReader::new(stderr.unwrap());
                loop {
                    let mut buf = String::new();
                    match stderr_buff_reader.read_line(&mut buf) {
                        Ok(size) => {
                            if size == 0 {
                                // EOF
                                debug!("stderr EOF");
                                break;
                            }
                            stderr_string.push_str(&buf);
                        }
                        Err(e) => {
                            error!("read line failed: {}", e);
                            break;
                        }
                    };
                }
                return stderr_string;
            })
            .unwrap();
        debug!("starting join");
        let wait_res = wait.join();
        debug!("wait joined");
        let _ = kill.join();
        let stdout_res = stdout_thread.join();
        debug!("stdout joined");
        let stderr_res = stderr_thread.join();
        debug!("stderr joined");
        let stdout_string = match stdout_res {
            Ok(s) => s,
            Err(e) => return Err(anyhow!("{:?}", e)),
        };
        let stderr_string = match stderr_res {
            Ok(s) => s,
            Err(e) => return Err(anyhow!("{:?}", e)),
        };
        match wait_res {
            Ok(r) => match r {
                Ok(s) => {
                    if s.success() {
                        return Ok((s, stdout_string, stderr_string));
                    } else {
                        // warn!("stdout: {}", stdout_string);
                        // warn!("stderr: {}", stderr_string);
                        warn!(
                            "async run failed: {:?}, {}\n {}\n {}",
                            command,
                            s.to_string(),
                            stdout_string,
                            stderr_string
                        );
                        return Ok((s, stdout_string, stderr_string));
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            },
            Err(_) => return Err(anyhow!("wait thread join failed")),
        }
    }

    pub fn kill_child(pid: i32) {
        debug!("kill child: {}", pid);
        unsafe {
            kill(pid, SIGKILL);
        }
    }
}
