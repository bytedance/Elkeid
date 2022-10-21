use anyhow::Result as AnyHowResult;
use nix::sched::{setns, CloneFlags};
use std::fs::File;
use std::os::unix::io::AsRawFd;

pub fn switch_namespace(pid: i32) -> AnyHowResult<()> {
    for (ns, types) in [
        ("ipc", CloneFlags::CLONE_NEWIPC),
        // ("pid", CloneFlags::),
        ("net", CloneFlags::CLONE_NEWNET),
        ("mnt", CloneFlags::CLONE_NEWNS),
    ] {
        let fd = File::open(format!("/proc/{}/ns/{}", pid, ns))?;
        setns(fd.as_raw_fd(), types)?;
    }
    Ok(())
}
