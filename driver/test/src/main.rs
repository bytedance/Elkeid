#[allow(unused)]

extern crate getopts;
use getopts::Options;
use std::env;
use libc::c_int;

pub const RING_KMOD: c_int = 0x5254004B as _; /* kmod: smith/hids_driver/elkeid */
pub const RING_EBPF: c_int = 0x52540045 as _; /* ebpf program */

pub const RING_KMOD_V1_7: c_int = 0x5254174B as _; /* hids_driver */
pub const RING_KMOD_V1_8: c_int = 0x5254184B as _; /* smith */
pub const RING_KMOD_V1_9: c_int = 0x5254194B as _; /* elkeid */

fn control_kmod(module: Option<&str>) -> String {
    match module {
        Some(n) => format!("/sys/module/{n}/parameters/control_trace"),
        None => format!("/sys/module/elkeid/parameters/control_trace"),
    }
}

fn process_kmod(module: Option<&str>) {

    let ipv4list: Vec<String> = vec!["10.79.232.80".to_string()];
    let ipv6list: Vec<String> = vec!["fdbd:dc03:ff:500:f11d:b678:cfd8:d478".to_string()];

    let psadflag: Vec<usize> = vec![128, 512];
    let bl_md5_json = "md5.json";

    /*
     *  different version of HIDS requires control_path as:
     *
     *  v1.7:  ::new(RING_KMOD_V1_7, "/proc/elkeid-endpoint")
     *  v1.8:  ::new(RING_KMOD_V1_8, "/proc/elkeid-endpoint")
     *  v1.9:  ::new(RING_KMOD_V1_9, "/sys/module/elkeid/parameters/control_trace")
     *
     * Example for v1.7:
     *
     * let control_path = "/proc/elkeid-endpoint";
     * let (mut rs, _cancel) = ringslot::RingSlot::new(RING_KMOD_V1_7, &control_path).unwrap();
     * let controler = ringslot::SmithControl::new(RING_KMOD_V1_7, &control_path).unwrap();
    *
     * Example for v1.8:
     *
     * let control_path = "/proc/elkeid-endpoint";
     * let (mut rs, _cancel) = ringslot::RingSlot::new(RING_KMOD_V1_8, &control_path).unwrap();
     * let controler = ringslot::SmithControl::new(RING_KMOD_V1_8, &control_path).unwrap();
     *
     * Example for v1.9:
     *
     * let control_path = "/sys/module/elkeid/parameters/control_trace";
     * let (mut rs, _cancel) = ringslot::RingSlot::new(RING_KMOD_V1_9, &control_path).unwrap();
     * let controler = ringslot::SmithControl::new(RING_KMOD_V1_9, &control_path).unwrap();
     */

    let control_path = control_kmod(module);
    let (mut rs, _cancel) = ringslot::RingSlot::new(RING_KMOD_V1_9, &control_path).unwrap();
    let controler = ringslot::SmithControl::new(RING_KMOD_V1_9, &control_path).unwrap();

    if let Err(e) = controler.clear_all() {
        println!("{}", e);
    }

    if let Err(e) = controler.ac_set_block_md5(bl_md5_json) {
        println!("{}", e);
    }

    if let Err(e) = controler.psad_enable() {
        println!("{}", e);
    }

    if let Err(e) = controler.psad_set_flag(&psadflag) {
        println!("{}", e);
    }

    if let Err(e) = controler.psad_add_allowlist_ipv4(&ipv4list) {
        println!("{}", e);
    }
    if let Err(e) = controler.psad_add_allowlist_ipv6(&ipv6list) {
        println!("{}", e);
    }

    loop {
        if let Ok(rec) = rs.read_record() {
            let rec_collect = rec.split(|c| *c == 0);
            for each in rec_collect.into_iter() {
                if let Ok(tc) = String::from_utf8(each.to_vec()) {
                    print!("{} ", tc);
                }
            }
            println!("");
        }
    }
}

fn control_ebpf(module: Option<&str>) -> String {
    match module {
        Some(n) => n.to_string(),
        None => String::new(),
    }
}

fn process_ebpf(_bpfprog: Option<&str>) {

    /* noew connect to elkeid maps (in /sys/fs/bpf) */
    let ctrl = ringslot::EBPFControl::new(&String::new()).unwrap();
    let (mut read, _cancel) = ringslot::EBPFConsumer::new(&String::new()).unwrap();

    let mut buffer = [0u8; 16];
    ringslot::EBPFControl::get_version(&mut buffer).unwrap();
    println!("loaded ebpf version: {}", String::from_utf8(buffer.to_vec()).unwrap());

    if let Err(e) = ctrl.clear_all() {
        println!("{}", e);
    }

    let exe_wget = String::from("/usr/bin/wget");
    if let Err(e) = ctrl.ac_add_allow_exe_bytes(exe_wget.as_bytes()) {
        println!("{}", e);
    }
    let exe_curl = String::from("/usr/bin/curl");
    if let Err(e) = ctrl.ac_add_allow_exe_bytes(exe_curl.as_bytes()) {
        println!("{}", e);
    }
    if let Err(e) = ctrl.ac_del_allow_exe_bytes(exe_wget.as_bytes()) {
        println!("{}", e);
    }

    let argv_top = String::from("top -bn 1");
    if let Err(e) = ctrl.ac_add_allow_argv_bytes(argv_top.as_bytes()) {
        println!("{}", e);
    }

    loop {
        if let Ok(rec) = read.read_record() {
            let rec_collect = rec.split(|c| *c == 0);
            for each in rec_collect.into_iter() {
                if let Ok(tc) = String::from_utf8(each.to_vec()) {
                    print!("{} ", tc);
                }
            }
            println!("");
        }
    }
}

fn do_load_ebpf(bpfprog: Option<&str>) {

    /* the first thing is loading the ebpf program */
    let control_path = control_ebpf(bpfprog);
    let _ebpf = ringslot::EBPFLoader::new(&control_path).unwrap();

    process_ebpf(bpfprog);
}

fn show_help(program: &str, opts: Options) {
    let brief = format!("Usage: {} [-n elkeid] or [-l ebpfprog.o]", program);
    print!("{}", opts.usage(&brief));
    print!("\nExamples for kmod:\n");
    print!("{} -N elkeid\n", program);
    print!("{} -n\n", program);
    print!("\nExamples for ebpf:\n");
    print!("{} -l hids/elkeid.bpf-6.1.0-9-amd64.o\n", program);
    print!("{} -Q /sys/fs/bpf/elkeid\n", program);
    print!("{} -q\n", program);
}

fn main() {
    let cmd_args: Vec<String> = env::args().collect();
    let cmd_prog = cmd_args[0].clone();

    let mut cmd_opts = Options::new();
    cmd_opts.optflag("n", "name", ": query events from loaded elkeid.ko");
    cmd_opts.optopt("N", "name", ": query events from loaded LKM module", "module");
    cmd_opts.optopt("l", "load", ": load and attach ebpf program", "bpfprog");
    cmd_opts.optopt("L", "", ": load and attach ebpf program", "bpfprog");
    cmd_opts.optopt("Q", "query", ": query events from loaded ebpf prog", "bpfprog");
    cmd_opts.optflag("q", "query", ": query events from /sys/fs/bpf/elkeid");
    cmd_opts.optflag("h", "help", ": show this message");
    let cmd_pats = match cmd_opts.parse(&cmd_args[1..]) {
        Ok(m) => { m }
        Err(f) => { print!("{}\n", f.to_string()); return; }
    };

    if cmd_pats.opt_present("h") {
        show_help(&cmd_prog, cmd_opts);
        return;
    }

    if cmd_pats.opt_present("q") || cmd_pats.opt_present("Q") {
        let ebpfprog = cmd_pats.opt_str("Q");
        process_ebpf(ebpfprog.as_deref());
        return;
    }

    if cmd_pats.opt_present("L") {
        match cmd_pats.opt_str("L") {
            Some(n) => do_load_ebpf(Some(n).as_deref()),
            None => show_help(&cmd_prog, cmd_opts),
        }
        return;
    }
    if cmd_pats.opt_present("l") {
        match cmd_pats.opt_str("l") {
            Some(n) => do_load_ebpf(Some(n).as_deref()),
            None => show_help(&cmd_prog, cmd_opts),
        }
        return;
    }

    let module = cmd_pats.opt_str("N");
    if cmd_pats.opt_present("n") || cmd_pats.opt_present("N") {
        process_kmod(module.as_deref());
    } else {
        /* default: try kernel module elkeid */
        process_kmod(module.as_deref());
    }
}
