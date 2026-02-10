use cc;
fn main() {
    println!("cargo:rerun-if-changed={}", "../LKM/include");
    println!("cargo:rerun-if-changed={}", "../zua");
    println!("cargo:rerun-if-changed={}", "../xfer");
    println!("cargo:rerun-if-changed={}", "../libbpf");
    println!("cargo:rerun-if-changed={}", "../libbpf/include/uapi");
    println!("cargo:rerun-if-changed={}", "../libbpf/include");
    println!("cargo:rerun-if-changed={}", "../ebpf");
    println!("cargo:rerun-if-changed={}", "../ebpf/hids");
    println!("cargo:rerun-if-changed={}", "../ebpf/helper");
    cc::Build::new()
        .include("..")
        .include("../LKM/include")
        .include("../zua")
        .include("../xfer")
        .include("../libbpf")
        .include("../libbpf/include/uapi")
        .include("../libbpf/include")
        .include("../ebpf")
        .include("../ebpf/hids")
        .include("../ebpf/helper")

        .file("../ring/kmod.c")
        .file("../ring/core.c")
        .file("../ring/safeboot.c")
        .file("../zua/zua_scanner.c")
        .file("../zua/zua_parser.c")
        .file("../zua/zua_type.c")
        .file("../xfer/xfer.c")
        .file("../ebpf/consume.c")
        .file("../ebpf/load.c")
        .file("../ebpf/helper/errno_helpers.c")
        .file("../ebpf/helper/trace_helpers.c")
        .file("../ebpf/helper/btf_helpers.c")
        .file("../ebpf/helper/map_helpers.c")
        .file("../ebpf/helper/uprobe_helpers.c")
        .file("../ebpf/helper/syscall_helpers.c")

        .compile("elkeid")
}
