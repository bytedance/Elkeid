use cc;
fn main() {
    println!("cargo:rerun-if-changed={}", "LKM/include");
    println!("cargo:rerun-if-changed={}", "LKM/zua");
    cc::Build::new()
        .include("LKM/include")
        .include("LKM/zua")
        .file("LKM/test/xfer.c")
        .file("LKM/test/ring.c")
        .file("LKM/zua/zua_scanner.c")
        .file("LKM/zua/zua_parser.c")
        .file("LKM/zua/zua_type.c")
        .compile("ring");
}
