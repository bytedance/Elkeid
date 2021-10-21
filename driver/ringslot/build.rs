use cc;
const INCLUDE_DIR: &str = "../LKM/include";
const COMPILE_FILE: &str = "../LKM/test/ring.c";
const OUTPUT: &str = "ring";
fn main() {
    println!("cargo:rerun-if-changed={}", INCLUDE_DIR);
    println!("cargo:rerun-if-changed={}", COMPILE_FILE);
    cc::Build::new()
        .include(INCLUDE_DIR)
        .file(COMPILE_FILE)
        .compile(OUTPUT);
}
