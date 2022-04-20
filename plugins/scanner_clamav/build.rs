mod bindings {
    #![allow(warnings, dead_code, unused_imports, nonstandard_style)]
    use std::env;

    pub const CLAMAV_MUSSELS: &str = "./lib";

    pub const RUSTC_STATIC_LINK_LIB: &str = "cargo:rustc-link-lib=static=";
    pub const RUSTC_LINK_SEARCH: &str = "cargo:rustc-link-search=native=";

    pub const LINK_STATIC_LIBS: &[&str] = &[
        "clamav_static",
        "json-c",
        "bz2_static",
        "crypto",
        "ssl",
        "xml2",
        "pcre2-8",
        "z",
        "clammspack_static",
        "clamunrar_static",
        "clamunrar_iface_static",
    ];

    pub fn build_and_link() {
        if let Ok(libstdc_static_a) = env::var("STDLIBCXX_STATIC_PATH") {
            println!("cargo:rustc-flags=-l static=stdc++");
            println!("cargo:rustc-link-search=native={}", libstdc_static_a);
        } else {
            panic!("STDLIBCXX_STATIC_PATH undefined, unable to find the path of libstdc++.a\nplease export STDLIBCXX_STATIC_PATH=/path/to/libstdc++.a")
        }
        for each_lib in LINK_STATIC_LIBS {
            println!("{}{}", RUSTC_STATIC_LINK_LIB, each_lib);
        }
        println!("{}{}", RUSTC_LINK_SEARCH, CLAMAV_MUSSELS);
        let mut bindings = bindgen::Builder::default()
            .header("wrapper.h")
            .clang_arg("-I./usr/include/linux")
            .clang_arg("-Iinclude")
            .clang_arg("-Iclamav-mussels-cookbook/mussels/install/include")
            .generate()
            .unwrap();
        bindings.write_to_file("src/clamav.rs").unwrap();
    }
}

fn main() {
    bindings::build_and_link();
}
