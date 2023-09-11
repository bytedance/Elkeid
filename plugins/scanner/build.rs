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
        "iconv",
        "charset",
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
        const BINDGEN_VARS: &[&str] = &[
            "CL_INIT_DEFAULT",
            "CL_SCAN_GENERAL_YARAHIT",
            "CL_SCAN_PARSE_ELF",
            "CL_SCAN_PARSE_PE",
            "CL_SCAN_PARSE_ARCHIVE",
            "CL_DB_DIRECTORY",
            "cl_error_t_CL_SUCCESS",
            "cl_error_t_CL_CLEAN",
            "cl_error_t_CL_VIRUS",
            "cl_engine_field",
            "cl_engine_field_CL_ENGINE_MAX_SCANSIZE",
            "cl_engine_field_CL_ENGINE_MAX_FILESIZE",
            "cl_engine_field_CL_ENGINE_MAX_SCANTIME",
            "cl_engine_field_CL_ENGINE_PCRE_MATCH_LIMIT",
            "cl_engine_field_CL_ENGINE_PCRE_RECMATCH_LIMIT",
            "cl_engine_field_CL_ENGINE_DISABLE_CACHE",
        ];

        const BINDGEN_TYPES: &[&str] = &["timeval", "cl_engine", "cl_scan_options"];
        const BINDGEN_FUNCTIONS: &[&str] = &[
            "cl_init",
            "cl_strerror",
            "cl_engine_new",
            "cl_engine_addref",
            "cl_engine_free",
            "cl_engine_set_num",
            "cl_load",
            "cl_engine_compile",
            "cl_fmap_open_memory",
            "cl_fmap_close",
            "cl_yr_hit_cb_ctx_init",
            "cl_yr_hit_cb_ctx_free",
            "cl_scanmap_callback",
            "cl_scanfile",
            "cl_scanfile_callback",
        ];

        for each_lib in LINK_STATIC_LIBS {
            println!("{}{}", RUSTC_STATIC_LINK_LIB, each_lib);
        }
        println!("{}{}", RUSTC_LINK_SEARCH, CLAMAV_MUSSELS);
        let mut builder = bindgen::builder()
            .raw_line("#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]")
            .header("wrapper.h")
            .clang_arg("-I./opt/x86_64-linux-musl/include")
            .clang_arg("-I./opt/x86_64-linux-musl/x86_64-linux-musl/include")
            .clang_arg("-I./opt/x86_64-linux-musl/x86_64-linux-musl/include/strings.h")
            .clang_arg("-I./opt/x86_64-linux-musl/x86_64-linux-musl/include/linux")
            .clang_arg("-Iinclude")
            .clang_arg("-Iclamav")
            .clang_arg("-Iclamav/build")
            .clang_arg("-Iclamav/libclamav")
            .clang_arg("-Iclamav/libclamav/regex")
            .clang_arg("-Iclamav/libclamunrar_iface")
            .clang_arg("-Iclamav-mussels-cookbook/mussels/install/include")
            .clang_arg("-Iclamav-mussels-cookbook/mussels/install/include/json-c");

        for &c_var in BINDGEN_VARS {
            builder = builder.allowlist_var(c_var);
        }
        for &c_function in BINDGEN_FUNCTIONS {
            builder = builder.allowlist_function(c_function);
        }
        for &c_type in BINDGEN_TYPES {
            builder = builder.allowlist_type(c_type);
        }

        builder
            .generate()
            .unwrap()
            .write_to_file("src/model/engine/clamav/clamav.rs")
            .unwrap();
    }
}

fn main() {
    bindings::build_and_link();
}
