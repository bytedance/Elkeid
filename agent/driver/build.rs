use codegen;
use heck::CamelCase;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use toml;
#[derive(Deserialize, Debug)]
struct Template {
    metadata: Metadata,
    config: Config,
    structures: HashMap<String, Structure>,
}
#[derive(Deserialize, Debug)]
struct Metadata {
    version: String,
    maintainers: Vec<String>,
}
#[derive(Deserialize, Debug)]
struct Config {
    ko_url: Vec<String>,
    name: String,
    pipe_path: String,
    socket_path: String,
}
#[derive(Deserialize, Debug)]
struct Structure {
    common_fields: bool,
    data_type: usize,
    #[serde(rename = "additional_fields",default)]
    fields: HashMap<String, Field>,
}
#[derive(Deserialize, Debug, Clone)]
struct Field {
    index: usize,
    #[serde(rename = "type")]
    _type: String,
}
const COMMON_FIELDS_KERNEL: &[&str] = &[
    "uid",
    "data_type",
    "exe",
    "pid",
    "ppid",
    "pgid",
    "tgid",
    "sid",
    "comm",
    "nodename",
    "sessionid",
    "pns",
    "root_pns",
];
const COMMON_FIELDS_USER: &[&str] = &[
    "username",
    "timestamp",
    "exe_hash",
    "ppid_argv",
    "pgid_argv",
    "argv",
    "pid_tree",
];
const PARSER_PATH: &str = "src/parser.rs";
const CONFIG_PATH: &str = "src/config.rs";
fn generate_parser(content: &mut Template) {
    content.structures.iter_mut().for_each(|(_, v)| {
        if v.common_fields {
            v.fields.iter_mut().for_each(|(_, f)| {
                f.index += COMMON_FIELDS_KERNEL.len();
            });
            for i in 0..COMMON_FIELDS_KERNEL.len() {
                v.fields.insert(
                    String::from(COMMON_FIELDS_KERNEL[i]),
                    Field {
                        index: i,
                        _type: String::from("kernel"),
                    },
                );
            }
            for i in 0..COMMON_FIELDS_USER.len() {
                if !v.fields.contains_key(COMMON_FIELDS_USER[i]) {
                    v.fields.insert(
                        String::from(COMMON_FIELDS_USER[i]),
                        Field {
                            index: v.fields.len() + 1,
                            _type: String::from("user"),
                        },
                    );
                }
            }
        }
    });
    let mut scope = codegen::Scope::new();
    scope.import("crate::cache", "{ArgvCache, FileHashCache}");
    scope.import("anyhow", "*");
    scope.import("clru", "CLruCache");
    scope.import("coarsetime", "Clock");
    scope.import("fnv", "FnvBuildHasher");
    scope.import("ipnet", "{Ipv4Net, Ipv6Net}");
    scope.import("iprange", "IpRange");
    scope.import("plugin", "*");
    scope.import("log", "*");
    scope.import("serde", "Serialize");
    scope.import("users", "{Users, UsersCache}");
    content.structures.iter().for_each(|(k, v)| {
        let s = scope.new_struct(&k.to_camel_case());
        s.generic("\'a").derive("Debug").derive("Serialize");
        for (i, _) in &v.fields {
            s.field(i, "&'a str");
        }
    });
    scope
        .new_struct("Parser")
        .field("sender", "Sender")
        .field("user_cache", "UsersCache")
        .field("argv_cache", "ArgvCache")
        .field("pid_tree_cache", "CLruCache<u32, String, FnvBuildHasher>")
        .field("file_hash_cache", "FileHashCache")
        .vis("pub");
    let mut parser_impl = codegen::Impl::new("Parser");
    parser_impl
        .new_fn("new")
        .arg("sender", "Sender")
        .ret("Self")
        .line("let mut ipv4_range: IpRange<Ipv4Net> = IpRange::new();")
        .line("let mut ipv6_range: IpRange<Ipv6Net> = IpRange::new();")
        .line("ipv4_range.add(\"127.0.0.1/8\".parse().unwrap());")
        .line("ipv6_range.add(\"::1/128\".parse().unwrap());")
        .line("ipv6_range.add(\"fe80::/10\".parse().unwrap());")
        .line("Self {sender,user_cache: UsersCache::default(),")
        .line("argv_cache: ArgvCache::new(10240),")
        .line("pid_tree_cache: CLruCache::with_hasher(10240, FnvBuildHasher::default()),")
        .line("file_hash_cache: FileHashCache::new(10240),}")
        .vis("pub");
    let parser_func = parser_impl
        .new_fn("parse")
        .arg_mut_self()
        .arg("fields", "Vec<&str>")
        .ret("Result<()>")
        .line("match fields[1] {")
        .vis("pub");
    for (k, v) in content.structures.iter() {
        parser_func.line(format!("\"{}\"=>{{", v.data_type));
        // Add timestamp
        if v.fields.contains_key("timestamp") {
            parser_func.line("let timestamp = Clock::now_since_epoch().as_secs().to_string();");
        }
        // Add username
        if let Some(f) = v.fields.get("uid") {
            parser_func.line(format!(
                "let username = if let Ok(uid) = fields[{}].parse::<u32>() {{
                    match self.user_cache.get_user_by_uid(uid) {{
                        Some(n) => n.name().to_str().unwrap_or_default().to_owned(),
                        None => \"-3\".to_string(),
                    }}
                }} else {{
                    \"-3\".to_string()
                }};",
                f.index
            ));
        }
        // Add old_username
        if v.fields.contains_key("old_username") {
            parser_func.line(format!(
                "let old_username = if let Ok(old_uid) = fields[{}].parse::<u32>() {{
                    match self.user_cache.get_user_by_uid(old_uid) {{
                        Some(n) => n.name().to_str().unwrap_or_default().to_owned(),
                        None => \"-3\".to_string(),
                    }}
                }} else {{
                    \"-3\".to_string()
                }};",
                v.fields.get("old_uid").unwrap().index
            ));
        }
        // Add exe_hash
        if v.fields.contains_key("exe_hash") {
            parser_func.line(
                "let exe_hash = if fields[2] != \"-1\" && fields[2] != \"\" {
                    self.file_hash_cache.get(fields[2])
                } else {
                    \"-3\".to_string()
                };",
            );
        }
        // Add pid tree or put in cache
        if let Some(f) = v.fields.get("pid_tree") {
            match f._type.as_ref() {
                "user" | "placeholder" => {
                    parser_func.line(
                        "let pid_tree = if let Ok(pid) = fields[3].parse::<u32>() {
                    let pid_tree = match self.pid_tree_cache.get(&pid) {
                        Some(t) => t,
                        None => \"-3\",
                    };
                    pid_tree
                } else {
                    \"-3\"
                };",
                    );
                }
                "kernel" => {
                    parser_func.line(format!(
                        "if let Ok(pid) = fields[3].parse::<u32>() {{
                    if fields[{}] != \"\" && fields[{}] != \"-1\" {{
                        self.pid_tree_cache.put(pid, fields[{}].to_string());
                    }}
                }}",
                        f.index, f.index, f.index
                    ));
                }
                _ => {}
            }
        }
        // Add argv or put in cache
        if let Some(f) = v.fields.get("argv") {
            match f._type.as_ref() {
                "user" | "placeholder" => {
                    parser_func.line(
                        "let argv = if let Ok(pid) = fields[3].parse::<u32>() {
                    self.argv_cache.get(&pid)
                } else {
                    \"-3\".to_string()
                };",
                    );
                }
                "kernel" => {
                    parser_func.line(format!(
                        "if let Ok(pid) = fields[3].parse::<u32>() {{
                    if fields[{}] != \"\" && fields[{}] != \"-1\" {{
                        self.argv_cache.put(pid, fields[{}].to_string());
                    }}
                }}",
                        f.index, f.index, f.index
                    ));
                }
                _ => {}
            }
        }
        // Add pgid_argv
        if let Some(f) = v.fields.get("pgid_argv") {
            match f._type.as_ref() {
                "user" | "placeholder" => {
                    parser_func.line(
                        "let pgid_argv = if let Ok(pgid_id) = fields[5].parse::<u32>() {
                    self.argv_cache.get(&pgid_id)
                } else {
                    \"-3\".to_string()
                };",
                    );
                }
                _ => {}
            }
        }
        // Add ppid_argv
        if let Some(f) = v.fields.get("ppid_argv") {
            match f._type.as_ref() {
                "user" | "placeholder" => {
                    parser_func.line(
                        "let ppid_argv = if let Ok(ppid) = fields[4].parse::<u32>() {
                    self.argv_cache.get(&ppid)
                } else {
                    \"-3\".to_string()
                };",
                    );
                }
                _ => {}
            }
        }
        // Add socket_argv
        if let Some(f) = v.fields.get("socket_argv") {
            match f._type.as_ref() {
                "user" | "placeholder" => {
                    parser_func.line(format!(
                        "let socket_argv = if let Ok(socket_pid) = fields[{}].parse::<u32>() {{
                    self.argv_cache.get(&socket_pid)
                }} else {{
                    \"-3\".to_string()
                }};",
                        v.fields.get("socket_pid").unwrap().index,
                    ));
                }
                _ => {}
            }
        }
        // Add send func
        parser_func.line(format!("self.sender.send(&{} {{", k.to_camel_case()));
        // Add data struct
        for (i, j) in v.fields.iter() {
            match j._type.as_str() {
                "kernel" => {
                    parser_func.line(format!("{}:fields[{}],", i, j.index));
                }
                "placeholder" | "user" => {
                    parser_func.line(format!("{}:&{},", i, i));
                }
                _ => {}
            }
        }
        parser_func.line("})},");
    }

    // Unsupported type
    parser_func
        .line("_ => {")
        .line("warn!(\"Datatype does not support:{:?}\", fields);")
        .line("Ok(())}");
    parser_func.line("}");
    scope.push_impl(parser_impl);
    // Write to file
    fs::write(
        PARSER_PATH,
        format!(
            "// Code generated by build.rs DO NOT EDIT.\n// VERSION: {}\n// Maintainers: {:?}\n{}",
            content.metadata.version,
            content.metadata.maintainers,
            scope.to_string()
        ),
    )
    .unwrap();
    // Format file
    std::process::Command::new("rustfmt")
        .arg("--edition")
        .arg("2018")
        .arg(PARSER_PATH)
        .spawn()
        .unwrap();
}
fn generate_config(content: &mut Template) {
    let mut scope = String::new();
    scope.push_str(&format!(
        "pub const KO_URL: &[&str] = &{:?};\n",
        content.config.ko_url
    ));
    scope.push_str(&format!(
        "pub const NAME: &str = \"{}\";\n",
        content.config.name
    ));
    scope.push_str(&format!(
        "pub const PIPE_PATH: &str = \"{}\";\n",
        content.config.pipe_path
    ));
    scope.push_str(&format!(
        "pub const SOCKET_PATH: &str = \"{}\";\n",
        content.config.socket_path
    ));
    scope.push_str(&format!(
        "pub const VERSION: &str = \"{}\";\n",
        content.metadata.version
    ));
    // Write to file
    fs::write(
        CONFIG_PATH,
        format!(
            "// Code generated by build.rs DO NOT EDIT.\n// VERSION: {}\n// Maintainers: {:?}\n{}",
            content.metadata.version,
            content.metadata.maintainers,
            scope.to_string()
        ),
    )
    .unwrap();
    // Format file
    std::process::Command::new("rustfmt")
        .arg("--edition")
        .arg("2018")
        .arg(CONFIG_PATH)
        .spawn()
        .unwrap();
}
fn main() {
    println!("cargo:rerun-if-changed=template.toml");
    let template = fs::read_to_string("template.toml").unwrap();
    let mut content: Template = toml::from_str(&template).unwrap();
    generate_parser(&mut content);
    generate_config(&mut content);
}
