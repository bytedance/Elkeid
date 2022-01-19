fn main() {
    protobuf_codegen_pure::Codegen::new()
        .out_dir("src")
        .inputs(&["../bridge.proto"])
        .include("../")
        .run()
        .expect("Codegen failed.");
}
