plugin:
	cargo build --bin elkeid_rasp_monitor --release
plugin-musl:
	cargo build --bin elkeid_rasp_monitor --release --target x86_64-unknown-linux-musl
bin:
	cargo build --bin elkeid_rasp_monitor --release --features=debug
bin-musl:
	cargo build --bin elkeid_rasp_monitor --release --target x86_64-unknown-linux-musl --features=debug
clean:
	cargo clean
debug:
	cargo build --bin elkeid_rasp_monitor --features=debug
debug-musl:
	cargo build --bin elkeid_rasp_monitor --target x86_64-unknown-linux-musl --features=debug


