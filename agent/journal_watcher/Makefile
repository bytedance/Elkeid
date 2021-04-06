un:
	cargo run --release
run-musl:
	cargo run --release --target x86_64-unknown-linux-musl
build:
	cargo build --release
build-musl:
	cargo build --release --target x86_64-unknown-linux-musl
	upx target/x86_64-unknown-linux-musl/release/journal_watcher
clean:
	cargo clean
