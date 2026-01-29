.PHONY: build test run clean

build:
	cargo build

test:
	cargo test

run:
	cargo run

clean:
	cargo clean

fmt:
	cargo fmt

check:
	cargo check

doc:
	cargo doc --open

clippy:
	cargo clippy