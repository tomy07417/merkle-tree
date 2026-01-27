.PHONY: build test run clean

set-up:
	git config core.hooksPath .githooks

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