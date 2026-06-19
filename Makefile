# Vex — common dev tasks. `make` or `make check` before pushing.

VERSION := $(shell grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)

.PHONY: all check fmt lint test build clean bump tag help

all: check

## check: format check + clippy + tests (mirrors CI — run before pushing)
check:
	cargo fmt -- --check
	cargo clippy -- -D warnings
	cargo test

## fmt: apply rustfmt
fmt:
	cargo fmt

## lint: clippy with warnings as errors
lint:
	cargo clippy -- -D warnings

## test: run the test suite
test:
	cargo test

## build: optimized release binary
build:
	cargo build --release

## clean: cargo clean + remove local runtime artifacts
clean:
	cargo clean
	rm -f vex-audit.log pins.json

## bump: set the crate version, e.g. make bump V=0.2.0 (then commit, then make tag)
bump:
	@test -n "$(V)" || { echo "usage: make bump V=X.Y.Z"; exit 1; }
	@sed -i.bak -E 's/^version = "[^"]*"/version = "$(V)"/' Cargo.toml && rm -f Cargo.toml.bak
	@cargo update --workspace -q 2>/dev/null || cargo check -q
	@echo "bumped to $(V) — commit, then 'make tag'"

## tag: tag v$(VERSION) from Cargo.toml and push it (triggers the release workflow)
tag:
	git tag -a v$(VERSION) -m "vex-mcp v$(VERSION)"
	git push origin v$(VERSION)

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
