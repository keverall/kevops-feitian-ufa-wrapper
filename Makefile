# KevOps Feitian UFA wrapper - local quality gates.
#
# `make ci` mirrors .github/workflows/ci.yml, so you can reproduce CI offline.
# Add STRICT=1 to turn "tool missing" into a hard failure instead of a skip.

.DEFAULT_GOAL := ci
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO ?= cargo
PIN   ?= 1234

# guarded <tool> <command...> <install-hint>
# Runs <command> when <tool> is on PATH. Missing tools skip the step with a hint,
# unless STRICT=1 makes it a hard error.
guarded = \
	if command -v $(1) >/dev/null 2>&1; then $(2); \
	elif [ "$${STRICT:-0}" = "1" ]; then echo "error: $(1) not found - install with: $(3)" >&2; exit 1; \
	else echo "skip: $(1) not found - install with: $(3)"; fi

## help: list the available targets
.PHONY: help
help:
	@echo "Targets:" ; grep -hE '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

## build: debug build of the library and binary
.PHONY: build
build:
	$(CARGO) build --all-targets

## release: reproducible, stripped release artifact
.PHONY: release
release:
	$(CARGO) build --release

## fmt: format Rust and TOML sources in place
.PHONY: fmt
fmt: fmt-rust fmt-toml

## fmt-rust: cargo fmt --all
.PHONY: fmt-rust
fmt-rust:
	$(CARGO) fmt --all

## fmt-toml: taplo fmt
.PHONY: fmt-toml
fmt-toml:
	@$(call guarded,taplo,taplo fmt,cargo install taplo-cli --locked)

## fmt-check: fail when formatting is off
.PHONY: fmt-check
fmt-check: fmt-check-rust fmt-check-toml

## fmt-check-rust: cargo fmt --all --check
.PHONY: fmt-check-rust
fmt-check-rust:
	$(CARGO) fmt --all --check

## fmt-check-toml: taplo fmt --check
.PHONY: fmt-check-toml
fmt-check-toml:
	@$(call guarded,taplo,taplo fmt --check,cargo install taplo-cli --locked)

## toml-lint: schema-aware TOML lint
.PHONY: toml-lint
toml-lint:
	@$(call guarded,taplo,taplo lint --config .taplo.toml,cargo install taplo-cli --locked)

## lint-rust: cargo clippy --all-targets -- -D warnings
.PHONY: lint-rust
lint-rust:
	$(CARGO) clippy --all-targets -- -D warnings

## lint: clippy, formatting and documentation gates together
.PHONY: lint
lint: fmt-check lint-rust doc

## test: unit, functional and doc tests
.PHONY: test
test:
	$(CARGO) test --all-targets
	$(CARGO) test --doc

## audit: rustsec vulnerability scan
.PHONY: audit
audit:
	@$(call guarded,cargo-audit,$(CARGO) audit --deny warnings,cargo install cargo-audit --locked)

## udeps: unused dependency scan (nightly)
.PHONY: udeps
udeps:
	@$(call guarded,cargo-udeps,$(CARGO) +nightly udeps --all-targets,cargo install cargo-udeps --locked)

## doc: rustdoc, warnings denied
.PHONY: doc
doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --document-private-items

## ci: the full offline gate
.PHONY: ci
ci: fmt-check toml-lint lint-rust test doc
	@echo "all gates green"

## run: derive the vault key (needs the device)
.PHONY: run
run:
	$(CARGO) run --quiet --

## enroll: register or replace the vault credential (PIN=<pin>)
.PHONY: enroll
enroll:
	$(CARGO) run --quiet -- enroll --pin $(PIN)

## clean: remove build artifacts
.PHONY: clean
clean:
	$(CARGO) clean
