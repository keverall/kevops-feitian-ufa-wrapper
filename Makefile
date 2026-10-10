# =============================================================================
# KevOps Feitian UFA Wrapper - Makefile
# =============================================================================
# Common Rust development and CI tasks for local and offline use.
#
# Quick start:
#   make check            # Run the required local quality gates
#   make test             # Run unit, integration, and documentation tests
#   make ci               # Run the full quality gate including optional tools
#   make run              # Derive the vault key from the connected device
#   make enroll PIN=<pin> # Enrol or replace the vault credential
#
# Optional tools (taplo, cargo-audit) skip locally and fail with STRICT=1:
#   make STRICT=1 ci
# =============================================================================

# ─── Configuration ───────────────────────────────────────────────────────────
CARGO  ?= cargo
STRICT ?= 0

.DEFAULT_GOAL := ci
.SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# guarded <tool> <command...> <install-hint>
# Runs <command> when <tool> is on PATH. Missing tools skip the step with an
# install hint on stderr, unless STRICT=1 turns the skip into a hard failure.
guarded = \
	if command -v $(1) >/dev/null 2>&1; then $(2); \
	elif [ "$(STRICT)" = "1" ]; then \
		echo "error: $(1) not found - install with: $(3)" >&2; exit 1; \
	else \
		echo "skip: $(1) not found - install with: $(3)" >&2; \
	fi

.PHONY: help build release fmt fmt-rust fmt-toml fmt-check fmt-check-rust \
	fmt-check-toml toml-lint lint-rust lint test audit doc check ci run enroll \
	clean

# ─── Help ────────────────────────────────────────────────────────────────────

help: ## List the available targets
	@echo "Targets:"
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/^([a-z-]+):.*## /\1  -  /'

# ─── Build ───────────────────────────────────────────────────────────────────

build: ## Build the library and binary in debug mode
	$(CARGO) build --all-targets --locked

release: ## Build the stripped, optimized release artifact
	$(CARGO) build --release --locked

# ─── Formatting ──────────────────────────────────────────────────────────────

fmt: fmt-rust fmt-toml ## Format all Rust and TOML sources in place

fmt-rust: ## Format Rust sources with rustfmt
	$(CARGO) fmt --all

fmt-toml: ## Format TOML sources with taplo (optional)
	@$(call guarded,taplo,taplo fmt,cargo install taplo-cli --locked)

fmt-check: fmt-check-rust fmt-check-toml ## Verify all sources are formatted

fmt-check-rust: ## Fail when Rust sources are not formatted
	$(CARGO) fmt --all --check

fmt-check-toml: ## Verify TOML formatting with taplo (optional)
	@$(call guarded,taplo,taplo fmt --check,cargo install taplo-cli --locked)

toml-lint: ## Lint TOML syntax and style with taplo (optional)
	@$(call guarded,taplo,taplo lint --config .taplo.toml,cargo install taplo-cli --locked)

# ─── Lint and documentation ───────────────────────────────────────────────────

lint-rust: ## Lint Rust with Clippy, warnings denied
	$(CARGO) clippy --all-targets --locked -- -D warnings

doc: ## Build rustdoc, warnings denied
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --locked --no-deps --document-private-items

lint: fmt-check lint-rust doc ## Run formatting, lint, and documentation checks

# ─── Tests and security ───────────────────────────────────────────────────────

test: ## Run unit, integration, and documentation tests
	$(CARGO) test --all-targets --locked
	$(CARGO) test --doc --locked

audit: ## Scan dependencies for advisories with cargo-audit (optional)
	@$(call guarded,cargo-audit,$(CARGO) audit --deny warnings,cargo install cargo-audit --locked)

# Required local gate: every available check must pass, optional tools excluded.
check: fmt-check lint-rust test doc ## Run the required local quality gates
	@echo "check: all gates green"

# Full CI gate: required checks plus the optional TOML and supply-chain gates.
# STRICT=1 makes a missing optional tool a failure instead of a skip.
ci: check toml-lint audit ## Run the full CI quality gate
	@echo "ci: all gates green"

# ─── Device operations ────────────────────────────────────────────────────────

run: ## Derive the vault key using the connected authenticator
	$(CARGO) run --quiet --locked --

enroll: ## Enrol or replace the vault credential; requires PIN=<pin>
	@test -n "$(PIN)" || (echo "usage: make enroll PIN=<pin>" >&2; exit 2)
	$(CARGO) run --quiet --locked -- enroll --pin "$(PIN)"

# ─── Cleanup ──────────────────────────────────────────────────────────────────

clean: ## Remove Cargo build artifacts
	$(CARGO) clean
