.PHONY: all circuits compile-circuits test-circuits verify-circuit-artifacts copy-circuit-artifacts \
       build-ios sync-ios-bindings gen-srs clean \
       fmt fmt-check lint score benchmark spec-check bench-report bench-size bench-execute bench-prove-verify bench-update-baseline \
       install-hooks release-patch release-minor release-major

CIRCUIT_DIR = circuits
MOPRO_DIR = mopro-binding
MOPRO_IOS_BINDINGS_DIR = $(MOPRO_DIR)/MoproiOSBindings
SWIFT_PACKAGE_BINDINGS_DIR = Sources/MoproiOSBindings
CIRCUIT_PACKAGES = passport_verifier data_integrity disclosure prepare_link show_link passport_adapter openac_show device_binding sdjwt_adapter jwt_x5c_adapter x509_show composite_show
IOS_ARCHS ?= aarch64-apple-ios,aarch64-apple-ios-sim

# ──────────────────────────────────────────────────
# Build (lint gate enforced)
# ──────────────────────────────────────────────────

# Build everything (lint → compile → test → iOS)
all: lint circuits build-ios

# Compile all Noir circuits (format check first)
circuits: fmt-check compile-circuits test-circuits

compile-circuits:
	cd $(CIRCUIT_DIR) && nargo compile --workspace

test-circuits:
	cd $(CIRCUIT_DIR) && nargo test --workspace

verify-circuit-artifacts:
	@for pkg in $(CIRCUIT_PACKAGES); do \
		if [ ! -f "$(CIRCUIT_DIR)/target/$$pkg.json" ]; then \
			echo "Missing compiled circuit artifact: $(CIRCUIT_DIR)/target/$$pkg.json"; \
			exit 1; \
		fi; \
	done
	@echo "Verified compiled circuit artifacts: $(CIRCUIT_PACKAGES)"

copy-circuit-artifacts: verify-circuit-artifacts
	@echo "Copying compiled circuits to mopro test-vectors..."
	mkdir -p $(MOPRO_DIR)/test-vectors/noir
	@for pkg in $(CIRCUIT_PACKAGES); do \
		cp "$(CIRCUIT_DIR)/target/$$pkg.json" "$(MOPRO_DIR)/test-vectors/noir/"; \
	done

# Build iOS Swift bindings via mopro
build-ios: circuits copy-circuit-artifacts
	@echo "Building iOS bindings..."
	cd $(MOPRO_DIR) && IOS_ARCHS="$(IOS_ARCHS)" IPHONEOS_DEPLOYMENT_TARGET=15.0 CONFIGURATION=release cargo run --bin ios
	@$(MAKE) sync-ios-bindings

sync-ios-bindings:
	@if [ ! -d "$(MOPRO_IOS_BINDINGS_DIR)" ]; then \
		echo "Missing $(MOPRO_IOS_BINDINGS_DIR). Run 'make build-ios' first."; \
		exit 1; \
	fi
	@echo "Syncing iOS bindings into Swift Package Sources..."
	rm -rf $(SWIFT_PACKAGE_BINDINGS_DIR)
	mkdir -p Sources
	cp -R $(MOPRO_IOS_BINDINGS_DIR) $(SWIFT_PACKAGE_BINDINGS_DIR)
	./scripts/patch_mopro_fallback.sh $(SWIFT_PACKAGE_BINDINGS_DIR)/mopro.swift

# Generate bundled SRS for every compiled circuit (internet required on first run).
# Output goes to mopro-binding/test-vectors/srs/*.srs.bin so the iOS xcframework
# build can bundle them alongside the circuit JSONs.
gen-srs: copy-circuit-artifacts
	@echo "Generating SRS for compiled circuits..."
	cd $(MOPRO_DIR) && cargo run --bin gen_srs --release -- \
		--circuits-dir test-vectors/noir \
		--out-dir test-vectors/srs

# ──────────────────────────────────────────────────
# Format & Lint
# ──────────────────────────────────────────────────

# Auto-format all Noir files
fmt:
	cd $(CIRCUIT_DIR) && nargo fmt --workspace

# Check formatting (fails if unformatted)
fmt-check:
	@echo "Checking Noir formatting..."
	@cd $(CIRCUIT_DIR) && nargo fmt --check --workspace

# Full lint: format + 9-dimension quality score (must pass ≥ C)
lint: fmt-check
	@./benchmark/scripts/circuit-lint.sh .

# Score only (no format gate, informational)
score:
	@./benchmark/scripts/circuit-lint.sh .

# ──────────────────────────────────────────────────
# Benchmark
# ──────────────────────────────────────────────────

# Full benchmark pipeline
benchmark:
	@./benchmark/scripts/run-all.sh

# Spec compliance check only
spec-check:
	@./benchmark/scripts/spec-check.sh .
	@./benchmark/scripts/cross-circuit-check.sh .
	@./benchmark/scripts/cross-layer-check.sh .

# Performance metrics only (assumes compiled)
bench-report:
	@./benchmark/scripts/perf-bench.sh . benchmark/reports/benchmark-$$(date +%Y%m%d-%H%M%S).json

# Size analysis
bench-size:
	@./benchmark/scripts/size-bench.sh .

# Witness generation time per circuit (lower bound for prove time).
# For real prove + verify time, see `make bench-prove-verify`.
bench-execute:
	@mkdir -p benchmark/reports
	@./benchmark/scripts/execute-bench.sh . benchmark/reports/execute-bench-$$(date +%Y%m%d-%H%M%S).json

# Real prove + verify time via mopro-binding cargo bench tests.
# Currently only `disclosure` has a complete bench in `mopro-binding/src/noir.rs`
# (see PERF-1, PERF-4, PERF-5, PERF-7). Other circuits await test vectors.
# First run is slow because cargo must build mopro-binding (~10 min).
bench-prove-verify:
	@echo "Running mopro-binding cargo bench (release; first run ~10 min)..."
	@cd $(MOPRO_DIR) && cargo test --release -- --ignored --nocapture bench_

# Update baseline
bench-update-baseline:
	@echo "Updating baseline from latest benchmark..."
	@cp benchmark/reports/benchmark-latest.json benchmark/expected/latest-snapshot.json
	@echo "Snapshot saved. Manually update baseline.toml with new values."

# ──────────────────────────────────────────────────
# Release (auto-version + tag)
# ──────────────────────────────────────────────────

# Usage: make release-patch  (v0.1.0 → v0.1.1)
#        make release-minor  (v0.1.0 → v0.2.0)
#        make release-major  (v0.1.0 → v1.0.0)
release-patch: lint
	@./scripts/release.sh patch

release-minor: lint
	@./scripts/release.sh minor

release-major: lint
	@./scripts/release.sh major

# ──────────────────────────────────────────────────
# Git Hooks
# ──────────────────────────────────────────────────

install-hooks:
	@echo "Installing git hooks..."
	@cp scripts/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed."

# ──────────────────────────────────────────────────
# Clean
# ──────────────────────────────────────────────────

clean:
	cd $(CIRCUIT_DIR) && rm -rf target
	cd $(MOPRO_DIR) && cargo clean
	rm -rf $(MOPRO_IOS_BINDINGS_DIR)
	rm -rf $(SWIFT_PACKAGE_BINDINGS_DIR)
