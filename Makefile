.PHONY: all circuits compile-circuits test-circuits verify-circuit-artifacts copy-circuit-artifacts build-ios sync-ios-bindings clean benchmark spec-check bench-report bench-update-baseline

CIRCUIT_DIR = circuits
MOPRO_DIR = mopro-binding
MOPRO_IOS_BINDINGS_DIR = $(MOPRO_DIR)/MoproiOSBindings
SWIFT_PACKAGE_BINDINGS_DIR = Sources/MoproiOSBindings
CIRCUIT_PACKAGES = passport_verifier data_integrity disclosure prepare_link show_link
# iOS-only default: real device + Apple Silicon simulator.
# Add x86_64-apple-ios if you need Intel Mac simulator support.
IOS_ARCHS ?= aarch64-apple-ios,aarch64-apple-ios-sim

# Build everything
all: circuits build-ios

# Compile all Noir circuits
circuits: compile-circuits test-circuits

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

# ──────────────────────────────────────────────────
# Benchmark
# ──────────────────────────────────────────────────

# Full benchmark pipeline: TDD → Compile → Spec Check → Test → Metrics
benchmark:
	@./benchmark/scripts/run-all.sh

# Spec compliance check only (no compile/test)
spec-check:
	@./benchmark/scripts/spec-check.sh .
	@./benchmark/scripts/cross-circuit-check.sh .
	@./benchmark/scripts/cross-layer-check.sh .

# Performance metrics only (assumes already compiled)
bench-report:
	@./benchmark/scripts/perf-bench.sh . benchmark/reports/benchmark-$$(date +%Y%m%d-%H%M%S).json

# Update baseline after confirmed improvements
bench-update-baseline:
	@echo "Updating baseline from latest benchmark..."
	@cp benchmark/reports/benchmark-latest.json benchmark/expected/latest-snapshot.json
	@echo "Snapshot saved. Manually update baseline.toml with new values."

# Clean build artifacts
clean:
	cd $(CIRCUIT_DIR) && rm -rf target
	cd $(MOPRO_DIR) && cargo clean
	rm -rf $(MOPRO_IOS_BINDINGS_DIR)
	rm -rf $(SWIFT_PACKAGE_BINDINGS_DIR)
