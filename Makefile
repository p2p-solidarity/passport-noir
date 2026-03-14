.PHONY: all circuits compile-circuits test-circuits build-ios sync-ios-bindings clean

CIRCUIT_DIR = circuits
MOPRO_DIR = mopro-binding
MOPRO_IOS_BINDINGS_DIR = $(MOPRO_DIR)/MoproiOSBindings
SWIFT_PACKAGE_BINDINGS_DIR = Sources/MoproiOSBindings
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

# Build iOS Swift bindings via mopro
build-ios: circuits
	@echo "Copying compiled circuits to mopro test-vectors..."
	mkdir -p $(MOPRO_DIR)/test-vectors/noir
	cp $(CIRCUIT_DIR)/target/passport_verifier.json $(MOPRO_DIR)/test-vectors/noir/ 2>/dev/null || true
	cp $(CIRCUIT_DIR)/target/data_integrity.json $(MOPRO_DIR)/test-vectors/noir/ 2>/dev/null || true
	cp $(CIRCUIT_DIR)/target/disclosure.json $(MOPRO_DIR)/test-vectors/noir/ 2>/dev/null || true
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

# Clean build artifacts
clean:
	cd $(CIRCUIT_DIR) && rm -rf target
	cd $(MOPRO_DIR) && cargo clean
	rm -rf $(MOPRO_IOS_BINDINGS_DIR)
	rm -rf $(SWIFT_PACKAGE_BINDINGS_DIR)
