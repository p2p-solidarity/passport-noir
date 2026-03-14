.PHONY: all circuits compile-circuits test-circuits build-ios clean

CIRCUIT_DIR = circuits
MOPRO_DIR = mopro-binding

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
	cd $(MOPRO_DIR) && CONFIGURATION=release cargo run --bin ios

# Clean build artifacts
clean:
	cd $(CIRCUIT_DIR) && rm -rf target
	cd $(MOPRO_DIR) && cargo clean
