use crate::error::MoproError;
use std::collections::HashMap;

use noir_rs::native_types::WitnessMap;
use noir_rs::FieldElement;

/// Load circuit bytecode from a compiled Noir circuit JSON file.
fn load_circuit_bytecode(circuit_path: &str) -> Result<String, MoproError> {
    let json_str = std::fs::read_to_string(circuit_path)
        .map_err(|e| MoproError::CircuitError(format!("Failed to read circuit file: {e}")))?;
    let json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| MoproError::CircuitError(format!("Failed to parse circuit JSON: {e}")))?;
    json["bytecode"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| MoproError::CircuitError("Circuit JSON missing 'bytecode' field".into()))
}

/// Convert named inputs (HashMap<String, Vec<String>>) to a flat WitnessMap.
///
/// The circuit ABI defines the order of inputs. For now, we use the ABI from
/// the compiled circuit JSON to map named inputs to witness indices.
fn build_witness_map(
    circuit_path: &str,
    inputs: HashMap<String, Vec<String>>,
) -> Result<WitnessMap<FieldElement>, MoproError> {
    let json_str = std::fs::read_to_string(circuit_path)
        .map_err(|e| MoproError::InvalidInput(format!("Failed to read circuit file: {e}")))?;
    let json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| MoproError::InvalidInput(format!("Failed to parse circuit JSON: {e}")))?;

    // Extract ABI parameters to determine witness ordering
    let abi = json.get("abi").ok_or_else(|| {
        MoproError::InvalidInput("Circuit JSON missing 'abi' field".into())
    })?;
    let params = abi
        .get("parameters")
        .and_then(|p| p.as_array())
        .ok_or_else(|| {
            MoproError::InvalidInput("Circuit ABI missing 'parameters' array".into())
        })?;

    let mut witness_map = WitnessMap::new();
    let mut witness_idx: u32 = 0;

    // Map each ABI parameter to sequential witness indices
    for param in params {
        let name = param
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| {
                MoproError::InvalidInput("ABI parameter missing 'name'".into())
            })?;

        if let Some(values) = inputs.get(name) {
            for val_str in values {
                let field = FieldElement::try_from_str(val_str).ok_or_else(|| {
                    MoproError::InvalidInput(format!(
                        "Cannot parse '{val_str}' as field element for input '{name}'"
                    ))
                })?;
                witness_map.insert(
                    noir_rs::native_types::Witness(witness_idx),
                    field,
                );
                witness_idx += 1;
            }
        } else {
            // Count expected witness slots from the ABI type and skip
            let count = count_abi_witnesses(param.get("type"));
            witness_idx += count;
        }
    }

    Ok(witness_map)
}

/// Count the number of witness elements an ABI type occupies.
fn count_abi_witnesses(typ: Option<&serde_json::Value>) -> u32 {
    match typ {
        Some(t) => {
            if let Some(kind) = t.get("kind").and_then(|k| k.as_str()) {
                match kind {
                    "field" | "integer" | "boolean" => 1,
                    "array" => {
                        let len = t
                            .get("length")
                            .and_then(|l| l.as_u64())
                            .unwrap_or(1) as u32;
                        let inner = count_abi_witnesses(t.get("type"));
                        len * inner
                    }
                    _ => 1,
                }
            } else {
                1
            }
        }
        None => 1,
    }
}

/// Generate a Noir proof for a given circuit.
///
/// # Arguments
/// * `circuit_path` - Path to the compiled circuit JSON (e.g., disclosure.json)
/// * `srs_path` - Optional path to the SRS file for faster proving
/// * `inputs` - Map of input name -> list of string values
///
/// # Returns
/// A tuple of (proof_bytes, verification_key_bytes)
pub fn generate_noir_proof(
    circuit_path: String,
    srs_path: Option<String>,
    inputs: HashMap<String, Vec<String>>,
) -> Result<(Vec<u8>, Vec<u8>), MoproError> {
    let bytecode = load_circuit_bytecode(&circuit_path)?;

    // Setup SRS (downloads or loads from file)
    noir_rs::barretenberg::srs::setup_srs_from_bytecode(
        &bytecode,
        srs_path.as_deref(),
        false,
    )
    .map_err(|e| MoproError::CircuitError(format!("SRS setup failed: {e}")))?;

    // Build witness map from named inputs
    let witness_map = build_witness_map(&circuit_path, inputs)?;

    // Get verification key
    let vk = noir_rs::barretenberg::verify::get_ultra_honk_verification_key(&bytecode, false)
        .map_err(|e| MoproError::CircuitError(format!("Failed to get VK: {e}")))?;

    // Generate proof
    let proof = noir_rs::barretenberg::prove::prove_ultra_honk(
        &bytecode,
        witness_map,
        vk.clone(),
        false,
    )
    .map_err(|e| MoproError::ProofGenerationError(format!("{e}")))?;

    Ok((proof, vk))
}

/// Get the verification key for a Noir circuit.
///
/// # Arguments
/// * `circuit_path` - Path to the compiled circuit JSON
/// * `srs_path` - Optional path to the SRS file
///
/// # Returns
/// The verification key bytes
pub fn get_noir_verification_key(
    circuit_path: String,
    srs_path: Option<String>,
) -> Result<Vec<u8>, MoproError> {
    let bytecode = load_circuit_bytecode(&circuit_path)?;

    noir_rs::barretenberg::srs::setup_srs_from_bytecode(
        &bytecode,
        srs_path.as_deref(),
        false,
    )
    .map_err(|e| MoproError::CircuitError(format!("SRS setup failed: {e}")))?;

    let vk = noir_rs::barretenberg::verify::get_ultra_honk_verification_key(&bytecode, false)
        .map_err(|e| MoproError::CircuitError(format!("{e}")))?;

    Ok(vk)
}

/// Verify a Noir proof.
///
/// # Arguments
/// * `proof` - The proof bytes to verify
/// * `vk` - The verification key bytes
///
/// # Returns
/// True if the proof is valid
pub fn verify_noir_proof(
    proof: Vec<u8>,
    vk: Vec<u8>,
) -> Result<bool, MoproError> {
    let is_valid = noir_rs::barretenberg::verify::verify_ultra_honk(proof, vk)
        .map_err(|e| MoproError::VerificationError(format!("{e}")))?;

    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn test_vectors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/noir")
    }

    fn circuit_path(name: &str) -> String {
        let path = test_vectors_dir().join(format!("{name}.json"));
        if !path.exists() {
            panic!(
                "Circuit JSON not found at {:?}. Run `cd ../circuits && nargo compile --workspace` \
                 then `cp circuits/target/*.json mopro-binding/test-vectors/noir/`",
                path
            );
        }
        path.to_string_lossy().to_string()
    }

    fn has_test_vectors() -> bool {
        test_vectors_dir().join("disclosure.json").exists()
    }

    // Build minimal valid inputs for the disclosure circuit (smallest, 65KB)
    fn disclosure_test_inputs() -> HashMap<String, Vec<String>> {
        let mut inputs = HashMap::new();

        // MRZ data: 88 bytes, all '<' (ASCII 60) with some fields set
        let mut mrz = vec![60u8; 88];
        mrz[0] = 80; // P
        mrz[1] = 60; // <
        mrz[2] = 85; mrz[3] = 84; mrz[4] = 79; // UTO
        // Name at 5..43: DOE<<JOHN
        mrz[5] = 68; mrz[6] = 79; mrz[7] = 69; // DOE
        mrz[8] = 60; mrz[9] = 60; // <<
        mrz[10] = 74; mrz[11] = 79; mrz[12] = 72; mrz[13] = 78; // JOHN
        // Nationality at 54..56: UTO
        mrz[54] = 85; mrz[55] = 84; mrz[56] = 79;
        // DOB at 57..62: 900101
        mrz[57] = 57; mrz[58] = 48; mrz[59] = 48;
        mrz[60] = 49; mrz[61] = 48; mrz[62] = 49;

        inputs.insert(
            "mrz_data".to_string(),
            mrz.iter().map(|b| format!("0x{:02x}", b)).collect(),
        );

        let hash = sha256_of(&mrz);
        inputs.insert(
            "mrz_hash".to_string(),
            hash.iter().map(|b| format!("0x{:02x}", b)).collect(),
        );

        // Disclosure flags
        inputs.insert("disclose_nationality".to_string(), vec!["1".to_string()]);
        inputs.insert("disclose_older_than".to_string(), vec!["0".to_string()]);
        inputs.insert("disclose_name".to_string(), vec!["0".to_string()]);
        inputs.insert("age_threshold".to_string(), vec!["0x12".to_string()]); // 18

        // Current date "260314" as ASCII
        inputs.insert(
            "current_date".to_string(),
            vec!["0x32", "0x36", "0x30", "0x33", "0x31", "0x34"]
                .iter().map(|s| s.to_string()).collect(),
        );

        // Expected outputs
        inputs.insert(
            "out_nationality".to_string(),
            vec!["0x55", "0x54", "0x4f"] // UTO
                .iter().map(|s| s.to_string()).collect(),
        );
        inputs.insert(
            "out_name".to_string(),
            vec!["0x00".to_string(); 39],
        );
        inputs.insert("out_is_older".to_string(), vec!["0".to_string()]);

        inputs
    }

    // SHA-256 using system shasum for test vector generation
    fn sha256_of(data: &[u8]) -> [u8; 32] {
        use std::process::Command;
        let mut child = Command::new("shasum")
            .args(["-a", "256"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("Failed to run shasum");

        child.stdin.as_mut().unwrap().write_all(data).unwrap();
        let output = child.wait_with_output().unwrap();
        let hex_str = String::from_utf8(output.stdout).unwrap();
        let hex = hex_str.trim().split_whitespace().next().unwrap();

        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap();
        }
        result
    }

    // ===== Functional Tests =====

    // MP-1: Generate proof for disclosure circuit (smallest)
    #[test]
    #[ignore] // Requires compiled circuit JSONs
    fn test_generate_proof_disclosure() {
        if !has_test_vectors() {
            eprintln!("SKIP: test vectors not found. Run `make circuits` first.");
            return;
        }
        let path = circuit_path("disclosure");
        let inputs = disclosure_test_inputs();

        let result = generate_noir_proof(path, None, inputs);
        match &result {
            Ok((proof, vk)) => {
                println!("MP-1 PASS: proof={} bytes, vk={} bytes",
                    proof.len(), vk.len());
                assert!(!proof.is_empty(), "Proof should not be empty");
                assert!(!vk.is_empty(), "VK should not be empty");
            }
            Err(e) => panic!("MP-1 FAIL: proof generation failed: {e}"),
        }
    }

    // MP-2: Generate and verify proof roundtrip
    #[test]
    #[ignore]
    fn test_verify_proof_disclosure() {
        if !has_test_vectors() { return; }
        let path = circuit_path("disclosure");
        let inputs = disclosure_test_inputs();

        let (proof, vk) = generate_noir_proof(path, None, inputs)
            .expect("Proof generation should succeed");

        let is_valid = verify_noir_proof(proof, vk)
            .expect("Verification should not error");
        assert!(is_valid, "MP-2: Valid proof should verify successfully");
    }

    // MP-3: Tampered proof should fail verification
    #[test]
    #[ignore]
    fn test_verify_tampered_proof_fails() {
        if !has_test_vectors() { return; }
        let path = circuit_path("disclosure");
        let inputs = disclosure_test_inputs();

        let (mut proof, vk) = generate_noir_proof(path, None, inputs)
            .expect("Proof generation should succeed");

        // Tamper the proof
        if !proof.is_empty() {
            proof[0] ^= 0xFF;
        }

        let result = verify_noir_proof(proof, vk);
        match result {
            Ok(false) => println!("MP-3 PASS: tampered proof correctly rejected"),
            Err(_) => println!("MP-3 PASS: tampered proof caused verification error"),
            Ok(true) => panic!("MP-3 FAIL: tampered proof should NOT verify"),
        }
    }

    // MP-4: Get verification key
    #[test]
    #[ignore]
    fn test_get_verification_key() {
        if !has_test_vectors() { return; }
        let path = circuit_path("disclosure");

        let vk = get_noir_verification_key(path, None)
            .expect("Should get verification key");
        assert!(!vk.is_empty(), "MP-4: VK should not be empty");
        println!("MP-4 PASS: VK size = {} bytes", vk.len());
    }

    // MP-5: Invalid circuit path
    #[test]
    fn test_invalid_circuit_path() {
        let result = generate_noir_proof(
            "/nonexistent/circuit.json".to_string(),
            None,
            HashMap::new(),
        );
        assert!(result.is_err(), "MP-5: Should error on invalid path");
        println!("MP-5 PASS: {:?}", result.unwrap_err());
    }

    // MP-6: Invalid input names
    #[test]
    #[ignore]
    fn test_invalid_input_names() {
        if !has_test_vectors() { return; }
        let path = circuit_path("disclosure");

        let mut bad_inputs = HashMap::new();
        bad_inputs.insert("nonexistent_field".to_string(), vec!["42".to_string()]);

        let result = generate_noir_proof(path, None, bad_inputs);
        assert!(result.is_err(), "MP-6: Should error on invalid input names");
    }

    // MP-7: Proof roundtrip for all three circuits
    #[test]
    #[ignore]
    fn test_proof_roundtrip_all_circuits() {
        if !has_test_vectors() { return; }

        // Only test disclosure for now (smallest circuit, fastest prove)
        let circuits = ["disclosure"];
        for name in circuits {
            let path = circuit_path(name);
            let inputs = if name == "disclosure" {
                disclosure_test_inputs()
            } else {
                // TODO: Build proper inputs for passport_verifier and data_integrity
                continue;
            };

            let (proof, vk) = generate_noir_proof(path, None, inputs)
                .unwrap_or_else(|e| panic!("MP-7: {name} prove failed: {e}"));

            let is_valid = verify_noir_proof(proof, vk)
                .unwrap_or_else(|e| panic!("MP-7: {name} verify failed: {e}"));

            assert!(is_valid, "MP-7: {name} roundtrip should pass");
            println!("MP-7: {name} roundtrip OK");
        }
    }

    // MP-8: Proof bytes are non-trivial
    #[test]
    #[ignore]
    fn test_proof_serialization_format() {
        if !has_test_vectors() { return; }
        let path = circuit_path("disclosure");
        let inputs = disclosure_test_inputs();

        let (proof, vk) = generate_noir_proof(path, None, inputs)
            .expect("Should generate proof");

        // Proof should be non-trivial (not all zeros)
        let all_zero = proof.iter().all(|&b| b == 0);
        assert!(!all_zero, "MP-8: Proof should not be all zeros");
        println!("MP-8: proof={} bytes, vk={} bytes", proof.len(), vk.len());
    }

    // ===== Performance Benchmarks =====

    // PERF-1: Disclosure circuit prove time (smallest - baseline)
    #[test]
    #[ignore]
    fn bench_prove_disclosure() {
        if !has_test_vectors() { return; }
        let path = circuit_path("disclosure");
        let inputs = disclosure_test_inputs();

        let start = std::time::Instant::now();
        let result = generate_noir_proof(path, None, inputs);
        let elapsed = start.elapsed();

        println!("PERF-1: disclosure prove time: {:?}", elapsed);
        assert!(result.is_ok(), "Proof should succeed");
        assert!(elapsed.as_secs() < 60, "Disclosure proving took too long: {:?}", elapsed);
    }

    // PERF-4: Verification time for disclosure
    #[test]
    #[ignore]
    fn bench_verify_disclosure() {
        if !has_test_vectors() { return; }
        let path = circuit_path("disclosure");
        let inputs = disclosure_test_inputs();

        let (proof, vk) = generate_noir_proof(path, None, inputs)
            .expect("Prove should succeed");

        let start = std::time::Instant::now();
        let is_valid = verify_noir_proof(proof, vk)
            .expect("Verify should not error");
        let elapsed = start.elapsed();

        println!("PERF-4: disclosure verify time: {:?}", elapsed);
        assert!(is_valid);
        assert!(elapsed.as_secs() < 5, "Verification took too long: {:?}", elapsed);
    }

    // PERF-5: Proof size measurement
    #[test]
    #[ignore]
    fn bench_proof_size_bytes() {
        if !has_test_vectors() { return; }
        let path = circuit_path("disclosure");
        let inputs = disclosure_test_inputs();

        let (proof, vk) = generate_noir_proof(path, None, inputs)
            .expect("Prove should succeed");

        println!("PERF-5: disclosure proof_size={} bytes, vk_size={} bytes",
            proof.len(), vk.len());
    }

    // PERF-7: Memory usage (approximate via resident set)
    #[test]
    #[ignore]
    fn bench_memory_usage() {
        if !has_test_vectors() { return; }

        let before = get_rss_mb();
        let path = circuit_path("disclosure");
        let inputs = disclosure_test_inputs();

        let _ = generate_noir_proof(path, None, inputs);

        let after = get_rss_mb();
        println!("PERF-7: RSS before={}MB, after={}MB, delta={}MB", before, after, after - before);
        assert!(after < 2048, "Memory usage exceeded 2GB: {}MB", after);
    }

    fn get_rss_mb() -> usize {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok();
        output
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<usize>().ok())
            .map(|kb| kb / 1024)
            .unwrap_or(0)
    }
}
