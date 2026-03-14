use crate::error::MoproError;
use std::collections::HashMap;

/// Generate a Noir proof for a given circuit.
///
/// # Arguments
/// * `circuit_path` - Path to the compiled circuit JSON (e.g., passport_verifier.json)
/// * `srs_path` - Optional path to the SRS file for faster proving
/// * `inputs` - Map of input name → list of string values
///
/// # Returns
/// A tuple of (proof_bytes, public_inputs_bytes)
pub fn generate_noir_proof(
    circuit_path: String,
    srs_path: Option<String>,
    inputs: HashMap<String, Vec<String>>,
) -> Result<(Vec<u8>, Vec<u8>), MoproError> {
    let proof = noir_rs::prove(
        circuit_path.clone(),
        srs_path,
        inputs,
    )
    .map_err(|e| MoproError::ProofGenerationError(format!("{e}")))?;

    Ok(proof)
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
    let vk = noir_rs::get_verification_key(circuit_path, srs_path)
        .map_err(|e| MoproError::CircuitError(format!("{e}")))?;

    Ok(vk)
}

/// Verify a Noir proof.
///
/// # Arguments
/// * `circuit_path` - Path to the compiled circuit JSON
/// * `srs_path` - Optional path to the SRS file
/// * `proof` - The proof bytes to verify
/// * `public_inputs` - The public inputs bytes
///
/// # Returns
/// True if the proof is valid
pub fn verify_noir_proof(
    circuit_path: String,
    srs_path: Option<String>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, MoproError> {
    let is_valid = noir_rs::verify(circuit_path, srs_path, proof, public_inputs)
        .map_err(|e| MoproError::VerificationError(format!("{e}")))?;

    Ok(is_valid)
}
