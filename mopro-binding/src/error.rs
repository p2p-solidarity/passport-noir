#[derive(Debug, thiserror::Error)]
pub enum MoproError {
    #[error("Circuit error: {0}")]
    CircuitError(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),

    #[error("Verification failed: {0}")]
    VerificationError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
