mopro_ffi::app!();

mod error;
pub use error::MoproError;

mod noir;
pub use noir::{generate_noir_proof, get_noir_verification_key, verify_noir_proof};
