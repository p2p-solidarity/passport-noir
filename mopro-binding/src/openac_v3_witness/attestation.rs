//! Witness-build-time attestation chain.
//!
//! The 0.3.0 circuits verify RSA-2048 PKCS#1 v1.5 signatures over
//! app-normalised layouts (spec/upgrade-plan-v3.1.md sec.7.3: the DSC TBS
//! envelope and the DG1‖DG15 SOD-hash preimage are synthesized layouts, not
//! raw ICAO ASN.1). Real CSCA/DSC keys never signed those layouts, so the
//! builder derives a fresh in-circuit issuance chain per witness request:
//!
//!   attestation CSCA  ──signs──▶  synthetic DSC TBS (embeds the attestation
//!   DSC modulus, the REAL DSC serial, and SHA-256 digests of the REAL DSC
//!   TBS + REAL CSCA TBS as provenance bytes)
//!   attestation DSC   ──signs──▶  normalised sod_hash = SHA256(dg1ₕ ‖ dg15ₕ)
//!
//! Trust in the REAL chain comes from the layers around this one, all
//! fail-closed: native passive authentication against the bundled Master
//! List (request gate), the SOD/DG hash re-verification in `sod.rs`, the
//! Master-List CSCA metadata match, the real-serial revocation SMT, and DG15
//! Active Authentication. The attestation keys exist only for the lifetime
//! of one witness build and are never persisted.

use noir_rs::acir::{AcirField, FieldElement};
use num_bigint_dig::BigUint;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

use super::pedersen;

pub const RSA_LIMB_COUNT: usize = 18;
pub const RSA_MODULUS_BITS: usize = 2048;
pub const DSC_TBS_LEN: usize = 512;
pub const DSC_SERIAL_OFFSET: usize = 352;

const DSC_TBS_PROVENANCE_DOMAIN: &[u8] = b"solidarity.openac.dsc-tbs.v1";

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation-keygen-failed")]
    KeygenFailed,
    #[error("attestation-sign-failed")]
    SignFailed,
}

/// Split a non-negative big integer into 18 little-endian 120-bit limbs
/// (the noir-bignum layout for BigNumParams<18, 2048>).
pub fn limbs_120(value: &BigUint) -> [FieldElement; RSA_LIMB_COUNT] {
    let limbs = noir_bignum_paramgen::split_into_120_bit_limbs(value, RSA_MODULUS_BITS);
    let mut out = [FieldElement::zero(); RSA_LIMB_COUNT];
    for (i, limb) in limbs.iter().enumerate().take(RSA_LIMB_COUNT) {
        out[i] = FieldElement::from_be_bytes_reduce(&limb.to_bytes_be());
    }
    out
}

/// noir-bignum v0.9.2 `BARRETT_REDUCTION_OVERFLOW_BITS` (the circuits pin this
/// tag). noir-bignum-paramgen 0.1.5 still hardcodes the old value of 4, so we
/// compute the parameter directly instead of using its helper — a 4-vs-6
/// mismatch makes the in-circuit `__barrett_reduction` brillig hint
/// unsolvable.
const BARRETT_REDUCTION_OVERFLOW_BITS: usize = 6;

/// Barrett reduction parameter limbs for a 2048-bit modulus, matching the
/// circuit's `BigNumParams<18, 2048>`:
///   redc_param = floor(2^{2 * MOD_BITS + 6} / modulus),  MOD_BITS = 2048.
/// MOD_BITS is the circuit's declared bound, NOT `modulus.bits()` — a real
/// RSA-2048 modulus is exactly 2048 bits so they coincide, but pinning the
/// constant keeps a sub-2048-bit modulus from silently shifting the exponent.
pub fn redc_limbs_120(modulus: &BigUint) -> [FieldElement; RSA_LIMB_COUNT] {
    let exponent = 2 * RSA_MODULUS_BITS + BARRETT_REDUCTION_OVERFLOW_BITS;
    let redc = (BigUint::from(1u8) << exponent) / modulus;
    limbs_120(&redc)
}

fn sign_prehashed_sha256(
    key: &RsaPrivateKey,
    digest32: &[u8; 32],
) -> Result<BigUint, AttestationError> {
    let signature = key
        .sign(Pkcs1v15Sign::new::<Sha256>(), digest32)
        .map_err(|_| AttestationError::SignFailed)?;
    Ok(BigUint::from_bytes_be(&signature))
}

pub struct AttestationChain {
    pub csca_modulus_limbs: [FieldElement; RSA_LIMB_COUNT],
    pub csca_redc_limbs: [FieldElement; RSA_LIMB_COUNT],
    pub dsc_modulus_limbs: [FieldElement; RSA_LIMB_COUNT],
    pub dsc_redc_limbs: [FieldElement; RSA_LIMB_COUNT],
    pub dsc_tbs: [u8; DSC_TBS_LEN],
    pub dsc_cert_sig_limbs: [FieldElement; RSA_LIMB_COUNT],
    /// `compute_dsc_id(dsc_modulus, 65537)` — links dsc_chain ↔ passport core.
    pub dsc_id: FieldElement,
    dsc_key: RsaPrivateKey,
}

impl AttestationChain {
    /// Build the chain from caller-supplied attestation keys. Both keys MUST
    /// be RSA-2048 with e = 65537 (the ICAO profile the circuits pin).
    pub fn build_with_keys(
        csca_key: RsaPrivateKey,
        dsc_key: RsaPrivateKey,
        real_csca_tbs_sha256: &[u8; 32],
        real_dsc_tbs_sha256: &[u8; 32],
        real_dsc_serial20: &[u8; 20],
    ) -> Result<Self, AttestationError> {
        debug_assert_eq!(csca_key.n().bits(), RSA_MODULUS_BITS);
        debug_assert_eq!(dsc_key.n().bits(), RSA_MODULUS_BITS);

        let csca_modulus = csca_key.n().clone();
        let dsc_modulus = dsc_key.n().clone();
        let csca_modulus_limbs = limbs_120(&csca_modulus);
        let csca_redc_limbs = redc_limbs_120(&csca_modulus);
        let dsc_modulus_limbs = limbs_120(&dsc_modulus);
        let dsc_redc_limbs = redc_limbs_120(&dsc_modulus);

        // Synthetic DSC TBS envelope (dsc_chain layout):
        //   [0..288)    modulus limbs, 16-byte BE per 120-bit limb
        //   [288..320)  SHA256(domain ‖ real DSC TBS digest) — provenance
        //   [320..352)  real CSCA TBS digest — provenance
        //   [352..372)  REAL DSC serial (the revocation SMT subject)
        //   [372..512)  zero
        let mut dsc_tbs = [0u8; DSC_TBS_LEN];
        for (i, limb) in dsc_modulus_limbs.iter().enumerate() {
            let be = limb.to_be_bytes();
            // FieldElement BE is 32 bytes; the low 16 carry the 120-bit limb.
            dsc_tbs[i * 16..(i + 1) * 16].copy_from_slice(&be[16..32]);
        }
        let provenance: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(DSC_TBS_PROVENANCE_DOMAIN);
            hasher.update(real_dsc_tbs_sha256);
            hasher.finalize().into()
        };
        dsc_tbs[288..320].copy_from_slice(&provenance);
        dsc_tbs[320..352].copy_from_slice(real_csca_tbs_sha256);
        dsc_tbs[DSC_SERIAL_OFFSET..DSC_SERIAL_OFFSET + 20].copy_from_slice(real_dsc_serial20);

        let tbs_digest: [u8; 32] = Sha256::digest(dsc_tbs).into();
        let dsc_cert_sig = sign_prehashed_sha256(&csca_key, &tbs_digest)?;
        let dsc_cert_sig_limbs = limbs_120(&dsc_cert_sig);

        let dsc_id = pedersen::compute_dsc_id(&dsc_modulus_limbs, 65537);

        Ok(Self {
            csca_modulus_limbs,
            csca_redc_limbs,
            dsc_modulus_limbs,
            dsc_redc_limbs,
            dsc_tbs,
            dsc_cert_sig_limbs,
            dsc_id,
            dsc_key,
        })
    }

    /// Generate fresh attestation keys (used on device; tests inject the
    /// fixture keys to skip the keygen cost).
    pub fn generate(
        real_csca_tbs_sha256: &[u8; 32],
        real_dsc_tbs_sha256: &[u8; 32],
        real_dsc_serial20: &[u8; 20],
    ) -> Result<Self, AttestationError> {
        let mut rng = rand::rngs::OsRng;
        let csca_key = RsaPrivateKey::new(&mut rng, RSA_MODULUS_BITS)
            .map_err(|_| AttestationError::KeygenFailed)?;
        let dsc_key = RsaPrivateKey::new(&mut rng, RSA_MODULUS_BITS)
            .map_err(|_| AttestationError::KeygenFailed)?;
        Self::build_with_keys(
            csca_key,
            dsc_key,
            real_csca_tbs_sha256,
            real_dsc_tbs_sha256,
            real_dsc_serial20,
        )
    }

    /// DSC → SOD signature over the normalised sod_hash.
    pub fn sign_sod_hash(
        &self,
        sod_hash: &[u8; 32],
    ) -> Result<[FieldElement; RSA_LIMB_COUNT], AttestationError> {
        let sig = sign_prehashed_sha256(&self.dsc_key, sod_hash)?;
        Ok(limbs_120(&sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openac_v3_witness::fixtures;
    use rsa::Pkcs1v15Sign;

    fn fixture_chain() -> AttestationChain {
        AttestationChain::build_with_keys(
            fixtures::fixture_csca_key().clone(),
            fixtures::fixture_dsc_key().clone(),
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 20],
        )
        .expect("fixture chain builds")
    }

    #[test]
    fn tbs_embeds_modulus_limbs_and_serial() {
        let chain = fixture_chain();
        // Limb 0 = low 120 bits of the modulus at offset 0, 16-byte BE.
        let limb0_be = chain.dsc_modulus_limbs[0].to_be_bytes();
        assert_eq!(&chain.dsc_tbs[..16], &limb0_be[16..32]);
        assert_eq!(
            chain.dsc_tbs[0], 0,
            "limb top byte must be zero (120-bit limb)"
        );
        assert_eq!(
            &chain.dsc_tbs[DSC_SERIAL_OFFSET..DSC_SERIAL_OFFSET + 20],
            &[0x33; 20]
        );
    }

    #[test]
    fn csca_signature_over_tbs_verifies() {
        let chain = fixture_chain();
        let digest: [u8; 32] = Sha256::digest(chain.dsc_tbs).into();
        // Recompose the signature bytes from limbs and verify with the
        // public key — proves the limb split is value-preserving.
        let mut value = num_bigint_dig::BigUint::from(0u8);
        for limb in chain.dsc_cert_sig_limbs.iter().rev() {
            value = (value << 120) + num_bigint_dig::BigUint::from_bytes_be(&limb.to_be_bytes());
        }
        let mut sig = value.to_bytes_be();
        while sig.len() < 256 {
            sig.insert(0, 0);
        }
        fixtures::fixture_csca_key()
            .to_public_key()
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &sig)
            .expect("CSCA attestation signature verifies");
    }

    #[test]
    fn sod_signature_verifies_under_dsc_key() {
        let chain = fixture_chain();
        let sod_hash = [0x44u8; 32];
        let limbs = chain.sign_sod_hash(&sod_hash).expect("signs");
        let mut value = num_bigint_dig::BigUint::from(0u8);
        for limb in limbs.iter().rev() {
            value = (value << 120) + num_bigint_dig::BigUint::from_bytes_be(&limb.to_be_bytes());
        }
        let mut sig = value.to_bytes_be();
        while sig.len() < 256 {
            sig.insert(0, 0);
        }
        fixtures::fixture_dsc_key()
            .to_public_key()
            .verify(Pkcs1v15Sign::new::<Sha256>(), &sod_hash, &sig)
            .expect("DSC attestation signature verifies");
    }
}
