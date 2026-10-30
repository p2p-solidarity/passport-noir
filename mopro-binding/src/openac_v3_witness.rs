//! RETIRED in 0.5.0 — the OpenAC v3 passport witness builder.
//!
//! The <= 0.4.0 builder minted a fresh CSCA/DSC per request and signed
//! app-normalised layouts with it, so `dsc_chain` / `passport_adapter` /
//! `openac_show` proofs were never bound to any issuing state (SECURITY.md).
//! The export stays so existing bindings link, but it always answers
//! `ready = false`. Use `passport_mrz` (`build_passport_mrz_witness` +
//! `verify_passport_mrz`) instead.

use crate::MoproError;

const RESULT_SCHEMA: &str = "gg.solidarity.passport.openac-v3.witness-build-result.v1";

#[uniffi::export]
pub fn build_open_ac_v3_witness_bundle(request_json: String) -> Result<String, MoproError> {
    let _ = request_json;
    Ok(serde_json::json!({
        "schema": RESULT_SCHEMA,
        "passportNoirVersion": crate::passport_mrz::PASSPORT_NOIR_VERSION,
        "ready": false,
        "reason": "retired-not-issuer-bound",
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_retired_builder_never_produces_witnesses() {
        let result = super::build_open_ac_v3_witness_bundle("{}".into()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(value["ready"], false);
        assert_eq!(value["reason"], "retired-not-issuer-bound");
    }
}
