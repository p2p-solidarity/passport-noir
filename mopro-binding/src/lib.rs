mopro_ffi::app!();

mod error;
pub use error::MoproError;

mod noir;
pub use noir::{generate_noir_proof, get_noir_verification_key, verify_noir_proof};

mod openac;
pub use openac::{
    compute_challenge_digest, compute_prepare_commitment, compute_scoped_link_tag,
    verify_openac_prepare_show, OpenAcLinkMode, OpenAcPolicy, OpenAcPrepareArtifact,
    OpenAcShowPresentation,
};

pub mod openac_v2;
pub use openac_v2::{
    compute_challenge_digest_v2, verify_openac_v2, BatchEntry, LinkMode, PedersenPoint,
    PolicyV2, PrepareArtifactV2, ShowPresentationV2,
};

pub mod openac_v3;
pub use openac_v3::{
    compute_challenge_digest_v3, verify_openac_v3, PolicyV3, PrepareArtifactV3,
    ShowPresentationV3,
};
