//! Print sha256(vk) for a circuit — the build pin the creds app ships so a
//! viewer can verify other people's show proofs (PASSPORT_SHOW_VK_BUILD_PIN_SHA256).
//!
//!   cargo run --release --example vk_sha256 -- test-vectors/noir/openac_show.json test-vectors/srs/passport.srs.bin
use passport_zk_mopro::get_noir_verification_key;
use sha2::{Digest, Sha256};

fn main() {
    let mut args = std::env::args().skip(1);
    let circuit = args.next().expect("circuit json path");
    let srs = args.next();
    let vk = get_noir_verification_key(circuit, srs).expect("vk");
    let digest = Sha256::digest(&vk);
    println!("{}", digest.iter().map(|b| format!("{b:02x}")).collect::<String>());
}
