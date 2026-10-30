# Security

## Advisory: passport proofs from 0.3.x–0.4.0 are not bound to any issuing state

**Affected:** passport-noir `v0.3.0` – `v0.4.0`. This covers the `dsc_chain`, `passport_adapter` and `openac_show` circuits, the `build_open_ac_v3_witness_bundle` witness builder, and every verifier that accepts their proofs.
**Fixed in:** `v0.5.0`. The new `passport_mrz` circuit and `verify_passport_mrz` replace them; the old builder now always refuses.
**Found:** 2026-10-30, by the maintainers. It was verified by building proofs from invented passport data.

### What was wrong

- **No issuer signature.** `openac_show` checks a Pedersen commitment opening, a device signature and the predicates. It checks no issuer signature at all. A prover can open a commitment over any claims they make up, and the result verifies under the published verification key.
- **Self-minted keys.** `dsc_chain` and `passport_adapter` do verify RSA signatures, but not ones a state made. The witness builder created a fresh CSCA and DSC for every request and signed app-normalised layouts with them. A real CSCA or DSC never signed those layouts.
- **Nothing tied the proofs to a real chain.** Native passive authentication on the phone did check the real chain. But nothing in the proofs tied them to that check.

So a "passport" proof from these versions shows only that someone ran the prover. It does not show that a passport exists. It cannot back a claimed age, nationality, uniqueness (nullifier) or "real person" signal.

### What to do

- Do not accept proofs from ≤ 0.4.0 as evidence about a passport.
- Use 0.5.0: `build_passport_mrz_witness` (prover) and `verify_passport_mrz` (verifier).
  - The verifier must be given a **pinned CSCA list**, for example from the ICAO PKD Master List.
  - It refuses any DSC that a CSCA on that list did not issue.
  - With an empty list it accepts nothing. This is deliberate.

### What 0.5.0 proves, and what it does not

- **Proves:** a DSC, issued by a pinned CSCA, signed an LDSSecurityObject. That object contains the hash of this DG1 (the MRZ). Age and nationality are read from that endorsed DG1.
- **Proves:** whoever holds the device key signed the verifier's challenge.
- **Does not prove that the chip was present.** There is no Active Authentication or Chip Authentication. Anyone who has read the chip once (an airline, a hotel, a border system) holds the SOD and DG1, and can make a valid proof with their own device key.
- **Does not prove that the presenter is the holder.**
- **The nullifier links to the issuing state.** It is keyed on SHA-256(eContent). Anyone who holds the chip's SOD can compute it, the issuing state included.

### Supported inputs

The circuit accepts only:

- TD3 passports (93-byte DG1)
- SHA-256 LDS hashes and CMS digest
- an RSA-2048 DSC with e = 65537, signing PKCS#1 v1.5

Anything else fails to build a witness, with a reason code.

For the CSCA → DSC step, the verifier accepts:

- RSA PKCS#1 v1.5 with SHA-256, SHA-384 or SHA-512
- ECDSA P-256 / P-384

RSA-PSS, brainpool curves and SHA-1 are refused.

## Reporting

Report vulnerabilities privately through GitHub Security Advisories on this repository.
