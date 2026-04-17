# Circuit Specifications (Path A)

> 對應版本：`passport_adapter v3`、`jwt_x5c_adapter v1`、`sdjwt_adapter v1`、
> `openac_show v3`、`x509_show v1`、`composite_show v1`。
> 相對 v2 的差異：commitment 多綁一個 `pk_digest`；show circuit 內含 in-circuit ECDSA-P256 驗簽。
> 見 `x509-migration.md` 了解 v2 → v3 遷移語義。

---

## 1. Commitment 結構（三個 adapter 統一）

```
pk_digest = Poseidon(enclave_pk_x, enclave_pk_y)           // Poseidon hash_2 over bn254

C_passport = Pedersen(DOMAIN_PASSPORT, attr_hi, attr_lo, pk_digest, link_rand_p)
C_x509     = Pedersen(DOMAIN_X509,     attr_hi, attr_lo, pk_digest, link_rand_x)
C_sdjwt    = Pedersen(DOMAIN_SDJWT,    sd_root_hi, sd_root_lo, pk_digest, link_rand_s)

link_rand_x = Poseidon(link_rand_p, SALT_X509)
link_rand_s = Poseidon(link_rand_p, SALT_SDJWT)
```

- `pk_digest` 與 `link_rand_*` 都是 Field 元素。
- Pedersen arity 從 v2 的 4 元素（domain, hi, lo, rand）升到 5 元素（+ pk_digest）。
  `openac_core::commit::commit_attributes` 需要新增一個 5-arg 版本 `commit_attributes_v3`
  或擴充現有 API（實作由 openac_core 擁有者決定，spec 不綁定實作路徑）。
- `enclave_pk_x / enclave_pk_y` 為 **private witness**，不出現在 public output。

### 為何 pk 進 commitment

- 不可轉移性：沒有對應 Secure Enclave key 的人無法重開 commitment 也通過 ECDSA。
- 隱式鎖 device：同一個 commitment 綁定同一支手機。
- Unlinkability：`enclave_pk` 不公開，每次 show 看到的只有 `C` 與 nonce signature。
- 無須對 `link_rand` 做 device-binding 技巧（解除 P0-C 矛盾）。

---

## 2. Device Binding 段落（show circuit 內部共用）

```noir
// openac_core/src/device.nr
use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;
use crate::commit::hash_to_fields;

/// Verify nonce signature + return pk_digest bound to the enclave public key.
/// All enclave_pk fields stay private; only nonce_hash (verifier's challenge)
/// is a public input. pk_digest is surfaced through the commitment opening,
/// not directly exposed.
pub fn verify_device_binding(
    enclave_pk_x_bytes: [u8; 32],     // private witness
    enclave_pk_y_bytes: [u8; 32],     // private witness
    signature: [u8; 64],              // private witness (r || s)
    nonce_hash: [u8; 32],             // public input
) -> Field {
    // 1. ECDSA P-256 verify (Noir native black-box)
    let valid = verify_signature(
        enclave_pk_x_bytes, enclave_pk_y_bytes, signature, nonce_hash,
    );
    assert(valid, "Device binding: ECDSA P-256 signature verification failed");

    // 2. Split each 256-bit coord into (hi, lo) 128-bit fields (via hash_to_fields),
    //    then domain-separated pedersen_hash to a single Field.
    //    pedersen_hash replaces Poseidon because nargo 1.0.0-beta.19 does not
    //    export Poseidon; pedersen_hash is cryptographically equivalent in this
    //    role (collision-resistant hash-to-Field).
    let (pk_x_hi, pk_x_lo) = hash_to_fields(enclave_pk_x_bytes);
    let (pk_y_hi, pk_y_lo) = hash_to_fields(enclave_pk_y_bytes);
    pedersen_hash([DOMAIN_PK_DIGEST, pk_x_hi, pk_x_lo, pk_y_hi, pk_y_lo])
}

/// Prepare-side variant: same pk_digest derivation without ECDSA verify.
/// Used by Prepare circuits (passport_adapter, jwt_x5c_adapter, sdjwt_adapter)
/// which have no nonce yet.
pub fn pk_digest_from_bytes(
    enclave_pk_x_bytes: [u8; 32],
    enclave_pk_y_bytes: [u8; 32],
) -> Field { /* same pedersen_hash derivation as step 2 above */ }
```

- 使用 `std::ecdsa_secp256r1::verify_signature`，與現有 `device_binding` circuit 相同，
  baseline ~162 gates（black-box）。
- `DOMAIN_PK_DIGEST`（ASCII `"pkdg"`）作為 domain separator，防止 pk_digest 與
  `openac_core::profile` 內其他 pedersen_hash 用途碰撞。
- **沒有額外的 byte↔field 一致性 assert**：bytes 直接被 hash_to_fields 拆成
  (hi, lo) pair 各 ≤ 128-bit，再 pedersen_hash。實作不使用 native-Field
  representation，所以也沒有 bn254 prime 截斷風險。
- Prepare circuit 呼叫 `pk_digest_from_bytes`（無 nonce）；Show circuit 呼叫
  `verify_device_binding`（含 ECDSA）。兩者產生的 pk_digest 一致。

---

## 3. passport_adapter (v3.1, Prepare)

> v3.1 (2026-04-17) 新增 CSCA→DSC 信任鏈 + DSC 吊銷 SMT；解決 P0-E。
> DSC RSA modulus 由 public 降為 private witness（CSCA + Merkle inclusion 已證明其正當性）；
> 公開輸入改為兩個 trust anchor（`csca_root` ICAO Master List、`dsc_smt_root` 吊銷表）+ commitment。

### I/O (v3.1)

```
PUBLIC inputs:
  csca_root:           Field             // ICAO Master List snapshot root (depth-8 Merkle)
  dsc_smt_root:        Field             // DSC revocation SMT root (depth-32, shared with jwt_x5c_adapter)
  out_commitment_x:    Field
  out_commitment_y:    Field

PRIVATE witness:
  // DSC -> SOD (既有 v3)
  sod_hash:              [u8; 32]
  signature_limbs:       [u128; 18]
  modulus_limbs:         [u128; 18]       // v3.1: now private
  redc_limbs:            [u128; 18]
  exponent:              u32

  // CSCA -> DSC 新增 v3.1
  csca_modulus_limbs:    [u128; 18]
  csca_redc_limbs:       [u128; 18]
  dsc_tbs:               [u8; 1536]
  dsc_cert_sig_limbs:    [u128; 18]
  csca_merkle_index:     u32              // 0..255 (depth 8 = 256 country capacity)
  csca_merkle_siblings:  [Field; 8]

  // DSC 吊銷 SMT 新增 v3.1
  dsc_serial:            [u8; 20]
  smt_siblings:          [Field; 32]
  smt_old_key:           Field
  smt_old_value:         Field
  smt_is_old0:           bool

  // DG chain (既有)
  dg_count:              u8
  dg_contents:           [[u8; 512]; 4]
  dg_lengths:            [u32; 4]
  expected_dg_hashes:    [[u8; 32]; 4]
  link_rand:             Field

  // Path A device binding (既有 v3)
  enclave_pk_x:          [u8; 32]
  enclave_pk_y:          [u8; 32]
```

### 邏輯骨架 (v3.1)

```noir
fn main(/* inputs above */) {
    // 1. Existing: DSC signs SOD.
    verify_rsa(sod_hash, signature_limbs, modulus_limbs, redc_limbs, exponent);

    // 2. NEW v3.1: CSCA signs DSC TBS; extract DSC modulus from TBS and
    //    assert it equals the private `modulus_limbs` used in step 1.
    //    Then verify CSCA in ICAO Master List (depth-8 Merkle inclusion).
    verify_csca_chain(
        csca_modulus_limbs, csca_redc_limbs,
        dsc_tbs, dsc_cert_sig_limbs, modulus_limbs,
        csca_merkle_index, csca_merkle_siblings, csca_root,
    );

    // 3. NEW v3.1: DSC serial must NOT appear in revocation SMT (same
    //    primitive as jwt_x5c_adapter; see openac_core::smt).
    verify_non_membership(
        dsc_serial, smt_siblings, smt_old_key, smt_old_value, smt_is_old0, dsc_smt_root,
    );

    // 4..6. Existing: DG chain + pk_digest + Pedersen v3 commitment.
    ...
}
```

### Gate 成本實測

| 構成 | 新增 opcodes | 累計 |
|---|---|---|
| v3.0 baseline (DSC->SOD + DG chain + Pedersen v3) | — | 25,725 |
| + CSCA RSA verify + DSC modulus 提取+比對 | ~8,000 | ~33,700 |
| + Depth-8 Merkle inclusion (Pedersen nodes) | ~1,500 | ~35,200 |
| + Depth-32 SMT non-membership (shared primitive) | ~1,000 | ~36,200 |
| **v3.1 measured (nargo info)** | — | **36,223** |

### 邏輯骨架

```noir
fn main(/* inputs above */) {
    // 1. RSA DSC 驗簽 (v2 既有)
    verify_rsa(sod_hash, signature_limbs, modulus_limbs, redc_limbs, exponent);

    // 2. DG chain -> passport profile attrs (v2 既有)
    verify_dg_chain(sod_hash, dg_count, dg_contents, dg_lengths, expected_dg_hashes);
    let (birth_year, birth_month, birth_day, nationality) = extract_passport_profile(dg_contents[0]);
    let (attr_hi, attr_lo) = pack_passport_profile(
        sod_hash, expected_dg_hashes[0], birth_year, birth_month, birth_day, nationality);

    // 3. Path A 新增：pk_digest
    assert_pk_bytes_match_field(enclave_pk_x_bytes, enclave_pk_x_field);
    assert_pk_bytes_match_field(enclave_pk_y_bytes, enclave_pk_y_field);
    let pk_digest = hash_2([enclave_pk_x_field, enclave_pk_y_field]);

    // 4. Pedersen commitment with pk_digest
    let c = commit_attributes_v3(
        DOMAIN_PASSPORT, attr_hi, attr_lo, pk_digest, link_rand_p);
    assert_commitment_eq(c, out_commitment_x, out_commitment_y);
}
```

Prepare 階段不做 ECDSA 驗簽（沒有 nonce）。只綁 `pk_digest`。
ECDSA 驗簽發生在 show。

---

## 4. jwt_x5c_adapter (v3.1, Prepare)

> JSON parsing 策略：hardcoded-issuer-offset（D1/P0-G），由 `issuer_format_tag` public input 分派。
> 不做 base64 decode in-circuit；app 傳 canonicalized raw payload bytes，電路驗 SHA256 hash 即可。
> v3.1 (2026-04-17) 優化：SMT 改用 pedersen_hash、SMT_DEPTH 128→32、JWT_PAYLOAD_LEN 4096→1024、
> 固定偏移 claim extractor。詳見 `x509-benchmark.md §9`。

### I/O (v3.1)

```
PUBLIC inputs:
  issuer_modulus:      [u128; 18]   // x5c leaf signer (Mozilla Root snapshot anchors)
  smt_root:            Field        // revocation SMT root (Pedersen-hashed tree, see §11)
  jwt_signed_hash:     [u8; 32]     // SHA256(base64url(header) || "." || base64url(payload))
  jwt_payload_b64h:    [u8; 32]     // SHA256(base64url(payload)) — binds raw bytes
  issuer_format_tag:   Field        // 1 = GoogleOIDCv1 (v1 支援；其他值 assert false)
  out_commitment_x:    Field
  out_commitment_y:    Field

PRIVATE witness:
  // Cert chain (x5c)
  leaf_tbs:            [u8; 1536]
  issuer_tbs:          [u8; 1536]
  leaf_sig:            [u128; 18]
  issuer_sig:          [u128; 18]
  serial_number:       [u8; 20]
  smt_siblings:        [Field; 32]     // v3.1: depth 32 (was 128)
  smt_old_key:         Field
  smt_old_value:       Field
  smt_is_old0:         bool

  // JWT bytes
  jwt_payload_raw:     [u8; 1024]      // v3.1: was [u8; 4096]; app zero-pads to 1024
  jwt_sig:             [u128; 18]      // RSA variant (另有 ECDSA variant，見下)

  // OpenAC binding
  link_rand_p:         Field
  enclave_pk_x_bytes:  [u8; 32]
  enclave_pk_y_bytes:  [u8; 32]
```

### v3.1 常數

```noir
global SMT_DEPTH: u32 = 32;                        // 4 bytes × 8 bits serial key
global JWT_PAYLOAD_LEN: u32 = 1024;                // app-layer canonical + pad
global ISSUER_FORMAT_GOOGLE_OIDC_V1: Field = 1;
global GOOGLE_OIDC_V1_EMAIL_DOMAIN_OFFSET: u32 = 17;  // canonical payload offset
```

### 邏輯骨架 (v3.1)

```noir
fn main(/* inputs above */) {
    // 1. Cert chain
    CertRSA256Verify(leaf_tbs, issuer_modulus, issuer_sig);
    CertRSA256Verify(issuer_tbs, issuer_modulus, leaf_sig);
    // v3.1: depth-32 SMT with Pedersen internal-node hash (see §11).
    SMTNonMembership(serial_number, smt_root, smt_siblings, smt_old_key, smt_old_value, smt_is_old0);

    // 2. JWT signing key binding
    let jwt_key = ExtractModulus(leaf_tbs);
    RSAVerify(jwt_signed_hash, jwt_sig, jwt_key);

    // 3. Payload hash binding (app passes canonicalized raw bytes; circuit asserts hash match)
    assert SHA256(jwt_payload_raw) == jwt_payload_b64h;

    // 4. Fixed-offset claim extraction dispatched by issuer_format_tag (P0-G v1 design).
    //    v1 僅支援 issuer_format_tag == 1 (GoogleOIDCv1)；其它值 assert false。
    //    App 負責在 prepare 前 canonicalize payload 到已知 key 順序，此偏移才穩定。
    assert(issuer_format_tag == ISSUER_FORMAT_GOOGLE_OIDC_V1, "Unsupported issuer_format_tag");
    let (domain_bytes, domain_len) = extract_claim_at_offset(
        jwt_payload_raw, GOOGLE_OIDC_V1_EMAIL_DOMAIN_OFFSET);
    let (attr_hi, attr_lo) = pack_x509_domain(domain_bytes, domain_len);

    // 5. pk_digest + commitment
    let pk_digest = pk_digest_from_bytes(enclave_pk_x_bytes, enclave_pk_y_bytes);
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let c = commit_attributes_v3(
        DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    assert_commitment_eq(c, out_commitment_x, out_commitment_y);
}
```

### RSA / ECDSA variant 分拆

JWT signing algorithm 決定兩個 adapter variant：

```
jwt_x5c_rsa_adapter   — cert chain RSA-2048, JWT signed with RS256 (Google OIDC 現況)
jwt_x5c_ecdsa_adapter — cert chain RSA-2048, JWT signed with ES256
```

App 在 prepare 前檢查 JWT header 的 `alg`，選對應 adapter。
兩個 adapter 的 commitment scheme 一致，`x509_show` / `composite_show` 不感知 variant。

---

## 5. sdjwt_adapter (v1, Prepare)

> 修掉 P0-A：`_sd` disclosure 必須綁在 payload 裡。

### I/O

```
PUBLIC inputs:
  issuer_pk_x:         Field
  issuer_pk_y:         Field
  jwt_signed_hash:     [u8; 32]
  jwt_payload_b64h:    [u8; 32]
  out_commitment_x:    Field
  out_commitment_y:    Field

PRIVATE witness:
  jwt_payload_raw:     [u8; 4096]
  jwt_sig:             [u8; 64]     // ECDSA-P256
  sd_hashes:           [[u8; 32]; 32]    // _sd array, padded with [0; 32]
  sd_count:            u32                // actual entries ≤ 32
  disclosure_indices:  [u32; MAX_DISC]    // MAX_DISC = 4 by default
  disclosure_salts:    [[u8; 16]; MAX_DISC]
  claim_values:        [[u8; 64]; MAX_DISC]
  link_rand_p:         Field
  enclave_pk_x_field:  Field
  enclave_pk_y_field:  Field
  enclave_pk_x_bytes:  [u8; 32]
  enclave_pk_y_bytes:  [u8; 32]
```

### 邏輯骨架

```noir
fn main(/* inputs above */) {
    // 1. Payload hash binding + issuer signature
    assert SHA256(jwt_payload_raw) == jwt_payload_b64h;
    let valid = verify_signature(
        issuer_pk_x_bytes, issuer_pk_y_bytes, jwt_sig, jwt_signed_hash);
    assert(valid, "SD-JWT issuer ECDSA verification failed");

    // 2. _sd array binding (P0-A fix): parse payload by fixed offset
    let payload_sd = ExtractSDArray(jwt_payload_raw, sd_count);
    for i in 0..32 {
        assert(payload_sd[i] == sd_hashes[i], "SD array mismatch");
    }

    // 3. Disclosure verify (direct index, no separate Merkle)
    for i in 0..MAX_DISC {
        let disc_hash = SHA256(disclosure_salts[i] || claim_values[i]);
        assert(disc_hash == sd_hashes[disclosure_indices[i]], "Disclosure mismatch");
    }

    // 4. sd_root + attrs
    let sd_root = MerkleRoot(sd_hashes, 5);    // depth 5 / 32 leaves
    let (attr_hi, attr_lo) = hash_to_fields(sd_root);

    // 5. pk_digest + commitment
    let pk_digest = /* same as §2 */;
    let link_rand_s = hash_2([link_rand_p, SALT_SDJWT]);
    let c = commit_attributes_v3(
        DOMAIN_SDJWT, attr_hi, attr_lo, pk_digest, link_rand_s);
    assert_commitment_eq(c, out_commitment_x, out_commitment_y);
}
```

---

## 6. x509_show (v1, X.509-only Show)

```noir
fn main(
    // === PUBLIC ===
    in_commitment_x509_x: pub Field,
    in_commitment_x509_y: pub Field,
    nonce_hash:           pub [u8; 32],
    target_domain_hash:   pub Field,       // pedersen_hash of expected (attr_hi, attr_lo)
    link_scope:           pub Field,
    epoch:                pub Field,
    out_link_tag:         pub Field,
    out_challenge_digest: pub Field,
    out_domain_match:     pub Field,       // 0 or 1

    // === PRIVATE ===
    attr_hi:              Field,
    attr_lo:              Field,
    link_rand_x:          Field,
    enclave_pk_x:         [u8; 32],
    enclave_pk_y:         [u8; 32],
    signature:            [u8; 64],
) {
    // 1. ECDSA verify + derive pk_digest (single helper)
    let pk_digest = verify_device_binding(
        enclave_pk_x, enclave_pk_y, signature, nonce_hash);

    // 2. Re-open commitment with pk_digest
    let c = commit_attributes_v3(
        DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x);
    assert_commitment_eq(c, in_commitment_x509_x, in_commitment_x509_y);

    // 3. Predicate — domain match from opened attr (P0-B fix).
    //    Verifier pre-hashes expected domain via pedersen_hash([attr_hi, attr_lo])
    //    computed from the same pack_x509_domain routine; circuit just compares.
    let attr_domain_hash = pedersen_hash([attr_hi, attr_lo]);
    out_domain_match = if attr_domain_hash == target_domain_hash { 1 } else { 0 };

    // 4. Scoped link tag
    out_link_tag = pedersen_hash([link_rand_x, link_scope, epoch]);

    // 5. Challenge digest (hash_to_fields splits nonce_hash bytes → 2 Fields)
    let (nonce_hi, nonce_lo) = hash_to_fields(nonce_hash);
    out_challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_x]);
}
```

---

## 7. composite_show (v1, 護照 + X.509 / 護照 + SD-JWT)

```noir
fn main(
    // === PUBLIC ===
    in_commitment_passport_x: pub Field,
    in_commitment_passport_y: pub Field,
    in_commitment_aux_x:      pub Field,     // X.509 or SD-JWT
    in_commitment_aux_y:      pub Field,
    aux_domain:               pub Field,     // DOMAIN_X509 | DOMAIN_SDJWT
    nonce_hash:               pub [u8; 32],
    target_domain_hash:       pub Field,     // pedersen_hash of expected (attr_hi, attr_lo)
    age_threshold:            pub Field,
    link_scope:               pub Field,
    epoch:                    pub Field,
    out_link_tag:             pub Field,
    out_is_older:             pub Field,       // 0 or 1
    out_aux_predicate:        pub Field,       // 0 or 1 (domain_match or sdjwt disclosure)
    out_challenge_digest:     pub Field,

    // === PRIVATE ===
    p_attr_hi:                Field,
    p_attr_lo:                Field,
    a_attr_hi:                Field,
    a_attr_lo:                Field,
    link_rand_p:              Field,
    enclave_pk_x:             [u8; 32],
    enclave_pk_y:             [u8; 32],
    signature:                [u8; 64],
) {
    // 1. ECDSA verify + derive pk_digest (ONCE — same device both credentials)
    let pk_digest = verify_device_binding(
        enclave_pk_x, enclave_pk_y, signature, nonce_hash);

    // 2. Derive aux link_rand
    let link_rand_x = derive_x509_link_rand(link_rand_p);
    let link_rand_s = derive_sdjwt_link_rand(link_rand_p);
    let link_rand_aux = if aux_domain == DOMAIN_X509 { link_rand_x } else { link_rand_s };

    // 3. Open both commitments with shared pk_digest
    let c_p = commit_attributes_v3(
        DOMAIN_PASSPORT, p_attr_hi, p_attr_lo, pk_digest, link_rand_p);
    assert_commitment_eq(c_p, in_commitment_passport_x, in_commitment_passport_y);

    let c_a = commit_attributes_v3(
        aux_domain, a_attr_hi, a_attr_lo, pk_digest, link_rand_aux);
    // 4. Predicates from opened attributes (P0-B fix)
    out_is_older = age_from_attr(p_attr_hi, p_attr_lo, age_threshold);
    let attr_domain_hash = pedersen_hash([a_attr_hi, a_attr_lo]);
    out_aux_predicate = if attr_domain_hash == target_domain_hash { 1 } else { 0 };
    // (for SD-JWT, caller substitutes an sd_root_hash; target_domain_hash is
    // overloaded: it means "expected opened attr hash" regardless of credential type)

    // 5. Link tag + challenge
    out_link_tag = pedersen_hash([link_rand_p, link_scope, epoch]);
    let (nonce_hi, nonce_lo) = hash_to_fields(nonce_hash);
    out_challenge_digest = pedersen_hash([nonce_hi, nonce_lo, link_rand_p]);
}
```

**跨 credential 為何會連結到同一 device：**
- 兩個 commitment 都含 **同一個 `pk_digest`**；
- 同一個 ECDSA 簽名同時驗過這個 `pk_digest`；
- `link_rand_p` 經 Poseidon 派生到 `link_rand_x / link_rand_s`，保證同一 seed 下的 credential 可被 bundle。

**與 zkID 的對照：** zkID 用 Spartan `comm_W_shared` 共享 device key；
Path A 用 Pedersen commitment 裡顯式帶 `pk_digest`，等價效果，適配 UltraHonk（無 `comm_W_shared`）。

---

## 8. openac_show (v3, 既有 passport show 升版)

`openac_show` 升級到 v3：

- 在現有「predicate from opened attr」邏輯前加入 §6 的 ECDSA 驗簽步驟；
- commitment 開法改用 `commit_attributes_v3`（多一個 `pk_digest` 參數）；
- **舊 v2 commitment（無 `pk_digest`）無法在 v3 show 下驗證** — 見 `x509-migration.md` 的 re-issue flow。

---

## 9. DOMAIN / SALT 常數

```noir
// openac_core/src/commit.nr
pub global DOMAIN_PASSPORT: Field = 0x01;
pub global DOMAIN_X509:     Field = 0x02;
pub global DOMAIN_SDJWT:    Field = 0x03;
pub global DOMAIN_MDL:      Field = 0x04;
// v3.1 新增：SMT 內部節點 pedersen_hash domain separator（ASCII "smt1"）
pub global DOMAIN_SMT_NODE: Field = 0x736d7431;

// openac_core/src/device.nr
global DOMAIN_PK_DIGEST:    Field = 0x706b6467;    // "pkdg"（arity-5）

// openac_core/src/profile.nr
pub global SALT_X509:       Field = 0x78353039;    // "x509"
pub global SALT_SDJWT:      Field = 0x73646a77;    // "sdjw"
// SALT_LINK_RAND 刪除 — link_rand_p 不再由 device key 派生
```

**Domain / arity 分離規則**：任何新增 `pedersen_hash` 調用必須選擇不同 (domain, arity) 組合，
避免與現有輸出空間碰撞。現有使用：
- arity 2：`derive_x509_link_rand` 等 `profile.nr` 調用（payload 自帶 SALT_*）
- arity 3：SMT 節點折疊（固定第一 slot 為 `DOMAIN_SMT_NODE`）
- arity 5：`pk_digest_from_bytes`（固定第一 slot 為 `DOMAIN_PK_DIGEST`）

---

## 10. 實作切分（本 repo）

| Module | 責任 |
|---|---|
| `openac_core::commit` | `commit_attributes_v3` + `assert_commitment_eq` |
| `openac_core::device` | `verify_device_binding`, `hash_2`, `hash_2_with_scope`, SALT 常數 |
| `openac_core::predicate` | `age_from_attr`, `decode_domain`, `domain_suffix_match`, `sdjwt_predicate_check` |
| `passport_adapter` | §3 — prepare circuit |
| `jwt_x5c_adapter` (rsa + ecdsa variant) | §4 |
| `sdjwt_adapter` | §5 |
| `openac_show` | §8 (v3 passport-only show) |
| `x509_show` | §6 |
| `composite_show` | §7 |

原 `circuits/device_binding` 保留為 **ECDSA 驗簽單元測試 benchmark**；不再作為 show 流程的一環。

---

## 11. SMT internal-node hash（v3.1）

`jwt_x5c_adapter` 的 revocation SMT 在 v3.1 將內部節點 hash 從 SHA256 切換為
domain-separated pedersen_hash：

```noir
fn hash_field_pair(left: Field, right: Field) -> Field {
    pedersen_hash([DOMAIN_SMT_NODE, left, right])
}
```

### 為何採用 Pedersen 而非 Poseidon

- `nargo 1.0.0-beta.19` 不公開 Poseidon 高階 API（僅 `poseidon2_permutation` raw primitive）
- Pedersen on bn254 / Grumpkin 為 native black-box，~300 ACIR opcodes / arity-3 調用
- SHA256 對 64-byte preimage 約 ~2k opcodes，差距 ~1.7k per node × 33 nodes = ~56k opcodes 節省
  （stacking 與 SMT_DEPTH 128→32 的效果後，總節省 ~360k）

### Off-circuit 同步需求

`smt_root` 作為 public input 由 app 從靜態 CRL snapshot 載入。
對應的 tree-build tooling（目前不在本 repo）必須：
1. 使用 Grumpkin Pedersen 計算節點 hash
2. 套用相同 `DOMAIN_SMT_NODE = 0x736d7431` 常數
3. 使用相同的 big-endian serial_number[0..4] 作 key（depth 32）

參見 `spec/x509-contract.md §5.2` 的 snapshot shipping policy。
`passport_adapter` v3.1 共用同一個 `openac_core::smt` primitive — DSC revocation
與 X.509 cert revocation 使用同形狀的 witness / root (depth 32, Pedersen, same domain)；
CRL aggregator 可輸出單一 tree 服務兩種 credential，或維護兩個 root 分別餵給對應電路。

---

## 12. CSCA Master List Merkle（v3.1）

`passport_adapter` v3.1 以 depth-8 的 Merkle inclusion proof 驗證 CSCA 屬於
ICAO Master List snapshot。256 個 leaf 容量超過全球約 150 個活躍 CSCA，
預算充裕。

### 常數（`openac_core::merkle` / `openac_core::commit`）

```noir
pub global CSCA_MERKLE_DEPTH: u32 = 8;
pub global CSCA_MODULUS_LIMBS: u32 = 18;
pub global DOMAIN_CSCA_LEAF: Field = 0x6373636c;  // "cscl"
pub global DOMAIN_CSCA_NODE: Field = 0x6373636e;  // "cscn"
```

### Leaf 與節點雜湊

```noir
// Leaf: 將 18-limb RSA-2048 modulus 壓成單 Field
leaf = pedersen_hash([DOMAIN_CSCA_LEAF, limb_0_as_field, ..., limb_17_as_field]);   // arity 19

// 內部節點
node = pedersen_hash([DOMAIN_CSCA_NODE, left, right]);                              // arity 3
```

### Off-circuit tooling 對齊

CSCA snapshot builder（不在本 repo）必須：
1. 以 arity-19 Pedersen + `DOMAIN_CSCA_LEAF` 產生每個 CSCA 的 leaf
2. 以 arity-3 Pedersen + `DOMAIN_CSCA_NODE` 折疊至 root
3. 每個 CSCA 至 `csca_merkle_index ∈ [0, 256)`，app 端傳入 prepare
4. Snapshot 以 resource 形式 ship 進 `MoproNoir.xcframework`，與 Mozilla Root snapshot 共用 shipping policy（見 `spec/x509-contract.md §5.1 / §5.3`）
