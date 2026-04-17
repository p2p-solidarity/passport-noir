# P0 Issues & Solutions

| # | 位置 | 問題 | 解法 | 狀態 |
|---|---|---|---|---|
| P0-A | `sdjwt_adapter` | `_sd` disclosure 沒驗在 payload 裡 | in-circuit `ExtractSDArray` 驗一致 + index 查 | ✅ 2026-04-17 (x509-circuits §5) |
| P0-B | `openac_show` / `composite_show` | predicates floating，未從 opened attr 派生 | predicate 函數吃 `attr_hi/lo`，不接受獨立 input | ✅ 2026-04-17 (x509-circuits §7/§8) |
| P0-C | cross-link | Secure Enclave 與「device_sk 作 witness」互斥 | Path A：`pk_digest = Poseidon(enclave_pk_x, enclave_pk_y)` 進 commitment，in-circuit ECDSA 驗 nonce | ✅ 2026-04-17 (x509-design §D2/Changelog) |
| P0-D | iOS flow | AIA fetch 供應鏈攻擊 | 改用 JWT header 的 x5c，不需 AIA fetch | ✅ 2026-04-17 (x509-ios.md) |
| P0-E | `passport_adapter` | 護照無 revocation + 無 CSCA 根信任 | CSCA→DSC RSA chain + Master List 深度 8 Merkle + DSC 吊銷 SMT depth 32（v3.1 統一 depth 與 jwt_x5c_adapter） | ✅ 2026-04-17 v3.1 landed（`circuits/passport_adapter`；共用 `openac_core::smt`、新增 `openac_core::merkle`；36,223 opcodes vs. 50k budget）|
| P0-F | trust anchor | off-chain 驗 Mozilla Root，verifier 可能過時 | Mozilla Root snapshot shipping policy 寫入 `x509-contract.md §5`；v2 in-circuit Merkle root 歸為 research | ✅ contract 面定案 2026-04-17；in-circuit Merkle 待做 |
| P0-G | JSON parsing | 固定 offset 在真實 issuer 爛掉 | v1：hardcoded-issuer-offset + `issuer_format_tag` public input；app 傳 raw payload bytes，circuit assert `SHA256(raw) == payload_b64_hash`；v2 in-circuit normalize 歸 research | ✅ 2026-04-17 spec 定案 + v3.1 實作 landed（`circuits/jwt_x5c_adapter` 已切換至固定偏移分派；舊 marker-scan 迴圈刪除） |

---

## P0-C：Device Binding（**Path A 定案**）

### 原矛盾

`x509-design.md v0` 同時要求：

1. **Secure Enclave key 不可匯出** — iOS Secure Enclave 的 P-256 private key 無法讀出，只能用於 `SecKeyCreateSignature`。
2. **`device_sk` 作為 circuit witness** — 原 `verify_device_binding` 把 `device_sk: Field` 當 private input，並 assert `link_rand == Poseidon(device_sk, SALT)`。

這兩件事不能同時成立。這是 review §2-A 指出的最大問題。

### Path A 解法

```
Prepare time:
  1. App 從 Keychain 取 link_rand_p（一次性隨機，ThisDeviceOnly）
  2. App 從 Secure Enclave 取 enclave_pk（public key — 可匯出）
  3. Circuit 計算 pk_digest = Poseidon(enclave_pk_x, enclave_pk_y)
  4. C = Pedersen(DOMAIN, attr_hi, attr_lo, pk_digest, link_rand)

Show time:
  1. Verifier 傳 nonce
  2. App 在 Secure Enclave 裡 sign(nonce_hash) → signature
  3. Circuit 輸入 enclave_pk (private) + signature (private) + nonce_hash (public)
  4. Circuit:
       a. verify_signature(enclave_pk, signature, nonce_hash)       ← 綁這次 presentation
       b. assert pk_digest_from_commitment == Poseidon(enclave_pk)   ← 綁這個 device
```

**device_sk 永遠不進 circuit。** `enclave_pk` 作為 private witness，保持 unlinkability。

### 為何 link_rand_p **不**從 enclave 派生

原設計「`link_rand_p = HKDF(enclave_signature(固定 info))`」有三個問題：

1. 每次想用都要戳 Secure Enclave（Biometrics gate），UX 差。
2. Secure Enclave 簽章有 nonce randomness（RFC 6979 的部分實作會隨機），不保證 deterministic。
3. 反覆呼叫會造成 binder 不穩定。

改為：`link_rand_p = SecRandomCopyBytes(32)`，存 Keychain，`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`。
Device binding 已經透過 `pk_digest` 成立，`link_rand_p` 只需要持久 + device-local 即可。

### 副作用說明（寫明為產品決策）

- **換手機 / 重置 Secure Enclave**：`enclave_pk` 變，所有 commitment 都要重新 prepare。
  此為 v3 的刻意選擇（綁 device = 綁這支 enclave key）。
- **iCloud restore**：Keychain `ThisDeviceOnly` 不跨裝置，必要時改成 `AfterFirstUnlock`（跨同一 Apple ID 裝置），
  但這會讓另一支手機也能持有相同 `link_rand_p`，需同步 `enclave_pk` policy。v1 不支援多裝置 holder。

---

## P0-G：JSON Parsing 策略（**v1 hardcoded-issuer-offset 定案**）

### 原方案比較

| 方案 | 位置 | 正確性 | Gate 成本 | 結論 |
|---|---|---|---|---|
| 原 Swift canonical JSON + assert `norm_hash == jwt_signed_hash` | app | **錯** — JWS 簽的是 base64url(payload)，不是 canonical JSON | 0 | 刪除 |
| In-circuit base64 decode + JSON normalize | circuit | 正確但貴（每個 ~10-20k constraints） | ~30k | 歸 research（v2+） |
| **v1：hardcoded-issuer-offset** | circuit | 僅對已知 issuer 正確 | < 2k | **採用** |

### v1 做法

```
App：
  1. 從 id_token 取 base64url(payload)
  2. payload_b64_hash = SHA256(base64url(payload))           ← public input
  3. payload_raw = base64url_decode(base64url(payload))      ← circuit private witness
     然後 canonicalize field order + zero-pad 到 JWT_PAYLOAD_LEN = 1024 bytes

Circuit：
  1. assert SHA256(payload_raw) == payload_b64_hash           ← 綁住 app 沒偷天換日
  2. jwt_signed_hash = SHA256(header_b64 || "." || payload_b64)  ← public，ECDSA/RSA 驗簽對象
  3. 根據 issuer_format_tag 選 offset table：
       - tag == 1 (GoogleOIDCv1): email_domain 在 offset 17（canonical form）
       - tag == 其它: assert false (v3.1 目前只支援 GoogleOIDCv1)
  4. ExtractField(payload_raw, offset) → attr bytes → pack_x509_domain → (attr_hi, attr_lo)
```

### v3.1 實作位置

- 常數：`circuits/jwt_x5c_adapter/src/main.nr::{ISSUER_FORMAT_GOOGLE_OIDC_V1, GOOGLE_OIDC_V1_EMAIL_DOMAIN_OFFSET}`
- 分派函式：`extract_claim_by_tag(payload, issuer_format_tag)`
- Negative test：`test_extract_claim_by_tag_rejects_unknown_issuer` (tag = 2 → assert false)

**不做** base64 decode in-circuit；由 app 做 decode 再用 hash binding 確保忠實。
因為 `SHA256(base64url_decode(x))` 與 `SHA256(x)` 都是電路內可算的 hash，
app 可先 decode 再傳 raw bytes，circuit 驗 `SHA256(raw) == pre-computed hash` 即可。

### v2 research scope（非 v1 baseline）

- In-circuit base64url decode
- In-circuit JSON normalize（sorted keys + canonical whitespace）
- 支援任意 issuer，不需 `issuer_format_tag`

v2 的 gate 成本估計 > v1 兩倍，屬 research。實作前必須先看 mobile proving time benchmark。

---

## RSA / ECDSA 雙 key type 問題

JWT alg 分成兩個 adapter variant（見 x509-circuits §4）：

```
jwt_x5c_rsa_adapter   — cert chain RSA-2048, JWT signed with RS256
jwt_x5c_ecdsa_adapter — cert chain RSA-2048, JWT signed with ES256
```

- Commitment scheme 一致：`Pedersen(DOMAIN_X509, attr_hi, attr_lo, pk_digest, link_rand_x)`。
- `x509_show` / `composite_show` 不感知 adapter variant。
- App 根據 `alg` 在 prepare 前選電路；見 `x509-contract.md §3` envelope `adapterVariant` 欄位。

---

## Merkle depth / 容量

- `sdjwt_adapter` Merkle depth = 5（32 個 `_sd`），padding `[0u8; 32]`；depth 5 約 +5k constraints。
- MAX_DISC = 4（每張 VC 最多 4 個 claim disclosure），可再調。
- 若 issuer `_sd` 超過 32，app 層拒絕入庫（envelope 層 fail-closed）。

---

## 新追加：Poseidon + ECDSA 的 cost envelope

對 `openac_core` 實作者的提醒：

- Poseidon `hash_2` on bn254：~240 gates（Noir stdlib 黑箱版本）
- Pedersen arity 5 vs arity 4：約 +500 gates
- `std::ecdsa_secp256r1::verify_signature`：162 gates（baseline.toml 已量測）
- `assert_pk_bytes_match_field`（bytes ↔ Field repack）：約 +50 gates per 32-byte input

Path A 把 show circuit 的 ECDSA 檢查「一次驗完，兩個 commitment 共享 pk_digest」，
避免在 composite_show 內跑兩次 ECDSA。這是 gate budget 表（`x509-benchmark.md §3`）能成立的關鍵假設。
