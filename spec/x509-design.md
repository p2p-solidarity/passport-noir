# X.509 Integration Design

> Proof system: UltraHonk + barretenberg (mopro iOS)
> Cross-link: explicit commit-and-open（非 Spartan comm_W_shared）
> Adoption: **Path A — in-circuit ECDSA-P256 device binding with `H(enclave_pk)` inside Pedersen commitment** (決定於 2026-04-17，見 Changelog)

## 架構

```
標準 OIDC（Google、大學）     SD-JWT VC（OID4VCI）          ICAO e-Passport
         │                           │                            │
   jwt_x5c_adapter            sdjwt_adapter              passport_adapter (v3)
         │                           │                            │
         └─────────────┬─────────────┴────────────────┬───────────┘
                       │                              │
                x509_show / sdjwt_show          openac_show (v3)
                       │                              │
                       └──────────────┬───────────────┘
                                      │
                              composite_show
                   (護照 + X.509 / 護照 + SD-JWT / X.509-only)
```

所有 show circuit 都在**電路內**驗 ECDSA-P256 nonce 簽名（device binding），
不再使用獨立的 `device_binding` circuit。原 `device_binding` circuit 保留為單元測試基準。

## 三種 adapter 的統一 commitment

```
pk_digest = Poseidon(enclave_pk_x, enclave_pk_y)

C_passport = Pedersen(DOMAIN_PASSPORT, attr_hi, attr_lo, pk_digest, link_rand_p)
C_x509     = Pedersen(DOMAIN_X509,     attr_hi, attr_lo, pk_digest, link_rand_x)
C_sdjwt    = Pedersen(DOMAIN_SDJWT,    sd_root_hi, sd_root_lo, pk_digest, link_rand_s)
```

`pk_digest` 用 Poseidon 把 Secure Enclave 的 P-256 公鑰 `(x, y)` 壓成單一 Field。
Show circuit 內必須同時：
1. 重開 commitment（確認 `pk_digest` 屬於 prover 聲稱的 enclave key）
2. 用 `enclave_pk_x / enclave_pk_y` 驗證 verifier nonce 的 ECDSA-P256 簽名（`std::ecdsa_secp256r1::verify_signature`）

`enclave_pk` 是 **private witness**，從不公開 → 保證跨 presentation 的 unlinkability。

## link_rand 來源（**非**從 enclave 派生）

| Value | Source | Scope |
|---|---|---|
| `link_rand_p` | `SecRandomCopyBytes(32)`，存 iOS Keychain（`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`） | 持久 root seed |
| `link_rand_x` | `Poseidon(link_rand_p, SALT_X509)` | X.509 credential |
| `link_rand_s` | `Poseidon(link_rand_p, SALT_SDJWT)` | SD-JWT credential |

- `link_rand_p` **不是**從 Secure Enclave derive 出來，只是隨機 bytes。
- Keychain 的 `ThisDeviceOnly` flag 讓備份/iCloud restore 無法取回（符合隱私需求）。
- 跨 credential link 仍可成立：`link_rand_p` 是同一個 random seed，派生一致；
  device 綁定**走 `pk_digest`，不是 link_rand**。

> **Deprecated** (resolved P0-C contradiction): 原 `link_rand_p = HKDF(enclave signature)` 的設計被放棄。
> 原因：Secure Enclave 不可匯出 private key → 無法把 device_sk 當電路 witness。
> 解法：device binding 改為 pk → digest → commitment，簽名動作在 circuit 內驗。

## 兩條 adapter 路徑

|  | jwt_x5c_adapter | sdjwt_adapter |
|---|---|---|
| 適用 | 標準 OIDC id_token，JWT header 含 x5c | SD-JWT VC（OID4VCI），payload 含 `_sd` |
| Trust anchor | x5c cert chain → Mozilla Root snapshot | ECDSA issuer pubkey（known-set，v1 僅單一大學 issuer） |
| Claim 取得 | 電路內 payload hash-binding，fixed offset per known issuer（v1 hardcoded） | Merkle proof from `_sd` root |
| JWT signing | RSA-2048 或 ECDSA-P256（兩個 adapter variant） | ECDSA-P256 only |
| Device binding | **In-circuit ECDSA-P256**（Path A） | **In-circuit ECDSA-P256**（Path A） |

## 檔案索引

- [`x509-contract.md`](x509-contract.md) — **跨 repo shared contract**（proof type、envelope、artifact、trust anchor policy、fallback）
- [`x509-migration.md`](x509-migration.md) — v1 → v2 → v3（Path A）遷移順序與 artifact matrix
- [`x509-circuits.md`](x509-circuits.md) — 所有 circuit I/O 規格（Path A 版本）
- [`x509-ios.md`](x509-ios.md) — iOS OAuth + prepare/show flow
- [`x509-issues.md`](x509-issues.md) — P0 問題與解法（含 Path A 修復記錄）
- [`x509-benchmark.md`](x509-benchmark.md) — Gate 預算、效能目標、回歸規則
- [`x509-multi-agent-review.md`](x509-multi-agent-review.md) — 跨 repo 檢視與 2026-04-17 狀態批註

## 關鍵設計決策

**D1. JSON parsing** — v1 採 **hardcoded-issuer-offset**：app 傳 raw payload bytes，
circuit assert `SHA256(payload_bytes) == jwt_payload_b64_hash`，用 fixed offset 取 claim。
支援 Google OIDC + 一個大學 SD-JWT issuer。v2 in-circuit normalize 歸為 research。

**D2. Device binding** — `pk_digest = Poseidon(enclave_pk_x, enclave_pk_y)` 進 Pedersen commitment；
show circuit 內驗 ECDSA-P256 nonce 簽名。enclave_pk 為 private witness（unlinkability）。
`device_sk` **永遠不**進 circuit。

**D3. Cross-link** — `link_rand_p` 是 Keychain 隨機 bytes，持久但不綁 enclave。
`link_rand_x / link_rand_s = Poseidon(link_rand_p, SALT_*)` 確定性派生。
Device binding 經由 `pk_digest` commitment 成立，**與 link_rand 分離**。

**D4. X.509-only 支援** — 獨立 `x509_show` circuit，不強制綁護照；
`composite_show` 另外支援 passport + X.509 / passport + SD-JWT 兩種組合。

**D5. 版本控管** — `passport_adapter v2 (Pedersen, no pk_digest)` → `v3 (Pedersen + pk_digest)`
需要 re-issue 舊 commitment，不可直接 verify v2 commitment on v3 show circuit。詳見 `x509-migration.md`。

---

## Changelog

### 2026-04-17 — Path A 採用
- **破除 P0-C 矛盾**：原設計同時要求「Secure Enclave key 不可匯出」與「`device_sk` 作 circuit witness」—
  兩者不可並存。改採 Path A：in-circuit ECDSA-P256 驗 nonce 簽名，只把 `enclave_pk` 作 private witness。
- **commitment 結構變更**：三個 adapter 一致加入 `pk_digest = Poseidon(enclave_pk_x, enclave_pk_y)`。
  此變更屬 breaking change，`passport_adapter` 升為 v3，舊 v2 commitment 需 re-issue。
- **link_rand 來源變更**：從「enclave 派生」改為「Keychain 隨機 bytes + Poseidon 派生」。
- **JSON normalize 定案**：v1 固定 issuer offset；移除 Swift `normalizePayload()` 的 canonical JSON 例子
  （因 JWS 簽的是 base64-encoded bytes，不是 canonical JSON，原範例密碼學不正確）。
- **新增檔案**：`x509-contract.md`（shared contract）、`x509-migration.md`（遷移計畫），
  解決 review §1-A（ownership）/§1-B（artifact matrix）/§1-C（envelope）/§1-E（migration）缺口。
