# Migration Plan — v1 → v2 → v3 (Path A)

> 對應 review §1-E：「先站在 v1 還是直接跳 v2」「何者是 research，何者是 app-ready」。
> 本文件定義版本邊界、ship 順序、v2 → v3 breaking change 的處理方式。

---

## 1. 版本地圖

| Version | Commitment scheme | 適用 circuits | Status (2026-04-17) |
|---|---|---|---|
| **v1** | SHA256 OpenAC | `prepare_link`, `show_link`, `passport_verifier`, `data_integrity`, `disclosure` | **Deprecated for new features**；維持可編譯 + 可驗直到 v3 stable |
| **v2** | Pedersen（arity 4：domain, attr_hi, attr_lo, link_rand） | `openac_core` v2 API, `passport_adapter` v2, `openac_show` v2, `device_binding`（stand-alone） | **Deprecated for production**；不接受新整合；保留 re-issue period |
| **v3** | Pedersen（arity 5：+ `pk_digest`） + in-circuit ECDSA-P256 device binding（Path A） | `passport_adapter v3`, `openac_show v3`, `jwt_x5c_adapter v1`, `sdjwt_adapter v1`, `x509_show v1`, `composite_show v1` | **Target baseline**（2026 Q2 目標） |

---

## 2. 為何 v2 → v3 是 breaking change

**commitment shape 變了**：

```
v2:  C = Pedersen(domain, attr_hi, attr_lo, link_rand)                     // 4 element
v3:  C = Pedersen(domain, attr_hi, attr_lo, pk_digest, link_rand)           // 5 element，多 pk_digest
```

- 舊 v2 commitment **不可能**在 v3 show circuit 下被重開（Pedersen arity 不同）。
- 舊 v2 commitment 也不含 `pk_digest`，無從做 in-circuit ECDSA 驗證。
- → **必須走 re-issue flow**：把 v2 credential 重新 prepare 成 v3 commitment。

**同一個 enclave_pk + link_rand_p** 可以重建一致的 v3 commitment（只要用戶還在同一支手機、
Keychain `link_rand_p` 還在、Secure Enclave key 還在），重新 prepare 即可。

---

## 3. Re-issue flow（v2 → v3）

```
App 啟動時檢查 credentialStore：
  for each credential c in store:
    if c.schemaVersion < 3 and c.type in {passport, x509, sdjwt}:
        markNeedsReissue(c)

UI 顯示 banner：「已有 N 筆憑證需更新加密格式 → [更新]」

使用者按下：
  1. 對 passport: 重跑 passport_adapter v3（不需重新 NFC；原 SOD/DG 還在 app 內）
  2. 對 x509: 若 JWT 仍在 refresh window → 重跑 jwt_x5c_adapter v1
             若 JWT 過期 → 要求使用者重新 OAuth
  3. 對 sdjwt: 類似，VC 還在有效期就 re-issue，過期就重發
  4. 新產生 v3 commitment，取代舊紀錄；保留 v2 紀錄直到 migration grace period 結束
```

### Grace period

- v2 accept window: **v3 stable release 後 90 天**，app 仍可驗 v2 presentation（trust level 降 🟡）。
- 90 天後 v2 presentation 一律 reject。
- v1（SHA256）不接受 presentation，只保留離線驗證能力（給舊 backup 相容）。

---

## 4. Order of ship（實作順序）

> 實作 agent 請照此順序 PR。每個階段都必須：
> 1. 出 release tag
> 2. 更新 `baseline.toml`
> 3. 在 airmeishi 端做一次 manifest sync
> 4. 寫 e2e fixture 測試

### Phase 1 — `openac_core` v3 primitives（prerequisite）

- 新增 `commit_attributes_v3`（arity 5 Pedersen）
- 新增 `verify_device_binding`（in-circuit ECDSA + pk_digest）
- 新增 `hash_2`（Poseidon on bn254）wrapper
- `SALT_X509 / SALT_SDJWT` 常數定義
- 刪除 `SALT_LINK_RAND`（v3 不用）
- 完整 unit tests（positive + negative）

### Phase 2 — `passport_adapter` v3

- 實作 §3 of x509-circuits
- 保留 v2 circuit 原檔案 `passport_adapter/` 為 v2 + 新建 `passport_adapter_v3/` 或以 feature flag 切換（由實作者決定；spec 僅要求 artifact 命名 `passport_adapter_v3.json` 區分）
- `openac_show v3` 同步升級

### Phase 3 — `x509_show` v1 + `jwt_x5c_adapter_rsa_v1` (v3.1)

- 最小可用：支援 Google OIDC RS256（`issuer_format_tag = 1`）
- SMT witness 可先用 static root（P0-E 的 v1）；SMT_DEPTH = 32 使用 `serial_number[0..4]`
- App 端同步加 OAuth ingestion + Keychain link_rand_p + Enclave key init
- **2026-04-17 v3.1 優化 landed**：20,784 ACIR opcodes（對預算 32%）；原 v3.0 known-deficit 已解除

### Phase 4 — `composite_show` v1 + `passport_adapter` v3.1 CSCA/revocation

- passport + X.509 共享 `pk_digest` 的 composite predicate
- 單一 ECDSA verify（gate budget 關鍵）
- **2026-04-17 `passport_adapter` v3.1 landed**：CSCA→DSC RSA chain + depth-8 ICAO Master List Merkle inclusion + depth-32 DSC revocation SMT。新公開輸入 `csca_root` + `dsc_smt_root`；DSC modulus 降為 private witness；36,223 ACIR opcodes（50k budget 內）

### Phase 5 — `jwt_x5c_adapter_ecdsa_v1` + `sdjwt_adapter_v1`

- JWT ES256 + SD-JWT issuer ECDSA 驗簽
- university issuer onboarding

### Phase 6 — Revocation SMT v2

- 真實 CRL aggregator
- `smtRootEpoch` enforce staleness
- 見 `x509-contract.md §5.2`

### Phase 7 — Research spikes（非 blocking）

- In-circuit JSON normalize（v2 normalize）
- In-circuit Mozilla Root Merkle（取代 snapshot ship）
- Multi-device holder model（多支 enclave_pk 對應同一 identity）

---

## 5. Artifact Matrix（哪個版本進 app bundle）

### 當下（Phase 0，2026-04-17）

```
app bundle:
  openpassport_disclosure.json       ← v1 legacy，唯一可用
  openpassport_srs.bin
```

app 現況只跑 `disclosure` circuit，其它全 fallback。

### Phase 2 完成後（passport v3 baseline）

```
app bundle:
  passport_adapter_v3.json
  passport_adapter_v3_srs.bin
  passport_adapter_v3.vk
  openac_show_v3.json
  openac_show_v3_srs.bin
  openac_show_v3.vk
  disclosure.json                    ← legacy 保留為 fallback
  manifest.json
```

### Phase 3 完成後（x509 引入）

```
加上：
  jwt_x5c_adapter_rsa_v1.json
  jwt_x5c_adapter_v1_srs.bin         ← shared
  jwt_x5c_adapter_rsa_v1.vk
  x509_show_v1.json
  x509_show_v1_srs.bin
  x509_show_v1.vk
```

### Phase 4 完成後（composite）

```
加上：
  composite_show_v1.json
  composite_show_v1_srs.bin
  composite_show_v1.vk
```

### Phase 5 完成後（SD-JWT + ES256）

```
加上：
  jwt_x5c_adapter_ecdsa_v1.json + .vk
  sdjwt_adapter_v1.json + _srs.bin + .vk
```

### Bundle size budget

- 當前 circuits 總和 ~2.4 MB。
- v3 + 全部 Path A artifact 預估 < 4 MB。
- Hard limit：bundle 裡 circuit artifact 不超過 6 MB（影響 App Store 下載大小）。

---

## 6. What breaks（具體壞掉清單）

| 東西 | 壞掉原因 | 處理 |
|---|---|---|
| 舊 v2 passport commitment | v3 show 不認 | Re-issue flow (§3) |
| 舊 v1 SHA256 `prepare_link` / `show_link` proof | v3 verifier 不認 | 只驗不產生，舊離線 backup 用 |
| Rust `openac_v2.rs` verifier | commitment arity 變 | 新建 `openac_v3.rs`；保留 v2 為 deprecated |
| `OpenPassportSwift.swift::verifyOpenACLinking` | v2 邏輯仍可跑 | 新增 v3 path；依 `schemaVersion` switch |
| `mopro-binding` SRS | arity 變 → circuit re-compile → SRS 可能共享（universal setup）或需要換新 | 由 mopro-binding 實作者量測；若需要 bump SRS → release notes 明寫 |
| airmeishi `MoproProofService` `generateWithMopro` | circuit 名字變，需新增 `prove("passport_adapter_v3")` 分支 | 隨 Phase 2 release 一起改 |
| airmeishi `prepare_openpassport_build.sh` | 目前只同步 `openpassport_disclosure.json`，見 review §1-B | 改讀 `manifest.json`；同步所有列出的 artifact |
| Trust badge「三種 proof 都 🟢」 | 違反 §6 of contract | airmeishi UI 同步修正 |

---

## 7. Migration Timeline（建議）

| 月份 | Milestone |
|---|---|
| 2026-05 | Phase 1 openac_core v3 + Phase 2 passport v3 release（internal dev build） |
| 2026-06 | Phase 3 x509 v1 release；airmeishi 接 Google OIDC onboarding beta |
| 2026-07 | Phase 4 composite；正式 re-issue flow 上線，v2 grace period start |
| 2026-09 | Phase 5 SD-JWT + ES256；v2 grace period end（剩 passport v1 fallback） |
| 2026-10+ | Phase 6 revocation v2；Phase 7 research spikes 視容量執行 |

所有日期為目標，實作 agent 依 PR review pace 自行調整。

---

## 8. 回退策略

若 Phase N 出現 critical bug（e.g. v3 proving time > Hard Limit on iPhone 13）：

1. App bundle 立刻 revert 到前一個 release 的 artifact。
2. Verifier 端把 `proofType` 白名單退回前一版；新 proof 拒收。
3. 使用者看到的行為：Trust badge 降級 + inline warning「加密模組更新中」。
4. Fix 完成後再走 Phase N+1。
5. **不可**同時讓 v2 與 v3 共存正式 pipeline（會造成 double-commitment 混亂）；v2 只存在 grace period。

---

## 9. Known deficits

> 這一節記錄已知但未 block ship 的 gate/size/perf 缺口。實作 agent 在做 UX 測試、
> release notes、downstream migration 規劃時必須覆蓋這些項目。

### `jwt_x5c_adapter` — ✅ v3.1 已修復（2026-04-17）

- **v3.0 量測**：384,147 ACIR opcodes vs. 65,000 target（5.9× 超標）
- **v3.1 量測（2026-04-17 landed）**：**20,784 ACIR opcodes**（對 65,000 預算 ~32% 使用率）
- **v3.0 → v3.1 降幅**：**94.6%**
- **套用優化**：
  1. SMT 內部節點 hash：`SHA256(left_bytes || right_bytes)` → `pedersen_hash([DOMAIN_SMT_NODE, left, right])`
  2. `SMT_DEPTH` 128 → 32（`serial_number[0..4]` 作 key；4.3B keyspace 夠用）
  3. `JWT_PAYLOAD_LEN` 4096 → 1024（Google OIDC id_token < 1KB）
  4. email_domain 解析：4080×16 marker loop → `issuer_format_tag` 固定偏移分派（P0-G v1 設計）
- **同步更新**：`benchmark/expected/baseline.toml`、`benchmark/spec.toml::circuits.jwt_x5c_adapter`
  （已清除 `known_deficit` flag、`gate_budget_status = "within_budget"`）；
  詳細設計記錄於 `spec/x509-benchmark.md §9`、`spec/x509-circuits.md §4 / §11`、
  `spec/x509-contract.md §5.2.1`。
- **Release notes 建議**：「Google OIDC credential 建立時間 ≤10 s（iPhone 15 Pro）；
  無需特殊 loading 文案」。
- **Follow-up tasks**（非 blocking）：
  - 跨 repo 協調：v2 CRL aggregator tooling 必須採用相同 Pedersen + `DOMAIN_SMT_NODE`
  - ~~benchmark scripts 仍硬編 v2 circuit list~~ ✅ 2026-04-17 Phase A cleanup 完成；`Makefile::CIRCUIT_PACKAGES`、`benchmark/scripts/{circuit-lint,tdd-check,perf-bench,spec-check,size-bench}.sh` 已更新納入 `sdjwt_adapter`、`jwt_x5c_adapter`、`x509_show`、`composite_show`

---

## 10. mopro-binding v3.1 FFI integration plan（roadmap）

本節記錄 mopro-binding / iOS 端的 v3.1 對接計畫。程式碼改動不在本 repo 的
circuit / spec 範疇，但跨 repo 協調在此釘 SoT。

### 10.1 現況（2026-04-17 audit）

- `mopro-binding/src/openac.rs` (v1 SHA256) + `openac_v2.rs` (Pedersen arity-4) 存在；無 `openac_v3.rs`。
- `MoproiOSBindings/mopro.swift` 暴露 `generateNoirProof`, `verifyNoirProof`, `verify_openac_v2`；無 v3 entry point。
- `mopro-binding/test-vectors/noir/` 僅含 `disclosure.json`；缺少 `passport_adapter`, `sdjwt_adapter`, `jwt_x5c_adapter` 編譯產物。
- iOS `MoproProofService.swift` 因此 fallback 到 Semaphore → SD-JWT，等於真 ZK 護照 pipeline 不可用。
- Toolchain 不一致：circuits 用 nargo 1.0.0-beta.19，mopro-binding 用 1.0.0-beta.8，release.yml 兩者都執行。

### 10.2 Target PR 切分

**PR-10a：v3.1 Rust layer (`openac_v3.rs`)**
- 新增 `src/openac_v3.rs`：`PrepareArtifactV3 { commitment: PedersenPoint, pk_digest: [u8; 32] }`、`verify_openac_v3()`、domain constants 與 Noir 對齊。
- `lib.rs` 加 `pub mod openac_v3; pub use openac_v3::*;`。
- 保留 v1/v2 模組（90 天 grace period）。
- 預估：~400 LOC + 單元測試。

**PR-10b：v3.1 test vectors + build 同步**
- `make copy-circuit-artifacts` 擴充 `test-vectors/noir/` 納入 `passport_adapter.json`、`sdjwt_adapter.json`、`jwt_x5c_adapter.json`、`openac_show.json`、`x509_show.json`、`composite_show.json`。
- `cargo run --bin ios` 重跑 XCFramework；`patch_mopro_fallback.sh` 包住新 Swift entry point。
- 解決 nargo beta.19 vs beta.8 toolchain 差異（優先升級 mopro-binding 的 nargo）。

**PR-10c：iOS MoproProofService 對接**
- `MoproProofService.swift::generateWithMopro()` 改呼叫 `verify_openac_v3()` 與新 `passport_adapter` prepare entry。
- Bundle `csca_root` + `dsc_smt_root` 作為公開 input；fixture 從 resource 讀。
- Trust badge 在 v3.1 proof 成功時升 🟢，失敗則降 🔵/⚪ 按 `spec/x509-contract.md §6` 規則。

### 10.3 預估工作量

| PR | 天數估計 | 依賴 |
|---|---|---|
| 10a | 0.5 – 1 | 無 |
| 10b | 0.5 | 10a |
| 10c | 1 – 2 | 10a, 10b；需 airmeishi repo PR |
| **Total** | **2 – 3.5 工作天** | — |

### 10.4 風險 / Open question

- Toolchain split 可能造成 beta.19 compiled artifact 在 beta.8 prover 中無法解析 — 實測才知。
- `openac_v2.rs::rerandomize_commitment` 是 `unimplemented!()` stub；v3 不繼承此路徑，不 block。
- iOS app 需 airmeishi repo 同步 PR，本 repo 釘 v3.1 entry point 作 SoT；實際接線時以 airmeishi 為工作面。
