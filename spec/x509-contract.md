# Shared Contract — passport-noir × airmeishi

> 本文件是**跨 repo 的唯一真實來源（single source of truth）**。
> 任何一邊要變動的欄位、檔名、版本號，都必須先改這份文件再同步到兩 repo。
>
> 背景：multi-agent review §1-A/§1-B/§1-C/§1-D 指出原 x509 設計缺 ownership / artifact / envelope / trust anchor policy，
> 本文件就是回應。

---

## 1. Repo Ownership Matrix

| Capability | Owner | 輸出 artifact |
|---|---|---|
| Noir circuit 設計與實作 | `passport-noir/circuits/**` | `.json` + `.vk` artifact |
| mopro Rust binding / Swift FFI | `passport-noir/mopro-binding/**` | `MoproNoir.xcframework` |
| Rust verifier helper（openac_v2/v3） | `passport-noir/mopro-binding/src/openac_v3.rs`（新建） | Rust crate |
| Swift verifier helper（OpenPassportSwift） | `passport-noir/Sources/OpenPassportSwift.swift` | Swift Package |
| 本 contract / migration / benchmark spec | `passport-noir/spec/**` | Markdown（手動同步到 airmeishi 引用） |
| Presentation envelope build | `airmeishi/solidarity/Services/Identity/**` | VP / QR / BLE payload |
| Trust badge / UI downgrade | `airmeishi/solidarity/UI/**` | SwiftUI views |
| Issuer registry（OAuth endpoint、issuer_format_tag 對照） | `airmeishi/Resources/issuer-registry.json`（新建） | JSON resource |
| Mozilla Root snapshot | `passport-noir/mopro-binding/assets/mozilla-root-v{n}.pem`（新建） | Versioned bundle |

---

## 2. Proof Types & 版本號

| proofType | version | adapter / show circuit | Status |
|---|---|---|---|
| `passport_v1` | SHA256 OpenAC | `prepare_link` + `show_link` + `disclosure` | **Deprecated**（maintain only；no new features） |
| `passport_v2` | Pedersen OpenAC（無 pk_digest） | `passport_adapter v2` + `openac_show v2` | **Deprecated for production**（被 v3 取代，存在為了過渡） |
| `passport_v3` | Pedersen + pk_digest（Path A） | `passport_adapter v3` + `openac_show v3` | **Target baseline** |
| `x509_v1` | Path A | `jwt_x5c_adapter v1` + `x509_show v1` | Target baseline |
| `sdjwt_v1` | Path A | `sdjwt_adapter v1` + `sdjwt_show v1`（TBD；可先走 `composite_show` variant） | Target baseline |
| `composite_v1` | Path A | passport + aux（X.509 or SD-JWT） | Target baseline |
| `semaphore_fallback` | — | Semaphore group membership | Trust level 🔵 |
| `sdjwt_fallback` | — | 無密碼學 proof，只是簽名 VC | Trust level ⚪ |

---

## 3. Artifact 命名

```
{circuit_name}_v{major}[.{minor}].json      ← ACIR / circuit artifact
{circuit_name}_v{major}[.{minor}]_srs.bin   ← Structured Reference String（若同個 SRS 共用則 hashed 檔名）
{circuit_name}_v{major}[.{minor}].vk        ← verification key (raw barretenberg VK)
```

範例：

```
passport_adapter_v3.json
passport_adapter_v3_srs.bin
passport_adapter_v3.vk

jwt_x5c_adapter_rsa_v1.json
jwt_x5c_adapter_ecdsa_v1.json
jwt_x5c_adapter_v1_srs.bin             ← RS256 / ES256 variant 共用 SRS（相同 universal setup）
jwt_x5c_adapter_rsa_v1.vk
jwt_x5c_adapter_ecdsa_v1.vk

sdjwt_adapter_v1.json
sdjwt_adapter_v1_srs.bin
sdjwt_adapter_v1.vk

x509_show_v1.json / _srs.bin / .vk
composite_show_v1.json / _srs.bin / .vk
openac_show_v3.json / _srs.bin / .vk
```

**Release 打包方式**：
- `passport-noir` 的 `release.yml` 會把上面所有 artifact 壓進 `circuits-bundle-v{tag}.zip`，
  附上 `manifest.json` 列每個檔案的 SHA256。
- `airmeishi/scripts/prepare_openpassport_build.sh` 根據 `manifest.json` 同步到 app bundle。
- **不可以**只同步 `disclosure.json`（現況已過時；見 review §1-B）。

---

## 4. Envelope Schema（presentation 物件）

### 4.1 Prepare result envelope（app 存進 SwiftData 的物件）

```json
{
  "schemaVersion": 1,
  "proofType":     "passport_v3" | "x509_v1" | "sdjwt_v1" | "composite_v1",
  "adapterVariant": "rsa" | "ecdsa" | null,      // 僅 jwt_x5c_adapter 有意義
  "issuerID":      "google.com" | "ntu.edu.tw" | null,
  "issuerFormatTag": 1,                           // 對應 x509-circuits §4 of issuer_format_tag
  "proof":         "<base64 proof bytes>",
  "publicInputs": {
    "outCommitmentX": "<hex Field>",
    "outCommitmentY": "<hex Field>",
    "issuerModulusHash": "<sha256 hex>"           // 若適用
  },
  "vkHash":        "<sha256 of .vk file>",
  "createdAt":     "2026-04-17T12:34:56Z",
  "pkDigest":      "<hex Field, derived from enclave_pk>",   // 不含 enclave_pk 本身
  "trustLevel":    "green" | "blue" | "white"
}
```

### 4.2 Show result envelope（給 verifier / OID4VP）

```json
{
  "schemaVersion": 1,
  "proofType":     "passport_v3" | "x509_v1" | "composite_v1" | "sdjwt_v1",
  "proof":         "<base64 proof bytes>",
  "publicInputs": {
    "inCommitmentX": "<hex Field>",
    "inCommitmentY": "<hex Field>",
    "nonceHash":     "<sha256 hex>",
    "linkTag":       "<hex Field or zero>",
    "challengeDigest": "<hex Field>",
    "targetDomain":  "ntu.edu.tw" | null,
    "ageThreshold":  18 | null,
    "linkMode":      true | false,
    "linkScope":     "<hex Field>",
    "epoch":         0
  },
  "vkHash":        "<sha256 of .vk file>",
  "issuerMetadata": {
    "issuerFormatTag": 1,
    "trustAnchorSnapshotID": "mozilla-root-2026-04",
    "smtRootEpoch":    1234
  },
  "trustLevel":    "green" | "blue" | "white"
}
```

### 4.3 Verifier 必須驗的欄位

Verifier（可以是 airmeishi 或 third-party verifier）必須：

1. 根據 `proofType` 查對應 `.vk`（hash 必須 == `vkHash`）。
2. 用 barretenberg verify `proof` against `publicInputs`。
3. 檢查 `nonceHash == SHA256(self.issuedNonce)`。
4. 若 `trustAnchorSnapshotID` 不是當前 verifier 接受的 snapshot → **fail-closed downgrade**（見 §5）。
5. 若 `linkMode == false` 但 `linkTag != 0` → reject。
6. 若 `proofType` in `{semaphore_fallback, sdjwt_fallback}` → 允許但 trust level 降級。

---

## 5. Trust Anchor Policy

### 5.1 Mozilla Root snapshot

- **發版者**：`passport-noir` maintainers。
- **檔名**：`mozilla-root-YYYY-MM.pem` + `mozilla-root-YYYY-MM.manifest.json`（含 SHA256 + 每張 cert 的 SHA256）。
- **更新頻率**：每季度（與 Mozilla CA bundle upstream 對齊）。
- **App 接受 staleness 窗口**：6 個月。`createdAt` 在 snapshot 發版 + 6 個月內視為有效；更舊 → trust level 從 🟢 降 🔵。
- **Verifier 接受 policy**：
  - 若 proof `trustAnchorSnapshotID` 比 verifier 當前 snapshot 舊 1 個版本 → 接受，但 UI 標記「trust anchor stale」。
  - 舊 2 版以上 → reject。
- **安裝方式**：snapshot 以 resource 形式 ship 進 `MoproNoir.xcframework`，app 啟動時讀入。
  airmeishi 不直接同步 Mozilla upstream；只能隨 passport-noir release 升級。

### 5.2 Revocation SMT（P0-E）

- **SMT root source**：v1 由 passport-noir repo 維護（靜態 snapshot）；v2 接入真實 CRL aggregator。
- **更新頻率**：v1 不更新；v2 至少每日。
- **Epoch 欄位**：`smtRootEpoch`，monotonic u32。
- **App 接受 staleness**：v1 不 enforce；v2 不超過 24 小時。
- **Stale → fail-closed** + UI downgrade。

### 5.3 VK Hash Pinning

- 每個 `.vk` 檔在 release 時算 SHA256 並寫進 `manifest.json`。
- App 的 Swift verifier 啟動時比對 bundle 內 vk hash 與遠端（optional signed metadata）是否一致。
- **mismatch → 直接 fallback**，不可嘗試 proof（避免用不同 vk 驗出假結果）。

---

## 6. Trust Level / Downgrade Semantics

| proofType | Badge | 條件 |
|---|---|---|
| `passport_v3` | 🟢 L3 政府級 | passport_verifier + data_integrity + openac_show v3 皆通過；Mozilla Root 在 staleness 窗口內；enclave signature 在 show 時驗過 |
| `composite_v1` | 🟢 L3 | passport + aux credential 都成立；同一 `pk_digest` |
| `x509_v1` | 🔵 L2 機構級（預設） 或 🟢（若 issuer 在 gov 白名單）| jwt_x5c_adapter + x509_show 通過；依 `issuerID` 決定是否 promote 🟢 |
| `sdjwt_v1` | 🔵 L2 | sdjwt_adapter 通過 |
| `passport_v2` | 🟡（過渡）| 僅在 migration window 接受；超過 migration deadline → 降 🔵 |
| `passport_v1` | 🟡（過渡）| 同上 |
| `semaphore_fallback` | 🔵 | 無 document binding |
| `sdjwt_fallback` | ⚪ L1 自發行 | 無 cryptographic proof |

**App 必須顯式告訴使用者 downgrade**：
- 若 proof path 從 `passport_v3` 掉到 `semaphore_fallback` → 在 ProofView 顯示 inline warning，
  並 log 事件 `proof.downgrade` 給 analytics。
- **絕對不允許**三種 proof 都標成 🟢。（review §3-C 指出的 bug）

---

## 7. Cross-repo Sync / Release Cadence

| Event | passport-noir | airmeishi |
|---|---|---|
| `passport-noir` release tag `v0.x.y` | 打包 circuits bundle + xcframework | 更新 `Package.swift` checksum；跑 `prepare_openpassport_build.sh`；bundle artifact 進 app |
| Mozilla Root snapshot 更新 | 出 patch release（minor bump）| follow-up PR 把新版 snapshot ID 寫入 `issuer-registry.json` |
| 新 issuer 上線（e.g. NYCU SD-JWT） | 新增 `issuer_format_tag` + fixture + circuit 支援 | 更新 `issuer-registry.json` + onboarding UI |
| Circuit bug fix / VK 變更 | bump major version（如 `jwt_x5c_adapter_rsa_v1` → `_v2`）| App 必須同時 bump；舊版 proof failed-closed |

### Fail-closed 行為矩陣

| 情境 | App 行為 |
|---|---|
| Bundle 裡 `vkHash` 跟 manifest 對不起來 | 標記 `proof_engine_unavailable`；所有新的 passport/x509 proof 走 `semaphore_fallback` / `sdjwt_fallback` |
| Circuit artifact 缺 | 同上 |
| `trustAnchorSnapshotID` 超過 staleness 窗口 | proof 仍可驗，但 UI 降 🔵；log warning |
| `smtRootEpoch` 超過 24h（v2） | proof reject |
| `proofType` 不在 verifier 白名單 | reject + 顯示「不支援的憑證類型」 |

---

## 8. Verifier 公開輸入的「可見 vs 承諾」分界

| 欄位 | 可見性 | 說明 |
|---|---|---|
| `outCommitmentX/Y`（prepare 出來的） | 公開 | verifier 只看到曲線座標；不可逆推 attr |
| `inCommitmentX/Y`（show 輸入的） | 公開 | 等於先前 prepare 輸出 |
| `pkDigest` | **不公開於 show envelope** | 只在 prepare envelope 存一份給 app 自己記錄；show envelope 不出現（放上去會洩漏 device identity） |
| `enclavePkX/Y` | **永不公開** | circuit private witness only |
| `linkTag` | 公開 | verifier 用來做 same-scope-same-credential 偵測 |
| `nonceHash` | 公開 | 綁 ECDSA 簽章 |
| `linkMode / linkScope / epoch` | 公開 | policy input |
| `targetDomain / ageThreshold` | 公開 | predicate input |
| `issuerModulusHash` | 公開 | verifier 用來選 trust anchor |

---

## 9. 最小必備整合里程碑

1. `passport_adapter v3` + `openac_show v3` 出 release → airmeishi bump，所有護照 proof 走 v3。
2. `x509_show v1` + `jwt_x5c_adapter_rsa_v1` 出 release → airmeishi 接 Google OIDC onboarding（新子系統）。
3. `composite_show v1` → 綁 passport + X.509 的 composite predicate。
4. `sdjwt_adapter v1` + `jwt_x5c_adapter_ecdsa_v1` → university SD-JWT + OIDC ES256 支援。
5. SMT revocation v2 上線 → `smtRootEpoch` 有意義，fail-closed policy 生效。

細節順序見 `x509-migration.md`。
