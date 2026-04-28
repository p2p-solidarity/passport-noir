# Off-Chain Policy Variant — 設計計畫（v3.2 後續）

**狀態**：planning（尚未開實作）
**作者**：solidarity ZK team
**日期**：2026-04-28
**前置文件**：[`docs/v3.2-security-closure.md`](../docs/v3.2-security-closure.md) §4
**相關 audit issues**：P0-5（SD-JWT 已 in-circuit 閉環）、P1-4（JWT-X5C 已 in-circuit 閉環）

---

## 1. 背景與動機

v3.2 把 SD-JWT (P0-5) 與 JWT-X5C (P1-4) 的 issuer-bytes ↔ commit-claim 綁定全部塞進 circuit：

| Adapter | v3.1 gates | v3.2 gates | 倍數 |
|---|---|---|---|
| sdjwt_adapter | 5,841 | 35,885 | 6.1x |
| jwt_x5c_adapter | 20,879 | 136,440 | 6.5x |

iOS 上 prove time 跟著上揚（依裝置與 RAM 估 +30~60%），對某些場景偏重：

- 自家 backend verifier（B2B）→ verifier 是受信任服務，多一層 in-circuit 是 overkill。
- 短票 / 行銷 / loyalty → UX 重於密碼學完備。
- 教育 / 校園 SD-JWT 校內驗證 → verifier 屬同組織，可承擔 off-chain policy 責任。

**目標**：提供「可選的、明確標記」的 lite 模式，gate 退回 v3.1 等級，但 verifier policy 必須補回對應檢查。模式必須在 type-system 層面區分，**禁止**因為使用 lite 證明卻沒做 off-chain 檢查而漏掉。

> ⚠️ 預設仍是 strict。lite 模式需要 caller 顯式 opt-in，並提供 manifest。

---

## 2. 設計大綱

### 2.1 兩條 circuit 路徑（不共用 vk）

```
v3.2 default (strict):  sdjwt_adapter      / jwt_x5c_adapter
v3.2 + lite variant:    sdjwt_adapter_lite / jwt_x5c_adapter_lite
```

**lite circuit** 即 v3.1 行為：
- `sdjwt_adapter_lite` 移除 `jwt_payload_raw` / `jwt_payload_raw_len` / `disclosure_positions` witness 與對應 inclusion 斷言；保留 `out_disclosure_root` 公開輸出。
- `jwt_x5c_adapter_lite` 移除 `payload_b64_offset` / `payload_b64_len` / `payload_norm_len` witness 與 b64 decode + byte-equality 斷言；保留 `jwt_signed_hash` ↔ signing input 綁定（P0-4，仍需）。

**注意**：lite 與 strict 共用 commit Pedersen 公式（`commit_attributes_v3`），所以同一 prepare 的 commitment 在兩條路徑上**完全相等**。Show phase（openac_show / x509_show / composite_show）**不需**修改。

### 2.2 Swift verifier API 變更

```swift
public enum OpenACV3Mode: Sendable {
    /// In-circuit inclusion proof（v3.2 預設，最高保證）
    case strictInCircuit

    /// Off-chain manifest 比對。verifier 必須檢查：
    ///   * `out_disclosure_root` ∈ `manifest.allowedDisclosureRoots` (SD-JWT)
    ///   * `jwt_signed_hash`     ∈ `manifest.allowedSignedHashes`  (JWT-X5C)
    ///   * 已從 issuer 處離線取得簽名 payload bytes 並驗 b64url decode 結果與本地 prepare 用的 jwt_payload_norm 相符
    ///
    /// **未做以上任一條等同回到 v3 / v3.1 的 audit gap**。
    case offChainManifest(IssuerManifest)
}

public struct IssuerManifest: Sendable, Equatable {
    public let issuerId: String
    public let allowedDisclosureRoots: Set<Data>      // sdjwt 版用
    public let allowedSignedHashes: Set<Data>         // jwt_x5c 版用
    public let manifestSignature: Data?               // optional: issuer 對 manifest 的簽名
    public let validFromUnix: UInt64
    public let validUntilUnix: UInt64
}

public struct OpenACV3Policy {
    // ... 既有欄位 ...
    public let mode: OpenACV3Mode                     // 新增
}
```

### 2.3 Mopro / Rust 對應

`mopro-binding/src/openac_v3.rs`：

```rust
pub enum OpenACV3Mode {
    StrictInCircuit,
    OffChainManifest(IssuerManifest),
}

pub struct IssuerManifest {
    pub allowed_disclosure_roots: HashSet<[u8; 32]>,
    pub allowed_signed_hashes:    HashSet<[u8; 32]>,
    pub valid_from_unix: u64,
    pub valid_until_unix: u64,
    pub manifest_sig: Option<Vec<u8>>,
}
```

Rust verifier 在 `verify_openac_v3` 內加入：

```rust
match policy.mode {
    OpenACV3Mode::StrictInCircuit => {
        // current path: verify with strict ABI on sdjwt_adapter / jwt_x5c_adapter
    }
    OpenACV3Mode::OffChainManifest(ref m) => {
        // verify with strict ABI on sdjwt_adapter_lite / jwt_x5c_adapter_lite
        // PLUS:
        //   * extract out_disclosure_root / jwt_signed_hash from public inputs
        //   * check membership in m.allowed_*
        //   * check time window
        //   * check m.manifest_sig if provided
        // 其中任一條失敗 -> Err(OpenACV3Error::OffChainPolicyMismatch)
    }
}
```

### 2.4 iOS App 整合

`MoproProofService.swift` 新增 verification config：

```swift
public enum MoproVerificationConfig {
    case strict                                    // default
    case fast(manifestProvider: any IssuerManifestProvider)
}
```

App 初始化時依場景挑選：

```swift
// 校園 verifier app
let svc = MoproProofService(config: .fast(manifestProvider: campusManifestProvider))

// 跨組織 / 政府介接（預設）
let svc = MoproProofService(config: .strict)
```

---

## 3. 不變量 / 安全要求

無論選 strict 或 lite，以下**必須**仍然成立：

1. **commitment 公式不可分叉**：lite 與 strict 共享 `commit_attributes_v3`；同一筆 prepare 在兩條 path 下產生**相同** `(out_commitment_x, out_commitment_y)`。如不一致即視為實作錯誤。
2. **Show phase 完全沿用**：不論 prepare 走哪條，show 一律走 v3.2 的 `openac_show` / `x509_show` / `composite_show`，因為 show 階段只開 commitment 而不重驗 issuer bytes。
3. **lite 模式必有 manifest**：型別系統強制 `OffChainManifest(IssuerManifest)`；verifier 不能在 lite 模式下傳 `nil` manifest。
4. **manifest 過期硬性拒絕**：時間外的 manifest 一律 reject，避免「舊 manifest 無限期可用」。
5. **manifest 簽名（optional 但建議）**：若 issuer 提供簽名，verifier 必須驗；若為自家服務可省略。
6. **稽核紀錄**：lite 模式的每次驗證**必須**寫一筆 audit log（manifest hash + verifier id + timestamp），因為 proof 本身不再 self-contained。

---

## 4. TDD 計畫（紅 → 綠 → 重構）

### M1：`sdjwt_adapter_lite` circuit
**RED**
1. `test_lite_circuit_compiles_with_v31_witness_layout` — 確認 lite 沒有 jwt_payload_raw / disclosure_positions。
2. `test_lite_circuit_emits_same_commitment_as_v32_for_same_inputs` — 共用 commit_attributes_v3。
3. `test_lite_circuit_does_not_assert_disclosure_inclusion` — 一個故意 inclusion 不對的 input 在 lite 裡通過、在 strict 裡 panic。

**GREEN**
1. 複製 sdjwt_adapter 的 main，移除 inclusion 段落；保留 commit + sd_root + disclosure_root。
2. 加進 spec.toml + baseline.toml；ABI check 應落在 v3.1 layout。

**REFACTOR**
1. 抽出共用 helper（`compute_sdjwt_commitment`、`verify_disclosure_hashes`）到 sdjwt 共用模組，避免兩個 circuit 維護兩份。

### M2：`jwt_x5c_adapter_lite` circuit
同 M1 模式，移除 b64 decode + byte-equality；保留 P0-4 sha256_var(signing_input) ↔ jwt_signed_hash。

### M3：Rust verifier `OpenACV3Mode` 切換
**RED**
1. `test_strict_mode_rejects_lite_proof_with_missing_inclusion`（strict 拒 lite proof）
2. `test_lite_mode_rejects_when_manifest_missing_root`
3. `test_lite_mode_rejects_when_manifest_expired`
4. `test_lite_mode_accepts_when_manifest_valid`

**GREEN**
1. 在 `verify_openac_v3` 分流 `mode`。
2. 加 `OffChainPolicyMismatch` error variant。

**REFACTOR**
1. 把 manifest 比對抽成 `verify_off_chain_manifest()`，方便 Swift 與 Rust 共用測試向量。

### M4：Swift API
**RED**
1. `testStrictModeIsDefault` — 不傳 mode 時等於 strict。
2. `testOffChainManifestRejectsTamperedDisclosureRoot`
3. `testOffChainManifestExpired`

**GREEN**
1. `OpenACV3Policy.mode` 新欄位（default = `.strictInCircuit`）。
2. `verifyOpenACv3` 內依 mode 走兩條驗證路徑。

**REFACTOR**
1. 把 manifest 載入抽到 `IssuerManifestStore`，提供本地快取 + 線上同步介面。

### M5：iOS App `MoproProofService`
**RED**
1. `testFastModeUsesLiteCircuit`
2. `testFastModeRejectsExpiredManifest`
3. `testFastModeFallsBackToStrictWhenManifestUnavailable`（離線 / 取不到 manifest 時退回 strict）

**GREEN**
1. `MoproVerificationConfig` enum + `IssuerManifestProvider` protocol。
2. `MoproProofService.generateAndVerify()` 依 config 挑 prepare circuit。

**REFACTOR**
1. UX 層：在 trust-level badge 上把 `.fast` 模式標為 🔵（同現行 TLSNotary 階級），strict 仍 🟢。

---

## 5. 預期效果與驗收標準

| 指標 | strict (v3.2) | lite (此 plan) |
|---|---|---|
| sdjwt_adapter gates | 35,885 | ≤ 6,000（回到 v3.1） |
| jwt_x5c_adapter gates | 136,440 | ≤ 22,000 |
| Prove time（iPhone 17 Pro 估） | ~3-5s | ~0.6-1s |
| Trust level（UX badge） | 🟢 L3 | 🔵 L2.5 |
| Verifier off-chain code | ø | manifest 比對 + audit log |

DoD：
1. 兩條 path 在同一 prepare witness 下產出相同 commitment（cross-circuit golden vector）。
2. Rust + Swift verifier 各 5 個 unit test（4.1-4.5 列出的）。
3. 至少一個整合測試走「fast mode + 真實 manifest」全綠。
4. `docs/v3.2-security-closure.md` §4.4 verifier checklist 在 README 與 SDK doc 顯眼處連結。
5. iOS app 端有 toggle 並在 settings 把 risk 寫清楚。

---

## 6. 何時**不要**用 lite 模式

| 場景 | 原因 |
|---|---|
| 跨組織 W3C VC 互通 | 需 self-contained evidence（外部 verifier 沒有你的 manifest） |
| 政府 / 法律可追溯 | audit log 需 in-circuit 證據鏈 |
| 公開 verifier（任何匿名第三方） | 沒有「受信任」這件事 |
| 高金額交易（KYC、AML） | UX 落後一秒 < 風險成本 |
| issuer 還在快速變動 / 沒 manifest 機制 | 沒得比對 |

→ 預設 strict，並在 doc 與 SDK API 註解清楚提醒。

---

## 7. 風險與緩解

| 風險 | 緩解 |
|---|---|
| 開發者誤用 lite mode 卻忘了做 manifest 比對 | 1) 型別強制帶 manifest；2) Rust / Swift verifier 兩端**主動**做 manifest membership，不仰賴 caller |
| manifest 簽名洩漏 → 偽 manifest | manifest 過期窗 + issuer 簽名雙重保護；manifest 強制 short TTL（≤ 24h） |
| lite circuit 與 strict commitment 公式漂移 | cross-circuit golden test：同 witness 在兩 circuit 產出相同 commitment；CI 紅燈 |
| 未來再加新 audit gap 時 lite 沒同步補 | spec.toml 標 `lite_variant = true` 並在 spec-check 強制兩 circuit 的 commitment 相關欄位同步 |

---

## 8. 開工順序建議

1. **不急**：v3.2 已經安全可上 prod。lite 是優化 UX，不是 blocker。
2. 先 spike `sdjwt_adapter_lite`（M1）就好，量出真實 prove time delta；如果差不到 30% 就不必做 jwt_x5c_lite。
3. 若校園 / 教育場景排程在前，優先 sdjwt 路線；OIDC 公司客戶在前，優先 jwt_x5c 路線。
4. iOS app 端的 `MoproVerificationConfig` 切換可以先 ship strict-only 版，等 lite circuit 與 verifier 都齊了再開放。

---

## 9. 開放問題

1. manifest 同步機制：HTTPS pull / DNS / 透明 log？
2. manifest 撤銷：如何處理 issuer 撤銷舊 manifest 的延遲？是否需要短 TTL + push 通知？
3. 是否要把 `OpenACV3Mode` 也綁進 prepareVk 的 hash 一併 pin？避免 verifier 拿 strict prepare proof 卻當 lite 驗。
4. UX：iOS app 是否要對使用者顯示「這份 proof 為 fast mode，verifier 額外查驗 ABC」？Trust badge 要不要加 tooltip？
