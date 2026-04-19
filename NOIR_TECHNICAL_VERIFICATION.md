# Noir Technical Verification Guide

更新日期：2026-03-23

這份文件是給工程師與人工 reviewer 用的。目的不是重講產品故事，而是把目前 repo 的 Noir circuits、OpenAC 實作位置、核心不變量、人工驗證步驟、以及實際可跑的 test 流程一次整理清楚。

## 1. 先講結論

目前這個 repo 的真正核心，不是單一 circuit，而是下面這條可連結的約束鏈：

```text
passport_verifier
  -> 驗證 sod_hash 的 DSC RSA 簽章

data_integrity
  -> 驗證 DG hash 鏈回到同一個 sod_hash
  -> 從 DG1/MRZ 所在資料群導出可被 disclosure 使用的 mrz_hash

disclosure
  -> 對 mrz_hash 綁定的 MRZ 做 selective disclosure

prepare_link
  -> 用 sod_hash + mrz_hash + link_rand 算出 prepare_commitment

show_link
  -> 用 prepare_commitment + challenge + scope + epoch 做 show phase 綁定
```

如果只問「哪裡是核心」，答案是兩層：

1. 密碼學核心：`sod_hash -> mrz_hash -> prepare_commitment` 這條鏈。
2. 系統核心：`mopro-binding/src/openac.rs`，因為它把 prepare proof、show proof、policy、TTL、challenge、scope 規則真正串成 verifier contract。

## 2. OpenAC 相關 code 全部在哪裡

### Noir circuits

- `circuits/prepare_link/src/main.nr`
  - OpenAC prepare phase。
  - 核心公式：`SHA256("openac.preparev1" || sod_hash || mrz_hash || link_rand)`
- `circuits/show_link/src/main.nr`
  - OpenAC show phase。
  - 核心公式：
    - `challenge_digest = SHA256("openac.show.v1" || challenge || prepare_commitment || epoch)`
    - `link_tag = SHA256("openac.scope.v1" || prepare_commitment || link_scope || epoch)`
- `circuits/disclosure/src/main.nr`
  - 基本 selective disclosure 在 `main()`
  - OpenAC challenge binding 擴充在 `main_with_challenge()`

### Rust verifier / mopro binding

- `mopro-binding/src/openac.rs`
  - OpenAC 真正的 verifier contract
  - 檢查：
    - prepare/show proof 是否有效
    - public inputs 是否與 presentation 一致
    - `prepare_commitment` 是否一致
    - `sod_hash` / `mrz_hash` 是否一致
    - challenge / epoch / scope policy 是否一致
    - prepare artifact 是否過期
- `mopro-binding/src/noir.rs`
  - mopro prove / verify 入口
  - 也是 Noir artifact 版本相容性的主要檢查點

### Swift wrapper

- `Sources/OpenPassportSwift.swift`
  - iOS/Swift 端的 OpenAC helper
  - `openACPrepare()`
  - `openACShow()`
  - `verifyOpenACLinking()`
  - `makeOpenACEnvelope()`

### 設計文件

- `openAC.md`
  - 論文對映與設計取捨
- `plan.md`
  - TDD-first 的實作計畫與切片歷程

## 3. Repo 目前最重要的主幹檔案

| 角色 | 檔案 | 為什麼重要 |
|---|---|---|
| Trust root | `circuits/passport_verifier/src/main.nr` | 把護照 SOD 的 RSA 簽章驗掉，沒有這一步就沒有政府級來源保證 |
| Data binding | `circuits/data_integrity/src/main.nr` | 把 DG hash 鏈對回 `sod_hash`，這是從 SOD 走到實際 DG 資料的橋 |
| Claim layer | `circuits/disclosure/src/main.nr` | 把 MRZ 轉成可 selective disclosure 的 claims |
| OpenAC prepare | `circuits/prepare_link/src/main.nr` | 產出 prepare commitment，是 Prepare/Show linking 的起點 |
| OpenAC show | `circuits/show_link/src/main.nr` | 綁定 verifier challenge、scope、epoch |
| Cross-proof verifier | `mopro-binding/src/openac.rs` | 把 prepare/show 兩份 proof 與 policy 真的組成一個可驗證流程 |
| Client parity | `Sources/OpenPassportSwift.swift` | 確保 iOS 端計算出來的 hash / tag / linking 規則與 Rust/Noir 一致 |

## 4. Circuit-by-Circuit 技術說明

### 4.1 `passport_verifier`

檔案：`circuits/passport_verifier/src/main.nr`

責任：

- 驗證 DSC 對 `sod_hash` 的 RSA-2048 + SHA-256 PKCS#1 v1.5 簽章。

主要程式：

- `main()` 內用 `BigNumParams<18, 2048>` 重建 modulus / redc 參數。
- 用 `RuntimeBigNum<18, 2048>` 重建 signature。
- 最後呼叫 `verify_sha256_pkcs1v15(sod_hash, signature, exponent)`。

public / private inputs：

| 類型 | 欄位 |
|---|---|
| Public | `modulus_limbs` |
| Private | `sod_hash`, `signature_limbs`, `redc_limbs`, `exponent` |

人工驗證重點：

1. `modulus_limbs` 是 public，代表 verifier 端可以把它拿去對 CSCA/DSC trust store。
2. circuit 本身只驗「這把公鑰能驗過這份 SOD hash」，不負責 trust store 管理。
3. RSA limb 規格固定是 18 個 `u128` limbs。

### 4.2 `data_integrity`

檔案：`circuits/data_integrity/src/main.nr`

責任：

- 驗證每個 DG 的 hash 與 SOD 內的 expected DG hash 一致。
- 再把四個 DG hash 組成 `combined_preimage`，驗證 `digest(combined_preimage) == sod_hash`。

主要程式：

- `main()` 先檢查 `dg_count` 與 `dg_lengths`
- 逐個 DG 把實際長度範圍內的資料複製到固定 512-byte buffer
- 對固定大小 buffer 做 `digest()`
- 最後對四個 32-byte DG hash 串接後再 hash 一次得到 `sod_hash`

public / private inputs：

| 類型 | 欄位 |
|---|---|
| Public | `expected_dg_hashes`, `sod_hash` |
| Private | `dg_count`, `dg_contents`, `dg_lengths` |

人工驗證重點：

1. 這個 circuit hash 的是 **512-byte padded DG buffer**，不是變長 raw bytes。
2. `sod_hash` 是四個 DG hash 固定位置串接後再 hash，一樣是固定長度結構。
3. 這一層是 `passport_verifier` 與 `disclosure` 之間的橋樑。

### 4.3 `disclosure`

檔案：`circuits/disclosure/src/main.nr`

責任：

- 對 88-byte TD3 MRZ 做 selective disclosure。
- 目前支援：
  - 國籍
  - 年齡是否大於等於門檻
  - 姓名欄位

主要程式：

- `main()` 先驗 `sha256(mrz_data) == mrz_hash`
- 再依 disclosure flag 檢查：
  - `out_nationality`
  - `out_name`
  - `out_is_older`
- 不揭露的欄位必須是 0

OpenAC 擴充：

- `main_with_challenge()` 先呼叫 `main()`
- 再計算 `SHA256("openac.show.v1" || challenge || mrz_hash || epoch)` 與 `out_challenge_digest` 比對

public / private inputs：

| 類型 | 欄位 |
|---|---|
| Public | `mrz_hash`, disclosure flags, `age_threshold`, `current_date`, `out_nationality`, `out_name`, `out_is_older` |
| Private | `mrz_data` |

人工驗證重點：

1. 這裡的 `mrz_hash` 是對 **raw 88-byte MRZ** 做 hash，不是對 DG1 的 512-byte padded buffer。
2. 年齡邏輯使用 2-digit year，靠 century rollover 規則處理 `99 -> 1999`、`10 -> 2010`。
3. 未揭露欄位一定要歸零，這是 privacy contract 的一部分。

### 4.4 `prepare_link`

檔案：`circuits/prepare_link/src/main.nr`

責任：

- 在 Prepare phase 生成 `prepare_commitment`。

主要程式：

- `compute_prepare_commitment()`
- `main()` 只做一件事：重算 hash 並與 `out_prepare_commitment` 比對。

public / private inputs：

| 類型 | 欄位 |
|---|---|
| Public | `out_prepare_commitment` |
| Private | `sod_hash`, `mrz_hash`, `link_rand` |

人工驗證重點：

1. domain separator 是 `"openac.preparev1"`，不是 `"openac.prepare.v1"`。
2. `link_rand` 每個 session 應該更新，否則 prepare commitment 可被重複關聯。

### 4.5 `show_link`

檔案：`circuits/show_link/src/main.nr`

責任：

- 在 Show phase 把 verifier challenge 與 prepare commitment 綁在一起。
- 在 scoped-linkable 模式下計算 `link_tag`。

主要程式：

- `compute_prepare_commitment()`
- `compute_challenge_digest()`
- `compute_scoped_link_tag()`
- `main()`

public / private inputs：

| 類型 | 欄位 |
|---|---|
| Public | `link_mode`, `link_scope`, `epoch`, `out_prepare_commitment`, `out_challenge_digest`, `out_link_tag` |
| Private | `sod_hash`, `mrz_hash`, `link_rand`, `challenge` |

人工驗證重點：

1. `show_link` 會自行重算 prepare commitment，不信任外部直接傳入的 prepare 值。
2. `link_mode=false` 時，`link_scope` 與 `out_link_tag` 必須全 0。
3. `link_mode=true` 時，`out_link_tag` 必須等於 scope hash。

## 5. 目前 OpenAC 的真正核心

如果要做人工驗證，最值得優先盯的不是單一函式，而是下面 5 個不變量：

1. `passport_verifier` 與 `data_integrity` 必須共享同一個 `sod_hash`
2. `data_integrity` 與 `disclosure` 必須共享同一個 MRZ 對應關係
3. `prepare_link` 與 `show_link` 必須共享同一個 `prepare_commitment`
4. `show_link` / `disclosure.main_with_challenge()` 必須綁定 verifier 的 `challenge + epoch`
5. verifier 端必須把 proof validity、public inputs、policy、TTL 一次檢查完

在目前 repo 中，最接近「核心合約」的檔案是：

- `mopro-binding/src/openac.rs`

原因：

- 它不是單純算 hash，而是把「proof 有效」與「presentation 規則有效」合在一起。
- 它做了這些真正決定系統安全性的檢查：
  - `prepare_vk_hash` / `show_vk_hash` trust 檢查
  - public input prefix 檢查
  - prepare artifact 啟用時間 / 過期時間
  - `prepare_commitment`、`sod_hash`、`mrz_hash` 一致性
  - verifier challenge 一致性
  - unlinkable / scoped-linkable policy 一致性

換句話說：

- Noir circuits 負責「把局部數學關係約束對」
- Rust `openac.rs` 負責「把整個 Prepare/Show 驗證流程串成可落地的 verifier」

## 6. 人工驗證 checklist

### 6.1 先驗 domain separator 是否跨語言一致

請核對以下 3 組字串在 Noir / Rust / Swift 是否完全一致：

| 用途 | 值 |
|---|---|
| Prepare | `openac.preparev1` |
| Show | `openac.show.v1` |
| Scope | `openac.scope.v1` |

必查檔案：

- `circuits/prepare_link/src/main.nr`
- `circuits/show_link/src/main.nr`
- `circuits/disclosure/src/main.nr`
- `mopro-binding/src/openac.rs`
- `Sources/OpenPassportSwift.swift`

### 6.2 驗 `prepare_commitment` 合約

手動核對：

1. preimage 順序必須是 `domain || sod_hash || mrz_hash || link_rand`
2. `prepare_link` 與 `show_link` 的 prepare 算法必須完全一致
3. Rust `compute_prepare_commitment()` 與 Swift `computeOpenACPrepareCommitment()` 必須同公式

### 6.3 驗 `challenge_digest` 合約

手動核對：

1. preimage 順序必須是 `domain || challenge || prepare_commitment || epoch`
2. `show_link` 與 Rust/Swift helper 必須一致
3. `disclosure.main_with_challenge()` 使用的是 `mrz_hash` 綁定版，這是 disclosure 子流程，不可和 `show_link` 混為同一個 digest

### 6.4 驗 unlinkable / scoped-linkable policy

手動核對：

1. unlinkable 模式時 `link_scope == 0` 且 `link_tag == 0`
2. scoped-linkable 模式時 `link_tag = H(scope_domain || prepare_commitment || link_scope || epoch)`
3. Rust / Swift verifier 都有做同樣 policy 驗證

### 6.5 驗 `mrz_hash` 來源

這是最容易人工 review 時看錯的一點：

1. `data_integrity` hash 的是 **512-byte padded DG1 buffer**
2. `disclosure` hash 的是 **raw 88-byte MRZ**
3. 兩者不是同一個 hash 值，這是 intentional design，不是 bug

review 時要核對的是：

- DG1 內容中是否真的承載同一份 MRZ
- disclosure 是否對應到 DG1 中那段 MRZ 原文

### 6.6 驗 verifier 端是否真的檢查 proof 與 public inputs

請看 `mopro-binding/src/openac.rs`：

1. `verify_noir_bundle_with()` 是否檢查 proof/vk 非空且 verify 成功
2. `verify_public_input_prefix()` 是否檢查 proof 開頭 public inputs 與 presentation 一致
3. `verify_openac_prepare_show_with_verifier()` 是否檢查：
   - trusted VK hash
   - prepare/show proof validity
   - public inputs 一致
   - prepare TTL
   - `sod_hash` / `mrz_hash` / `prepare_commitment`
   - challenge
   - scope policy

### 6.7 驗 Swift parity

請看 `Sources/OpenPassportSwift.swift`：

1. Swift helper 與 Rust helper 是否使用相同 domain separator
2. `verifyOpenACLinking()` 是否至少做和 Rust 同方向的 linking 檢查
3. Swift 端目前沒有 VK hash / proof public input prefix 檢查，真正完整 verifier 仍以 Rust 為主

## 7. Test 流程

### 7.1 Noir workspace

指令：

```bash
cd circuits
nargo test --workspace
```

2026-03-23 實測結果：

- `passport_verifier`: 9/9 passed
- `data_integrity`: 19/19 passed
- `disclosure`: 18/18 passed
- `prepare_link`: 3/3 passed
- `show_link`: 5/5 passed
- 總計：54 個 Noir tests 全綠

這一層代表：

- 各 circuit 內部邏輯一致
- 多數 tamper / should_fail case 已存在
- OpenAC prepare/show 的基本 hash 合約已經由 Noir 測試覆蓋

### 7.1.1 怎麼確認每個 circuit 真的有跑到

只看 `make build-ios` 不夠，因為過去這條路徑確實可能把缺少的 artifact 靜默吞掉。現在應該用下面 3 個層次確認：

1. 確認 workspace member 本身都有被編譯

```bash
cd circuits
nargo compile --workspace
```

你應該再檢查 target 目錄至少有這 5 個檔案：

```bash
ls circuits/target
```

必須看到：

- `passport_verifier.json`
- `data_integrity.json`
- `disclosure.json`
- `prepare_link.json`
- `show_link.json`

2. 確認 workspace member 本身都有跑測試

```bash
cd circuits
nargo test --workspace
```

這個輸出會分 package 顯示：

- `[passport_verifier]`
- `[data_integrity]`
- `[disclosure]`
- `[prepare_link]`
- `[show_link]`

只要少任何一個 package 標頭，就代表它沒有被跑到。

3. 確認 build-ios 真的把所有 compiled artifacts 複製進 mopro input

```bash
make verify-circuit-artifacts
make build-ios
ls mopro-binding/test-vectors/noir
```

現在 `Makefile` 已改成嚴格模式：

- `make verify-circuit-artifacts` 會逐一檢查 5 個 JSON 是否存在
- `make build-ios` 會先做這個檢查
- 若任何一個 circuit artifact 缺少，整個流程會直接失敗，不再 `|| true` 默默跳過

也就是說，現在要是某個 circuit 沒有 build 進去，`make build-ios` 會直接報錯，而不是假裝成功

### 7.2 Rust `mopro-binding`

指令：

```bash
cd mopro-binding
cargo test
```

2026-03-23 實測結果：

- 16 passed
- 11 ignored
- 0 failed

其中重要的 pass：

- `openac::tests::*` 共 14 個核心 verifier tests
- `noir::tests::test_invalid_circuit_path`
- `noir::tests::test_incompatible_noir_version_is_rejected`

ignored tests 的性質：

- 真正會去 prove / verify disclosure proof 的 integration / benchmark 類測試
- 例如：
  - `test_generate_proof_disclosure`
  - `test_verify_proof_disclosure`
  - `test_verify_tampered_proof_fails`
  - `test_get_verification_key`

如果要手動跑其中一個：

```bash
cd mopro-binding
cargo test test_generate_proof_disclosure -- --ignored --nocapture
```

2026-03-23 實測輸出重點：

- `proof=18976 bytes`
- `vk=1816 bytes`

### 7.3 Swift package

指令：

```bash
swift test
```

2026-03-23 實測結果：

- 5/5 passed

這一層目前主要驗：

- API compile surface
- OpenAC hash helper determinism
- scoped linking happy path
- scope mismatch error path

## 8. 目前最重要的現況風險

### 8.1 Noir artifact 版本斷層

這是目前最值得優先寫進人工驗證報告的地方。

現況：

- `circuits/target/*.json` 的 `noir_version` 現在是 `1.0.0-beta.19+...`
- 但 `mopro-binding/src/noir.rs` 只接受 `1.0.0-beta.8.x`

也就是說，下面兩件事不能混為一談：

1. `nargo test --workspace` 全綠
2. mopro 真正吃目前 `circuits/target/*.json` 也能直接 prove

目前 `mopro-binding` 的 prove integration test 之所以能跑，是因為：

- `mopro-binding/test-vectors/noir/disclosure.json` 目前是另一份 `1.0.0-beta.8+...` artifact
- 它不是現在 `circuits/target/disclosure.json` 這份 beta.19 artifact

這代表：

- repo 的「Noir source」與「mopro binding 可接受的 artifact」目前存在版本分叉
- 這也是 iOS app 側 mopro FFI 尚未真正接上的一個實際風險點

### 8.2 目前 OpenAC 是 hash-based，不是論文原版 Pedersen

現況：

- `prepare_commitment` 與 `link_tag` 都是 SHA-256 hash-based commitment
- 不是論文中的 Pedersen / Hyrax commitment

含義：

- 這是目前 repo 的設計選擇，不是實作漏掉
- 人工 reviewer 應該把它理解為「OpenAC-inspired adaptation」

### 8.3 Device binding 尚未完成

現況：

- verifier challenge 有做
- device ownership / secure enclave binding 還沒有 in-circuit

含義：

- 目前系統可做到 challenge binding 與 scoped linking
- 但 non-transferability 仍未完整達成

## 9. 建議的人工審核順序

如果你要最快抓到核心與風險，我建議照這個順序讀：

1. `mopro-binding/src/openac.rs`
2. `circuits/show_link/src/main.nr`
3. `circuits/prepare_link/src/main.nr`
4. `circuits/disclosure/src/main.nr`
5. `circuits/data_integrity/src/main.nr`
6. `circuits/passport_verifier/src/main.nr`
7. `Sources/OpenPassportSwift.swift`
8. `openAC.md`

原因：

- 先看 verifier contract，最容易理解整條 OpenAC flow 真正要求什麼
- 再看 show / prepare，理解 linking 與 challenge
- 最後回到 passport base proofs，看來源與資料完整性

## 10. 一句話定義這個 repo 的核心

這個 repo 的核心，不只是「幾個 Noir circuits」，而是：

> 用 `sod_hash` 證明護照資料有政府簽章來源，用 `mrz_hash` 把 MRZ claim 綁回 passport data，再用 `prepare_commitment` / `challenge_digest` / `link_tag` 把 OpenAC 的 Prepare/Show 流程變成可被 Rust 與 Swift 一致驗證的 contract。

如果你要做人工驗證，最優先看的就是這條 contract 有沒有在 Noir、Rust、Swift 三層維持一致。
