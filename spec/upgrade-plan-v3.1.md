# OpenAC v3.1 Upgrade Plan — Show 路徑統一 + Mobile 效能優先

> Status: **IMPLEMENTED 2026-06-10**（Phase 1 / 2 / 3 / 5 完成；Phase 0 bench wrappers 與 Phase 4 adapter 減重為後續工作，完整後續路線圖見 §7）
> 實測結果（nargo info, 2026-06-10）：openac_show **1,802 → 647 ACIR（−64%）**、passport_adapter **36,247 → 28,596（−21%）**、x509_show 549 → 488（−11%）、composite_show 815 → 827（+1.5%）；bundle 17.0 → 15.9 MB；電路測試 234 全綠、mopro 52 全綠、lint 71(C)。
> Baseline 對照: `benchmark/expected/baseline.toml`（2026-06-10 已刷新）
> 命名說明: 既有 v3.1 = 「v3 + trust-anchor model」(passport_adapter / jwt_x5c_adapter)。
> 本計畫把 **全部 openac 電路收斂到 v3.1**：show 路徑統一 + commitment layout 修正併入同一版號。
> 前置條件: 2026-06-10 security fixes (CRITICAL-2 / HIGH-2 / HIGH-3 / HIGH-5) 先行合併 ✅
> 補充（實作中發現）: nargo 不支援巢狀 workspace（會解析到最外層 Nargo.toml），故 legacy 電路放在頂層 `circuits-legacy/` 而非 `circuits/legacy/`。

---

## 0. TL;DR

| 主軸 | 現況 (v3/v3.1) | v3.1 統一後 |
|------|---------------|---------|
| Show challenge 綁定 | 雙軌：passport 用 SHA256 digest、x509/composite 用 Pedersen digest | **整個 `out_challenge_digest` 從電路移除**；freshness 由已 pin 的 `nonce_hash` 公開輸入承擔 |
| Verifier nonce | `challenge[32]` + `nonce_hash[32]` 兩套 | 單一 nonce：`nonce_hash = SHA256(verifier_nonce)`（圈外計算），亦為 ECDSA message |
| Link tag | passport 鍵控 commitment 座標、x509/sdjwt 鍵控 link_rand（HIGH-4：tag namespace 不相容） | 統一 `pedersen_hash([DOMAIN_LINK_TAG, credential_type, link_rand, scope, epoch])` |
| Epoch | `epoch[u8;4]` + `epoch_field` 重複 + 等值約束 | 單一 `epoch: pub Field` |
| Commitment 屬性 (passport) | `pack_passport_profile` 截斷 sod_hash 到 11 bytes / dg1_hash 到 12 bytes 塞進 32 bytes | arity-8 `commit_passport_v3_1`，full-width hash，免截斷、免 unpack 迴圈 |
| mopro 驗證端 | `ChallengeDigestCheck::{Sha256, PinnedInProof}` 雙路徑 | 單一路徑：只查 pin 的 `nonce_hash` + commitment（`openac_v3.rs` 原地演進） |
| Workspace | 14 條電路全部編譯/出貨（v1×5 + v2×1 已被 v3 取代） | v1/v2 移到 `circuits-legacy/`，bundle 只含 v3.1 |

**Mobile 預期收益（show 熱路徑，每次出示都要跑）：**
openac_show 移除 2-block SHA256 + 64 bytes 公開輸入 + epoch 等值約束。以 baseline 實測「disclosure 487 ACIR、SHA256 為主 → prove 26.7 s / RSS +309 MB」推斷，SHA256 blackbox 是 mobile prove 時間的主導項之一；移除後 show 的剩餘成本以 ECDSA-P256 為主。精確數字由 Phase 0 實測決定。

---

## 1. 現況盤點（與本版比較的基準）

### 1.1 Gate / artifact（baseline.toml, 2026-04-28）

| Circuit | ACIR opcodes | Artifact | 角色 | 手機上跑的頻率 |
|---|---:|---:|---|---|
| openac_show | 1,802 | 178 KB | show（熱路徑） | 每次出示 |
| x509_show | 549 | 112 KB | show | 每次出示 |
| composite_show | 815 | 133 KB | show | 每次出示 |
| passport_adapter | 36,247 | 1.44 MB | prepare（離線一次） | 每本護照一次 |
| sdjwt_adapter | 35,885 | 781 KB | prepare | 每張憑證一次 |
| jwt_x5c_adapter | 136,440 | 3.12 MB | prepare | 每張憑證一次 |
| mdoc_adapter | 692,381 | 10.1 MB | prepare | 每張 mDL 一次 |
| v1×5 + device_binding | ~26,900 | ~1.28 MB | 已被 v3 取代 | 不應再出貨 |
| **合計** | — | **17.0 MB** | | |

注意：CLAUDE.md 仍寫「總 artifact 預算 ~2.3 MB」，實際已是 17 MB —— 文件過期，本計畫 Phase 5 一併修正。

### 1.2 已知的唯一真實 prove 數據

`disclosure`（v1，487 ACIR，SHA256 為主體）：prove **26.7 s**、verify 83 ms、peak RSS **+309 MB**（darwin/arm64, UltraHonk）。ACIR opcode 數嚴重低估後端成本——SHA256 / ECDSA / RSA blackbox 在 Barretenberg 展開後是數萬~數十萬 backend gates（這也是 `gen_srs` 需要 8× SRS multiplier 的原因）。**結論：mobile 效能優化要看 blackbox 用量，不是 ACIR 數字。**

### 1.3 v3 show 熱路徑的 blackbox 成本構成（openac_show）

1. `ecdsa_secp256r1::verify_signature` — 非原生域 P-256，後端最貴的單項（無法移除，見 §3.4）
2. `sha256::digest(114 bytes)` — 2 個 compression block，**純粹為了 challenge digest**（v3.1 移除）
3. `pedersen_commitment` arity-5 + `pedersen_hash` ×2（pk_digest、link_tag）— 便宜
4. 32+32 bytes 的 challenge / out_challenge_digest 公開輸入 byte 約束（v3.1 移除）

---

## 2. 問題診斷：「openac 整體和核心結合起來的問題」

這些不是個別 bug，而是同一個根因：**v3 是從 v1 的 SHA256 協議長出來的，passport 路徑保留了 SHA256 習慣，x509/sdjwt 路徑另起 Pedersen 爐灶，兩邊從未收斂。**

### P-1. Show 協議雙軌（核心 vs 外圍不一致）
- `openac_core::show::compute_challenge_digest` = SHA256("openac.show.v2" ‖ cx ‖ cy ‖ challenge ‖ epoch) → 只有 openac_show 用
- `openac_core::profile::compute_show_challenge_digest_v2` = pedersen([CHLG, nonce_hi, nonce_lo, cx, cy, link_rand]) → x509_show / composite_show 用
- 同名概念、兩種 hash、兩種 preimage 結構、兩種 domain-separation 風格（ASCII byte string vs Field constant）。

### P-2. mopro 驗證端被迫雙路徑，且暴露 digest 冗餘
`openac_v3.rs` 的 `ChallengeDigestCheck::{Sha256, PinnedInProof}`：Rust 端沒有 Grumpkin Pedersen 實作，無法重算 x509/composite 的 digest，只能「pin 在 public input 裡」。但這恰好證明 digest 是冗餘的——**安全性實際來自電路內約束 + verifier 檢查 pin 的 `nonce_hash` 與 commitment**，digest 本身沒有提供額外保證（詳見 §3.1 安全論證）。SHA256 路徑是為了讓 Rust「能重算」而保留的，是倒因為果。

### P-3. 雙重 nonce
openac_show 同時收 `challenge[32]`（只進 digest）與 `nonce_hash[32]`（ECDSA message、公開輸入）。兩者都是 verifier 給的 freshness 值，功能重疊。

### P-4. Link tag namespace 分裂（HIGH-4）
passport tag 鍵控 commitment 座標；x509/sdjwt tag 鍵控 link_rand。除了無法跨憑證比對（已用註解警告），鍵控座標還有實質缺陷：若未來做圈外 homomorphic re-randomization（commit.nr 註解明言支援此特性），座標一變 tag 就變，scoped linkability 直接失效。鍵控 link_rand 的構造才是對的。

### P-5. Epoch 重複表示
`epoch[u8;4]` 只為 SHA256 preimage 存在，又要 `epoch_field` + 等值約束防 mixing。SHA256 一移除，整組可刪。

### P-6. 屬性 packing 截斷 + 命名失真
`pack_passport_profile` 把 sod_hash 截到 11 bytes、dg1_hash 截到 12 bytes 硬塞 32 bytes；欄位叫 `attr_hash_hi/lo` 但對 passport 其實是 packed struct 不是 hash。Pedersen arity 本來就可加寬，截斷是不必要的安全折衣（88/96-bit 2nd-preimage margin）+ show 端還要付 unpack 迴圈。

### P-7. 死重
v1×5 + device_binding（v2，2026-04-17 已標 deprecated）仍在 workspace 編譯、測試、出貨：~1.28 MB artifact、CI 時間、SRS 生成全是浪費。

---

## 3. v3.1 統一設計

### 3.1 核心簡化：移除 in-circuit challenge digest（回應「彌補 hash 選型」）

**改動：** show 電路不再計算/輸出 `out_challenge_digest`，刪除 `challenge[32]` 輸入。Verifier nonce 走唯一路徑：

```
verifier 發 nonce → 雙方圈外算 nonce_hash = SHA256(nonce)
→ enclave 對 nonce_hash 簽 ECDSA-P256（既有流程不變）
→ 電路：verify_device_binding(pk, sig, nonce_hash) + pk_digest 開 commitment
→ nonce_hash 是 pub input；verifier 檢查 pin 值 == 自己發的 nonce 的 hash
```

**無作弊可能性論證（為什麼不需要 digest）：**

| 攻擊 | v3 防禦 | v3.1 防禦 |
|---|---|---|
| Replay（舊 proof 重放） | digest 綁 challenge | `nonce_hash` 是公開輸入，verifier 比對自己本次發的 nonce；舊 proof 的 nonce_hash 對不上 → 拒絕 |
| Proof 移花接木到別的 commitment | digest 綁 cx/cy | commitment x/y 本來就是公開輸入且被 verifier pin（mopro 既有 step：`commitment_x_index/commitment_y_index`）；proof 的公開輸入由 UltraHonk 驗證綁死 |
| 跨憑證類型重用 | digest 無此功能 | `credential_type` 公開輸入 + commitment domain separator（P1-8 已有） |
| 設備綁定剝離 | in-circuit ECDSA | 不變：ECDSA over nonce_hash，pk_digest 必須等於 commitment 內綁的值 |

換句話說：UltraHonk 對 public inputs 的綁定本身就是 transcript binding，digest 是在 proof 系統之上又疊了一層自製 Fiat-Shamir，疊了卻沒有新增任何威脅模型覆蓋。**這是「用簡單、通用的方式彌補 hash 選型」的正解——不是換一個更便宜的 hash，而是發現這個 hash 在圈內根本不需要存在。**

若 W3C VC / 稽核層仍想要一個 session transcript digest，由 verifier 圈外算 `SHA256(nonce ‖ cx ‖ cy ‖ epoch)` 即可，零電路成本，Swift/Rust 都會算 SHA256，正好繞開「圈外算不了 Pedersen」的死結。

### 3.2 統一 link tag（修 P-4 / HIGH-4）

全憑證類型統一為（`openac_core::show::compute_link_tag` 原地重寫）：

```
link_tag = pedersen_hash([DOMAIN_LINK_TAG, credential_type, link_rand, link_scope, epoch])
link_mode == false → 強制 scope == 0 && tag == 0（沿用既有語意）
```

- 鍵控 link_rand：不受 commitment re-randomization 影響，且不洩漏 commitment 結構
- 把 `credential_type` 納入 preimage：取代「靠 arity 不同自然分離」的脆弱慣例，tag namespace 顯式分離
- composite 沿用 `derive_x509_link_rand / derive_sdjwt_link_rand` 派生鏈（不變）

### 3.3 Passport commitment layout v3.1（修 P-6）

```
commit_passport_v3_1 = pedersen_commitment([
    DOMAIN_PASSPORT,
    claims,                     // birth_year(4B) + month(1B) + day(1B) + nationality(3B) = 9 bytes，1 Field
    sod_hash_hi, sod_hash_lo,   // full-width SHA256(SOD)；不截斷
    dg1_hash_hi, dg1_hash_lo,   // full-width SHA256(DG1)
    pk_digest,
    link_rand,
])   // arity 8
```

- Pedersen arity 加寬的邊際成本是線性少量 gates，遠小於截斷的安全折衣與 unpack 成本
- show 端以一次 `to_be_bytes::<9>` 解 `claims`，刪掉 `unpack_passport_profile` 的 byte 迴圈與 6 條等值 assert
- x509 / sdjwt / mdl 維持 arity-5 `commit_attributes_v3`（它們的 attr 本來就是 full-width hash / 恰好 32 bytes 的 pack，沒有截斷問題）
- arity 8 ≠ arity 5 ≠ arity 4 → 與 v3/v1 commitment 天然不可混用（沿用既有 cross-version non-malleability 論證）

### 3.4 不動的東西（明確 non-goals）

- **ECDSA-P256 留在電路內。** Secure Enclave 只出 P-256；把 pk 公開到圈外驗就會變成全域 linkable identifier，違反 unlinkable mode。它是 v3.1 之後 show 路徑的成本地板。（可選研究：對「接受 linkable」的 verifier 提供 disclosed-pk fast mode，省掉整個 blackbox——僅當 Phase 0 實測證明 ECDSA 佔比 >70% 才值得做。）
- **Pedersen commitment 不換 Poseidon。** hiding/homomorphic 需要 EC point；Poseidon2 只考慮用於純 hash 場景（§4 Phase 4）。
- **Prepare adapters 維持離線一次性定位。** mdoc 692k ACIR 在手機上 prove 大概率不可行，但那是 prepare 不是 show；瘦身列 Phase 4，不擋 v3.1 主線。

---

## 4. 分期執行

### Phase 0 — 實測基準（先量再改，1–2 天）
baseline.toml 自己標注 `v2_v3_status = "wrappers_pending"`。在 `mopro-binding/src/noir.rs` 比照 disclosure 模式補 bench wrappers：**openac_show / x509_show / composite_show / passport_adapter**。產出每條的 prove ms / verify ms / peak RSS / proof bytes，寫入 baseline.toml `[performance]`。
**Gate：沒有這組數據，v3.1 的「快了多少」無法驗收。**

### Phase 1 — Show 路徑統一（主菜，預估 3–5 天）
1. `openac_core/src/show.nr` 原地重寫：刪 `compute_challenge_digest` / `assert_hash_eq` / SHA256 依賴 / epoch bytes；`verify_show` 只剩 link tag 邏輯（含 unlinkable 模式 0 值強制）
2. `profile.nr`：刪 `compute_link_challenge_digest` / `compute_show_challenge_digest_v2` / `compute_composite_challenge_digest`；link tag 系列遷到 `show.nr` 改 §3.2 構造
3. `openac_show/src/main.nr`：刪 `challenge` / `epoch[u8;4]` / `out_challenge_digest`；epoch 單 Field
4. `x509_show` / `composite_show` 同步遷移到統一 helper
5. `mopro-binding/src/openac_v3.rs` 原地演進：刪 `ChallengeDigestCheck` enum 與 SHA256 重算路徑，verifier 檢查收斂為「pin nonce_hash + pin commitment + pin credential_type + UltraHonk verify」；layout 索引隨新公開輸入順序重算
6. spec.toml / baseline.toml / CLAUDE.md 域分隔表同步（`openac.show.v2` → 標記 retired）

**對照驗收（vs 本版）：** openac_show 公開輸入 −68 bytes；SHA256 blackbox 0 個（現 2 blocks）；prove 時間以 Phase 0 數據對照，預期顯著下降（SHA256 佔比實測後填入）；mopro 驗證程式碼路徑 2 → 1。

### Phase 2 — Passport commitment layout v3.1（2–3 天，與 Phase 1 同批改完）
§3.3。動 `commit.nr` / `profile.nr` / `passport_adapter` 的 commit 呼叫點 / `openac_show` + `composite_show` 的 re-open 與 unpack。注意：**v3 已發的 passport prepare commitment 與 v3.1 不相容**，需要 app 端 re-prepare（離線、無感），release notes 註明。

### Phase 3 — Workspace 瘦身（1 天）
- `passport_verifier` / `data_integrity` / `disclosure` / `prepare_link` / `show_link` / `device_binding` → `circuits-legacy/`，移出預設 workspace members，CI 改為僅 legacy 檔案變更時才跑
- bundle / release.yml 只打包 v3.1 artifacts：**−~1.28 MB、−6 條電路的 SRS 與 CI 時間**
- baseline.toml / spec.toml 分出 legacy 區段

### Phase 4 — Prepare adapter 減重（機會性，不擋主線）
按 ROI 排序：
1. **mdoc_adapter（692k）**：審計 MAX buffer 尺寸是否貼合真實 mDL 上限；`sha256_var` 的 message 上限是 gate 主導項，每砍半省接近一半；評估 issuer-auth 與 deviceKey 抽取拆兩條電路
2. **jwt_x5c_adapter（136k）**：P1-4 的 1024-byte 圈內 base64 decode + byte 等值是 +115k 的來源；改為「4-char→3-byte 群組驗證、只覆蓋 witness 指出的視窗」可大幅縮減
3. **Merkle/SMT 節點 hash → Poseidon2**（`noir-lang/poseidon` 外部庫，stdlib beta.19 只有 permutation）：passport_adapter depth-8 CSCA + revocation SMT 受益；需 Rust 端同步實作 Poseidon2（風險中等，獨立評估）

### Phase 5 — 文件與量測閉環（0.5 天）
- CLAUDE.md：artifact 預算 2.3 MB → 實際值；電路表更新 v3.1
- baseline.toml 全面刷新（`make bench-update-baseline`）
- `make bench-prove-verify` 納入 CI nightly（非 PR gate）

---

## 5. 風險表

| 風險 | 等級 | 緩解 |
|---|---|---|
| 移除 digest 的安全論證有盲點 | 高影響/低機率 | §3.1 攻擊表逐項對照；PR 必跑 code-reviewer + 針對「digest 移除」寫 negative tests（重放 nonce、換 commitment、跨 domain 各一條 should_fail） |
| v3↔v3.1 過渡期 app 相容 | 中 | mopro 同時保留 v3 layout 常數一個版本；circuit JSON 帶版本欄位，Swift 端按 artifact 選 layout |
| passport commitment 不相容需 re-prepare | 低 | prepare 本來就是離線靜默流程；app 偵測 commitment arity 自動重跑 |
| Poseidon2 外部庫 + Rust 對拍 | 中 | 隔離在 Phase 4-3，做不成不影響 v3.1 主線（主線只用既有 pedersen） |
| Phase 0 實測發現 ECDSA 佔 show 成本 >90% | 中 | v3.1 仍值得做（公開輸入/協議簡化/維護性），但效能敘事改為「ECDSA 是地板」，並啟動 disclosed-pk fast mode 評估 |

---

## 6. 與本版逐項對照（驗收清單 — 2026-06-10 實測結果）

| # | 項目 | v3（改前） | v3.1（驗收標準） | 結果 |
|---|---|---|---|---|
| 1 | show 電路 SHA256 blackbox | 2 blocks/proof | 0 | ✅ 0 |
| 2 | challenge 相關公開輸入 | challenge 32B + digest 32B + epoch 4B | 0（nonce_hash 32B 既有，不變） | ✅ openac_show 公開輸入 85 → 49 slots |
| 3 | challenge digest 實作數 | 3 種（SHA256 / pedersen-v2 / pedersen-composite） | 0 種（圈外可選 1 種） | ✅ 全刪（Noir + Rust） |
| 4 | link tag 構造 | 2 種，namespace 不相容 | 1 種，顯式 domain + credential_type | ✅ `show::compute_link_tag` 唯一實作 + 跨 domain replay 負測試 |
| 5 | mopro 驗證路徑 | 2（Sha256 / PinnedInProof） | 1 | ✅ `ChallengeDigestCheck` enum 刪除 |
| 6 | epoch 表示 | bytes + Field + 等值約束 | Field ×1 | ✅ |
| 7 | 屬性 hash 截斷 (passport) | sod 11B / dg1 12B | full-width | ✅ arity-8 `commit_passport_v3_1` |
| 8 | workspace 電路數 | 14 | 8（+6 legacy 不出貨） | ✅ legacy 在頂層 `circuits-legacy/`（nargo 不支援巢狀 workspace） |
| 9 | bundle artifact | 17.0 MB | ≤ 15.7 MB（Phase 3） | ✅ 15.9 MB（−1.28 MB legacy + openac_show/passport_adapter 縮小；x509/composite/jwt_x5c 實測微增） |
| 10 | ACIR opcodes（附帶收益） | openac_show 1,802 / passport_adapter 36,247 / x509_show 549 | 不設目標 | ✅ **647（−64%）/ 28,596（−21%）/ 488（−11%）**；composite_show 815 → 827（+1.5%，arity-8 開銷） |
| 11 | openac_show prove ms | — | Phase 0 實測（待辦） | ⬜ bench wrappers 未實作（`baseline.toml [performance]` 標 pending） |
| 12 | Predicate context pin（追加修補） | v3 起 `age_threshold` / `current_date` / disclose 旗標是 prover 供給的公開輸入但 verifier 未 pin —— 未成年者可用 threshold=0 或未來日期誠實產出 `out_is_older=true` 騙過只讀布林的 verifier | layout builder 強制收齊 predicate context 並逐欄 pin | ✅ `show_layout_openac` pin 36–41、`show_layout_composite` pin 37–40，+2 回歸測試 |

---

## 7. 後續路線圖（2026-06-10 設計討論增補）

> 本節記錄 v3.1 落地後的設計討論結論：與 OpenAC paper 的真正差距在哪、
> prepare 為什麼比 v1 慢以及怎麼攤掉、adapter 還能縮多少、proof 的用戶
> 價值定位、以及對 euID / 自然人憑證的拓展評估。

### 7.1 與 OpenAC paper 的真正差距：unlinkability（非本次優化造成）

**結論：digest 移除沒有失去任何 binding 安全性**（unforgeability 與 device
binding 由「圈內 ECDSA + pk_digest 綁 commitment + verifier pin nonce_hash」
完整承擔，§3.1 已逐項論證）。paper 用模組間代數 binding 縫合 sigma protocol，
工程上極難做對；我們用 SNARK 把模組收進同一個約束系統，binding 是
by-construction——這是換來實作可行性的正確取捨。

**但有一個 v3 時代就存在的差距要誠實記錄**：show 電路把 commitment 座標當
公開輸入亮出來，且每次出示都是同一個點——等於一個**跨 verifier 的固定假名**。
unlinkable mode 只是不發 link tag；多個 verifier 合謀比對 commitment 座標
仍可關聯同一持有者。paper 用 commitment re-randomization 解決這件事。

補法（按建議順序）：

> Status: **IMPLEMENTED 2026-06-10（in-circuit per-scope 派生，比短期方案更強）**。
> passport_adapter 新增公開輸入 `link_scope` 與私有 `link_rand_seed`，圈內
> `link_rand = openac_core::profile::derive_scoped_link_rand(seed, link_scope)`
> （新 `SALT_SCOPE_RAND` = "scrd"）綁進 commitment。每個 scope → 不同
> commitment 座標，holder 只需保存單一 seed 即可重生，且 verifier pin
> `link_scope` 後可在密碼學上確定該 commitment 是「對應此 scope」的假名（跨
> scope 重用的 commitment 無法通過）。+63 ACIR（一個 pedersen_hash）。下方
> #1 的短期手動方案因此被取代；#2 長期 re-randomization 仍為研究項。

1. **短期（零電路改動，建議立即採用）**：每個 verifier scope 用不同
   `link_rand` 重跑 prepare（prepare 本來就離線），每個服務一個獨立
   commitment。代價是多份 prepare proof 的儲存。此方案需寫進 verifier
   整合文件作為正式建議。
2. **長期（研究項）**：show 圈內驗 `C_shown = C_prepare + delta*H`，
   C_prepare 轉私有後需要集合成員證明或遞迴來維持 prepare 連結——成本高，
   僅在短期方案的儲存代價變得不可接受時才啟動。

### 7.2 Phase 6 — passport prepare 拆分：快取式 DSC 信任鏈證明（最高優先）

> Status: **IMPLEMENTED 2026-06-10**。新增 `dsc_chain` 電路（CSCA→DSC RSA + depth-8 Merkle + 撤銷 SMT + serial binding → 公開 `out_dsc_id`），`passport_adapter` 瘦身為 per-holder core（DSC→SOD + DG + commitment + `in_dsc_id` pin）。連結用 `openac_core::merkle::compute_dsc_id(DSC modulus, exponent)`（新 `DOMAIN_DSC_ID`），verifier 檢查 `dsc_chain.out_dsc_id == passport_adapter.in_dsc_id`（無遞迴）。
> 實測（nargo info）：dsc_chain **10,111 ACIR**（可快取）、passport_adapter 手機端 core **19,997 → 11,000 ACIR**（比原始 28,596 −62%，優於本節預估的 ~18k，因 §7.3 的 MAX_DG_COUNT=2 已先讓 DG chain 變便宜）。dsc_chain 12 測試、passport_adapter 12 測試、openac_core +4（compute_dsc_id）全綠。mopro 雙 proof verifier 為後續 commit。

**背景**：v1 passport_verifier 只有 11.7k ACIR 是因為它只驗 DSC→SOD 一條
簽章，「DSC 是否可信」靠 verifier 圈外查表；v3.1 的 28.6k 多出來的是第二條
RSA（CSCA→DSC）+ depth-8 Merkle + depth-32 SMT + commitment。**「比 v1 慢
5–10x」是信任模型的價格，不是優化失敗**——而且可以攤掉：

```
dsc_chain proof（按 DSC 快取，~10.5k）: CSCA→DSC RSA + Merkle 包含 + 撤銷 SMT
                                          → 公開輸出 dsc_id (= compute_csca_leaf_v2 系)
passport_core proof（按本人，~18k）   : DSC→SOD RSA + DG chain + arity-8 commitment
                                          → 公開輸入 pin 同一個 dsc_id
verifier: 驗兩條 proof + 檢查 dsc_id 相等（不需要遞迴）
```

關鍵洞察：**同一顆 DSC 簽發數十萬本護照**，dsc_chain proof 是純公開資料的
證明——可以 server 端預算好、隨 CSCA snapshot 一起發佈。手機上實際要跑的剩
~18k，接近 v1 的 11.7k，卻保有完整信任鏈。

驗收：手機端 prepare ACIR 28,596 → ~18,000；dsc_chain proof 可離線分發；
spec.toml 新增 dsc_chain 電路條目 + 兩條 proof 的 dsc_id 連結寫進
cross_circuit 鏈。

### 7.3 Phase 7 — Adapter 約束減重細目（更新 Phase 4 的優先序）

| 目標 | 主導成本 | 手段 | 預期 |
|---|---|---|---|
| jwt_x5c_adapter 136k | P1-4 整段 1024B payload 圈內 base64 decode + byte 等值（+115k） | 只在 witnessed offset 做 4-char→3-byte 群組解碼，成本從 ∝1024B 變 ∝claim 視窗長度 | 砍掉大半的 115k |
| passport_adapter 28.6k | 圈內 if 兩分支都付費 → 4 個 DG slot 的 SHA256(512B) 永遠全額；DSC_TBS_LEN 1536 = 24 個 SHA block | MAX_DG_COUNT 4→2（commitment 只用 DG1）；DSC_TBS_LEN 收緊到真實 normalized layout 需要的大小（本來就是 app 合成 layout，非真 ASN.1） | 省數十個 SHA256 block；與 7.2 疊加 |
| mdoc_adapter 692k | 變動位置 byte 視窗掃描：Noir 動態索引每次存取 O(N) selector，4 claim envelope × 512B message + validUntil/deviceKey 視窗 | (a) MAX_MSG_LEN / MAX_PREIMAGE_LEN 對照真實 MSO 收緊；(b) 多視窗合併單次掃描；(c) 接受離線定位、評估 server 端跑（MSO 是 issuer 簽的公開結構，無隱私問題） | 量級下降，但手機端 prove 仍需 Phase 0 數據判定可行性 |

（原 Phase 4 的 Poseidon2 項目維持：獨立評估、不擋主線。）

### 7.4 Phase 8 — Active Authentication（DG15）防複製

> Status: **IMPLEMENTED 2026-06-10（EC-P256 變體，圈內 #2 長期方案）**。
> passport_adapter 新增 `verify_active_authentication`：從 DG-chain 綁定的
> DG15（slot 1，`AA_PK_X/Y_OFFSET`）抽出 AA EC-P256 公鑰，驗證晶片對公開
> `aa_challenge` 的 ECDSA 簽章（私有 `aa_signature`），證明晶片在場 —— 只有
> DG dump + SOD 的複製者沒有 AA 私鑰，無法通過。以公開 `require_aa` 旗標閘控
> （verifier 要防複製就 pin true，與 disclose_* 同 fail-closed 模式），故無
> DG15 的護照仍可用 `require_aa=false`。`require_aa=true` 時另 assert
> `dg_count > DG15_SLOT` 確保 AA 公鑰確實被 DG chain 雜湊綁定。+104 ACIR（一個
> ECDSA-P256 blackbox；後端成本約等於一條 P256 verify，與 show 端 device
> binding 同級）。
>
> 註：本實作走 EC-P256 AA（std::ecdsa_secp256r1 原生支援，與 device binding
> 共用），對應現代護照的 EC AA 金鑰；ICAO RSA AA（ISO 9796-2）與「無 DG15」
> 由 `require_aa=false`/未來變體處理。下方 #2 的 RSA 假設因此調整為 EC 主線。

Passive Auth 證明「資料來自真護照」但**不防晶片複製**：拿到他人 DG dump +
SOD 的人可以在自己手機上 enroll。防複製需要 Active Authentication（DG15
公鑰挑戰簽章，證明晶片在場）。app 的 NFC 層已讀 DG15；路線：

1. 短期：app 在 NFC session 內做 AA 挑戰並記錄結果（app-trust，非 ZK）。
2. 長期：AA 簽章驗證進 prepare 電路（DG15 多為 RSA-1024/2048，圈內成本
   與一條 RSA verify 同級），DG15 hash 已在 DG chain 內天然綁定。

### 7.5 憑證生態拓展評估（euID / 自然人憑證）

v3.1 統一後，「信任鏈模式（Merkle root + 撤銷 SMT）、commitment、device
binding、show/composite 電路」全部共用——**新憑證的邊際成本 ≈ 一條 prepare
adapter（解析 + 簽章驗證）**：

- **EUDI（euID）**：官方格式 = SD-JWT VC + mDoc，與現有兩條 adapter 直接
  對口。缺口：(a) issuer 信任要錨 EU LOTL（複用 CSCA Merkle root 模式）；
  (b) **sdjwt_adapter 只收裸 ES256 公鑰、jwt_x5c 只支援 RSA**，EUDI issuer
  多走 EC 憑證鏈 → 需要 EC P-256 cert chain 驗證（ECDSA blackbox 已有，
  主要是 TBS 解析工程）；(c) kb-jwt key binding 語意可直接映射 pk_digest。
- **自然人憑證（MOICA→GRCA）**：RSA-2048 X.509 鏈 → jwt_x5c 的 RSA 鏈 +
  SMT 撤銷近乎原樣複用，`moica_adapter` 邊際成本只剩屬性欄位解析。真正
  瓶頸在電路外：卡片簽章需讀卡機/中介軟體，手機取得簽章的通路要先解決。

### 7.6 Proof 的用戶價值定位

對用戶的三個具體價值：

1. **最小揭露**：證年齡/國籍不出示護照本體。
2. **Scoped link tag = 每服務一個假名**：服務方可做「一本護照一個帳號」的
   反女巫，卻拿不到任何身份資訊——這是被低估的核心賣點。
3. **可複用的政府級 VC**：prepare 一次（離線），之後每次出示只跑 647 ACIR
   的 show。

兩個誠實限制：(a) 防複製依賴 §7.4 的 AA；(b) proof 價值最終取決於 CSCA
root / 撤銷 snapshot 的維護治理與 relying party 採用度——治理問題，非密碼
學問題。

### 建議執行順序

1. **Phase 0**（bench wrappers）：把「快了多少 / mdoc 可不可行」變成實測數字
2. **Phase 6**（§7.2 dsc_chain 拆分）：直接回應 prepare 體感卡頓，ROI 最高
3. **§7.1 短期 unlinkability 方案**：寫進 verifier 整合文件（零電路改動）
4. **Phase 7**（§7.3，jwt_x5c 視窗化 base64 優先）
5. Phase 8（AA）與 §7.5 拓展按產品需求排程
