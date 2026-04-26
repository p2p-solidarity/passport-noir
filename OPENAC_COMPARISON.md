# OpenAC Implementation vs Paper — Comparison

> 對照對象
> - **Paper / Reference 實作**：`../ref/zkID/`（Privacy & Scaling Explorations @ Ethereum Foundation）
>   - 論文：`paper/zkID.pdf`、`paper/zkID_construction.tex`、`paper/ac_framework.tex`
>   - PoC code：`wallet-unit-poc/circom/`（Circom）、`wallet-unit-poc/ecdsa-spartan2/`（Rust + Spartan2 + Hyrax）、`wallet-unit-poc/openac-sdk/`（TS SDK + WASM bridge）
> - **本 repo 實作**：`circuits/*`（Noir）、`mopro-binding/src/openac{,_v2,_v3}.rs`（Rust verifier）、`Sources/OpenPassportSwift.swift`（iOS SDK）
> - 涵蓋本 repo 三個版本：v1（SHA256 commit）、v2（Pedersen commit）、v3 / Path A（Pedersen + in-circuit ECDSA device binding）

掃描日期：2026-04-18。

---

## 1. 快速結論

| 維度 | 論文 / zkID | 本 repo | 關係 |
|---|---|---|---|
| 架構分相 | Prepare / Show 兩相 | Prepare / Show 兩相 | **一致** |
| Commitment | Hyrax Pedersen（T256） | Grumpkin Pedersen（v2/v3）；SHA256（v1 legacy） | **概念一致；曲線與 packaging 不同** |
| Linking 機制 | 比對兩個 R1CS instance 的 `comm_W_shared`（Hyrax 列向量） | 比對 prepare/show 公開輸出的 commitment 點 `(C.x, C.y)` | **概念一致；實作粒度不同** |
| Re-randomization | `prepareBatch` 每次 show 用新的 shared blinds 重 reblind | 每次 session 用新的 `link_rand` 重生 prepare proof（無 batch） | **不同**（見 §6.1） |
| Device binding | Show circuit 內做 ECDSA-P256 over nonce | Show circuit 內做 ECDSA-P256，**且 pk_digest 折入 commitment**（Path A） | **本 repo 多了 commitment 綁定（優化）** |
| Issuer 簽章 | ES256（SD-JWT） / RS256（jwt_rs256） | RSA-2048（passport_verifier、jwt_x5c_adapter）、ES256（sdjwt_adapter） | **覆蓋面更大** |
| Backend | Spartan2 + Hyrax / T256 | Noir → mopro（UltraPlonk/Honk on bn254 + Grumpkin） | **完全不同 backend** |
| Frontend | Circom + R1CS | Noir + ACIR | **完全不同 DSL** |
| Trust root | 假設 issuer pk 是可信常數 | CSCA Master List Merkle proof + DSC 撤銷 SMT non-membership | **本 repo 多了 trust root + revocation（超出 paper scope）** |
| Multi-credential bundling | 論文只討論單一 credential | `composite_show`：在同一 ECDSA 下綁定 passport + X.509 兩個 commitment | **本 repo 多出來的功能** |
| Predicate / 揭露 | age (jwt) + ECDSA + selective disclosure | 國籍、age threshold、姓名、domain match | **概念一致** |
| Test vectors | desktop + mobile (iPhone17 / Pixel10 Pro) | Noir test 全綠 + Rust verifier 12 tests + Swift parity tests | **覆蓋面類似** |

**一句話總結**：論文定義了 generic AC 框架（issuer-sig + attribute-commit + predicate + device-binding 四個模組），本 repo 完整實作了這四個模組，並在 v3 / Path A 加入兩個論文沒提到的優化（commitment 折入 pk_digest、單一 ECDSA 同時 link multi-credential bundle），同時把 trust root（CSCA / Master List）與 revocation（DSC SMT）也吃進電路內。

---

## 2. Paper 是怎麼定義 OpenAC 的

來源：`../ref/zkID/paper/ac_framework.tex` + `paper/zkID_construction.tex` §Pre-processing and linking proofs。

### 2.1 Generic AC framework（`ac_framework.tex`）
> Modularity is a key requirement: **issuer-signature verification, attribute commitment, predicate proofs, and device binding are defined as separate modules with clear interfaces.**
> This allows the underlying proof system to be replaced (e.g. for quantum-proofing) without modifying other components.

Wallet 兩相：
- **Prepare（offline，每張 credential 一次）**
  1. 用標準函式庫驗 Issuer 簽章
  2. parse + 正規化 attribute（例如 DOB → integer age）
  3. 用 binding & hiding commitment 對 attribute 承諾
- **Show（online，每次 presentation）**
  1. 選擇 RP 要求的 attribute / predicate
  2. 在 ZK 中證明它們對應到先前 commitment
  3. 在 session challenge 上加上 fresh device signature（device binding）

### 2.2 Construction（`zkID_construction.tex`）
- **C₁ (Prepare relation)**：
  - `parse_SD-JWT(S) = ({m_i}, {s_i}, {h_i}, σ_I)`
  - `h_i = SHA256(m_i || s_i)`
  - `ECDSA.verify(σ_I, PK_I) = 1`
- **Linking**：witness 中代表 `{m_i}` 的 column 用 Hyrax Pedersen vector commit，`com(m_1, ..., m_N; r_1) = ∏ g_i^{m_i} · g_{N+1}^{r_1}`。
- **prepareBatch**：把上面的 commitment 重新隨機化 `c^{(j)} = c^{(1)} · g_{N+1}^{r_1^{(j)} - r_1^{(1)}}`，產生一批 `{π_prepare^{(j)}}`，每次 presentation 用一個。
- **C₂ (Show relation)**：
  - `p_i = f_i(m_1, ..., m_n)`（predicate / 揭露）
  - `ECDSA.verify(σ_nonce, m_1[1]) = 1`（device binding，`m_1[1]` 是 issuance 時綁的 device pk）
  - 用 **同一個** `r_1^{(j)}` 對 `{m_i}` 重算 Hyrax commit；Verifier 比對兩相 commit 相等。
- **Backend**：Spartan + Hyrax-style Pedersen polynomial commitment，curve = T256（scalar field == P-256 base field，方便 in-circuit ECDSA）。
- **ZK**：論文 §Adding ZK to Spartan 描述用 random pads + masking polynomial blinding sumcheck（Virgo trick）。

### 2.3 Reference 實作對應位置
- Circom：`circuits/jwt_rs256.circom`、`components/age-verifier.circom`、`components/claim-decoder.circom`、`components/payload_matcher.circom`
- Rust：`ecdsa-spartan2/src/circuits/jwt_rs256_circuit.rs`、`prove_circuit_in_memory`、`reblind_in_memory`
- TS SDK：`openac-sdk/src/prover.ts`（`createProof`：precompute → present → reblind both）、`verifier.ts`（`verifyProof`：先比對 `comm_W_shared`，再分別驗 prepare/show）
- WASM bridge：`openac-sdk/wasm/src/lib.rs::verify` — 第一行就是 `prepare_instance.comm_W_shared == show_instance.comm_W_shared`

---

## 3. 本 repo 怎麼對應這些模組

| Paper 模組 | 本 repo 對應 | 檔案 |
|---|---|---|
| Issuer signature verification | `passport_verifier`（RSA-2048）、`sdjwt_adapter`（ES256）、`jwt_x5c_adapter`（RS256 + cert chain） | `circuits/passport_verifier/src/main.nr`、`circuits/sdjwt_adapter/src/main.nr`、`circuits/jwt_x5c_adapter/src/main.nr` |
| Attribute commitment | `openac_core::commit::commit_attributes` (v2) / `commit_attributes_v3` (v3) | `circuits/openac_core/src/commit.nr` |
| Predicate proofs | `openac_core::predicate::{check_age_above, check_bytes3_eq, two_digit_year_to_four}`、`disclosure`（v1 SHA256 path） | `circuits/openac_core/src/predicate.nr`、`circuits/disclosure/src/main.nr` |
| Device binding | `openac_core::device::verify_device_binding`（in-circuit ECDSA-P256 + pk_digest） | `circuits/openac_core/src/device.nr`、`circuits/device_binding/src/main.nr` |
| Show 相整合 | `openac_show`（passport）、`x509_show`、`composite_show`（multi-credential bundle）、`openac_core::show::verify_show` | `circuits/openac_show/src/main.nr`、`circuits/x509_show/src/main.nr`、`circuits/composite_show/src/main.nr`、`circuits/openac_core/src/show.nr` |
| Verifier contract | `mopro-binding/src/openac{,_v2,_v3}.rs::verify_openac_*` | 見檔名 |
| Wallet SDK | `Sources/OpenPassportSwift.swift`（OpenACPrepareArtifact / OpenACShowPresentation / V2 / V3 Path A surface） | 同檔 |

對應到「論文要求 modularity」：
- `openac_core` 就是 paper §ac_framework 描述的 generic 模組層；
- 各 adapter（`passport_adapter`、`sdjwt_adapter`、`jwt_x5c_adapter`、`x509_show`）就是把不同 credential 接到同一個 commitment + show contract 上。

---

## 4. 一致 / 對得上的部分

下面這些設計是與 paper 一致或概念對映成功的：

### 4.1 兩相 Prepare / Show 結構
- 本 repo `*_adapter` 都是 prepare 相，`*_show` 是 show 相，與 paper C₁ / C₂ 完全對映。
- Prepare 提早做、Show 隨 presentation 重做的時間切分，設計目的（攤平 RSA / ECDSA 大成本到 offline）和 paper 一樣（`zkID_construction.tex` §17）。

### 4.2 Issuer signature verification 與 attribute parsing
- Paper：`parse_SD-JWT(S)` + `h_i = SHA256(m_i || s_i)` + `ECDSA.verify(σ_I, PK_I)`。
- 本 repo SD-JWT path（`sdjwt_adapter::main`）：完全照 paper C₁ 三件事做（`verify_signature` ES256 → `verify_disclosure_hashes` 重算 `h_i` → 串接後 `digest` 得 `combined_hash`）。
- Passport path：把 paper 的「issuer sig」展開成 ICAO 9303 的雙層（CSCA → DSC、DSC → SOD）+ DG hash chain（DG → SOD）。語意完全對映 C₁ 的 issuer-sig + 屬性 hash 一致性。

### 4.3 Attribute commitment 是 Pedersen
- Paper：`com(m_1,...,m_N; r) = ∏ g_i^{m_i} · g_{N+1}^{r}`，binding & hiding。
- 本 repo v2/v3：`pedersen_commitment([credential_type, attr_hi, attr_lo, (pk_digest,) link_rand])`，由 Noir stdlib 對應到 Grumpkin 上的 EmbeddedCurvePoint。性質相同（DL hardness binding、blinding by `link_rand` 達 hiding）。

### 4.4 Linking via commitment 相等
- Paper：Verifier 比對兩相 R1CS instance 的 `comm_W_shared`（Hyrax 上的 Pedersen 列承諾）。
- 本 repo v2/v3：Verifier 直接比對兩相公開輸出的 commitment 點 `(C.x, C.y)`：
  ```rust
  // mopro-binding/src/openac_v3.rs
  if prepare.commitment != show.commitment {
      return Err(verification_error("commitment_mismatch"));
  }
  ```
  + 同時要求該座標真的出現在 proof 的 public input prefix（`verify_commitment_in_proof`）。
- 概念：兩相對同一 attribute / randomness 算出同一個 commitment 點。

### 4.5 In-circuit device binding
- Paper：`ECDSA.verify(σ_nonce, m_1[1])` 在 show circuit 內，因為 T256 scalar field == P-256 base field，所以「自然」。
- 本 repo v3：`openac_core::device::verify_device_binding` 用 Noir 的 `std::ecdsa_secp256r1::verify_signature` 黑盒原語把 P-256 ECDSA 直接拉進電路，不依賴底層曲線是 T256（見 §6.2）。

### 4.6 Predicate / selective disclosure
- Paper：`p_i = f_i(m_1, ..., m_n)`。
- 本 repo：
  - `check_age_above`、`check_bytes3_eq`、`two_digit_year_to_four`（`openac_core::predicate`）
  - `composite_show` 多了 `decode_domain` (X.509)、`age_at_least`
  - 揭露策略對齊 paper：當 disclose flag = false 時欄位不約束 / 強制歸零（見 `disclosure::main` v1 + `openac_show::evaluate_predicates` v3）。

### 4.7 Domain separator 跨層一致
- Paper 沒明確要求，但 `openac.preparev1` / `openac.show.v1` (v1)、`openac.show.v2` / `openac.scope.v2` (v2/v3) 在 Noir / Rust / Swift 三邊都對齊（見 `circuits/openac_core/src/show.nr` 與 `mopro-binding/src/openac_v3.rs::SHOW_DOMAIN_V2 = b"openac.show.v2"`、Swift `OpenACDomain`）。這是一個 paper 沒 spell out、但 zkID PoC 也預設要做的工程性一致。

### 4.8 Modularity（生效中）
- 論文強調 issuer-sig / commit / predicate / device binding 是可替換模組。
- 本 repo `openac_core::{commit, device, show, predicate, profile, smt, merkle}` 就是這個界面層；任何新 credential 只要寫一個 `*_adapter`（已經有 passport / sdjwt / jwt_x5c / x509）就能掛進來。
- v3 「Path A」展示的是論文預期的「換 device-binding 模組」這件事：把 device binding 從外部 proof 折回 commitment 內，不用動其他模組。

---

## 5. 不一致 / 與 paper 不同的部分

### 5.1 Backend 與曲線選擇
| | Paper / zkID | 本 repo |
|---|---|---|
| Proof system | Spartan2 + Hyrax-style Pedersen polynomial commitments + ZK Spartan blinding (Virgo) | Noir → mopro，UltraPlonk / UltraHonk |
| Setup | Transparent（無 trusted setup） | SRS-based（`openpassport_srs.bin`） |
| Native curve | T256（Tom256，scalar field = P-256 base field） | bn254 / Grumpkin（embedded curve） |
| Circuit DSL | Circom → R1CS | Noir → ACIR |
| 蒼白點 | Mobile prove ~2.1 s（iPhone17，1920 B JWT） | mopro FFI 尚未鏈進 iOS app（CLAUDE.md 標 ❌） |

**影響**：
- ECDSA-P256 在 Paper 是「自然 fit」，在我們這邊靠 Noir `std::ecdsa_secp256r1` blackbox 達成，constraint 數目較多但可行。
- Hyrax 列向量承諾（一個 `√n`-grouped Pedersen 結構）在 UltraPlonk 沒有對應原語，所以本 repo 改用「對 attribute hash 直接做 4 / 5 元 Pedersen」並 expose `(C.x, C.y)` 作為 public input — 這是「等價但更粗顆粒」的 commitment。

### 5.2 Prepare 重隨機化策略
- Paper：`prepareBatch` 一次產生 `m` 份 reblinded `{π_prepare^{(j)}}`，每次 presentation 用一份；同時在 show 也 reblind（`openac-sdk/wasm/src/lib.rs::present` 內 `shared_blinds` 用同一組 randomness 重 blind 兩個 proof）。
- 本 repo：每次 session 重抽 `link_rand` 重新跑 prepare prove；**沒有 batch / reblind**（v1 開始就是這樣，v2/v3 沿用，因 UltraPlonk 沒有對應的「proof 上 reblind」原語）。
- 後果：
  - 論文模型下 prepare 可以被「離線跑一次、線上隨便用」；我們是「每次 session prepare + show 一起跑」。
  - Mobile 端 prepare 成本比 paper 高（zkID 每次 show 是 reblind，~1.5 s；本 repo 每次都是 fresh prove，更慢）。
  - Unlinkability 屬性等價：fresh `link_rand` 等同每次重新 sample；但成本較重。

### 5.3 Linking 細節
- Paper：兩相同一個 `r_1^{(j)}` 重算 Hyrax 列承諾；Verifier 拿兩個 R1CS instance 比對 `comm_W_shared`（這是「對 witness 內部的 column」做承諾）。
- 本 repo：兩相是兩個獨立 Noir 電路，各自把 attribute 與 randomness 在 Pedersen 上算成 `(C.x, C.y)` 並當作 public input 暴露；linking 是「對外輸出值相等」+「值真的出現在 proof 的 public input prefix」（`verify_commitment_in_proof` scan FIELD_BYTES-aligned offsets）。
- 後果：
  - Paper 的 linking 是「對 witness column」綁定，比較緊；本 repo 是「對 commitment 點」綁定，較粗。
  - 但因為兩相 commitment 都來自同一個 `pk_digest` + `link_rand` + attributes（v3），語意上 sound：要造假必須同時湊出兩相 sound proof + 同一個 commitment 點，這需要中斷 DL on Grumpkin。

### 5.4 「ZK Spartan」blinding 在我們這邊不需要
- Paper §Adding ZK to Spartan：因為 Spartan 預設不是 ZK，必須加 random pads + masking polynomials。
- 本 repo：UltraPlonk/Honk 預設就是 ZK，這層整個不存在。

### 5.5 Trust root + revocation
- Paper：明說 revocation **out of scope**（`zkID_construction.tex` security section、表格 §7 也是 N/A）。
- 本 repo：
  - **CSCA Master List Merkle 包含證明**（`openac_core::merkle::verify_inclusion_depth_8`）— 把 ICAO Master List 的 root 變成 prepare 公開輸入，避免「自己生 RSA key 簽自己的 SOD」。
  - **DSC 撤銷 SMT non-membership**（`openac_core::smt::verify_non_membership`）— 在 prepare 內證明 DSC 不在 issuer 維護的撤銷 SMT。
  - X.509 path 也有對應的 Merkle / SMT。
- 是論文沒有的功能，但與 paper 的 modularity 設計相容（issuer-sig 模組擴展即可）。

### 5.6 Multi-credential bundling
- Paper 模型每次 show 對應**一張** credential；要組合多張需要分別 show + 額外 link argument。
- 本 repo `composite_show`：
  - 一個 ECDSA-P256 verify 同時驗 device pk
  - 用同一個 `pk_digest` 重開 passport commitment + X.509 commitment（兩個 `commit_attributes_v3`）
  - 用 `derive_x509_link_rand(link_rand_p)` 從 passport 的 `link_rand` 推導 X.509 的（避免分別 sample）
  - 一個 link tag = `pedersen_hash([link_rand_p, scope, epoch])` 同時為兩張 credential 服務
- 等同於把 paper 模型擴展到「同 device 持有的多張 credential 一次 show」。

### 5.7 Path A：把 device-binding 折入 commitment
- Paper：device binding 是 show 相 C₂ 的一條額外約束 `ECDSA.verify(σ_nonce, m_1[1])`，與 commitment 相對獨立。
- 本 repo v3：commitment 從 4 元（attrs + r）擴成 5 元，把 `pk_digest` 折進去：
  ```noir
  commit_attributes_v3(ctype, attr_hi, attr_lo, pk_digest, link_rand)
  ```
  - Show 重算 commitment 必須用同一個 `pk_digest`，而 `pk_digest` 由 in-circuit ECDSA verify 得到。
  - 等於：**prepare/show linking ⇒ device binding linking**，不需要 verifier 額外比對 ECDSA 是否確實簽在「跟 commitment 同一把 key 上」。
- 優點：少一份 device-binding proof / 少一個 metadata 對齊；減少「中間人換 ECDSA 公鑰」這條 attack surface。
- 是論文沒有但完全 compatible 的優化。

### 5.8 SHA256 / Pedersen 混用
- Paper：linking + tag 全部建在 Pedersen / Hyrax 體系內。
- 本 repo `openac_core::show.nr`：
  - `compute_challenge_digest` 用 SHA256（domain `openac.show.v2` || cx || cy || challenge || epoch）
  - `compute_link_tag` 用 `pedersen_hash([cx, cy, link_scope, epoch_field])`
  - 理由：challenge digest 是 one-way 用途、SHA256 in-circuit 已經被優化過（`sha256` crate）；scoped link tag 需要的是「Pedersen 一致性 + 對 verifier 公開」，所以用算術 hash。
- 是工程取捨，不是 paper 規定。

### 5.9 V1（SHA256 commitment）並未對齊 paper
- v1 路徑（`prepare_link` / `show_link` / `disclosure`）的 commitment 是 `SHA256(domain || sod_hash || mrz_hash || link_rand)`。
- 與 paper 的 Pedersen vector commit **不一致**，這在 `openAC.md` §D1 已經自我紀錄是 pragmatic 取捨。
- 現況：v2/v3 才開始對齊 paper；v1 是 legacy，建議新使用走 v3 / Path A。

### 5.10 Issuer 簽章覆蓋面
| | Paper / zkID | 本 repo |
|---|---|---|
| ES256 SD-JWT | ✅（jwt_es256） | ✅（`sdjwt_adapter`） |
| RS256 JWT | ✅（jwt_rs256） | ✅（`jwt_x5c_adapter`） |
| RSA-2048 ICAO 9303 passport | ❌ | ✅（`passport_verifier` + `passport_adapter`） |
| RSA-4096 (FIDO MOICA-G3) | ✅（feature flag） | ❌ |
| 完整 X.509 chain（CSCA → DSC、CSCA Merkle） | ❌ | ✅（passport + jwt_x5c） |

### 5.11 Verifier policy 嚴格度
- Paper：verifier 主要做兩件事 — 比 commit 相等、各自 verify。
- 本 repo `verify_openac_v3_with_verifier`：除了上面兩件外，還做：
  1. `prepare_vk_hash` / `show_vk_hash` trust check（比對固定 trusted hash）
  2. `verify_commitment_in_proof`：commitment 座標真的出現在 proof public input prefix
  3. `proof_contains_field`：`nonce_hash` 真的在 show proof public input 中
  4. Prepare TTL（`created_at_unix` ≤ `now_unix` ≤ `expires_at_unix`）
  5. challenge / nonce_hash / challenge_digest 一致性
  6. Unlinkable 模式 ⇒ `link_scope` is None & `link_tag == 0`；ScopedLinkable ⇒ `link_tag != 0`
- 是 paper 模型外的「verifier contract」工程化，避免「proof 對但你拿錯 metadata」的攻擊。

---

## 6. 具體優化（本 repo 比 paper 多的）

按重要性排序：

1. **Path A — pk_digest 折入 commitment**（§5.7）
   優點：兩相 linking 自動帶上 device binding，不用額外信任 metadata。

2. **Composite show（multi-credential bundling）**（§5.6）
   優點：一張 ECDSA 同時為 N 張同 device credential 服務，省下 show 時間。

3. **CSCA Master List Merkle inclusion + DSC 撤銷 SMT**（§5.5）
   優點：補上 paper 標 N/A 的 revocation；passport 場景不可缺。

4. **Verifier policy hardening**（§5.11）
   優點：把「proof 對 ↔ 系統安全」中間的 metadata 落差關閉。

5. **SHA256 / Pedersen 混用**（§5.8）
   優點：one-way digest 走 SHA256（in-circuit 較便宜），algebraic tag 走 Pedersen；compile cost 比全 Pedersen / 全 SHA 更低。

6. **3 種 issuer 簽章 + 4 種 credential adapter**（§5.10）
   優點：證明 paper 的 modularity 在實作層面真的活著。

---

## 7. 與 paper 比有「劣勢」或「沒做到」的部分

1. **沒有 prepareBatch / online 期 reblind**（§5.2）。每次 session 都得重跑 prepare，mobile 上比 paper 模型慢。改善方向：等 mopro / Noir 出 proof reblind 原語、或退到 hash 體系做 deterministic precompute cache。
2. **mopro FFI 尚未鏈進 iOS app**（CLAUDE.md 已標 ❌）；Swift 端目前只能跑 helper 與 Semaphore / SD-JWT fallback，整個 v3 path 還沒在 device 上跑過 end-to-end。
3. **沒有 RSA-4096 / MOICA-G3 等價路徑**（§5.10）。zkID 有 feature flag；本 repo 全 RSA 都鎖在 18 個 u128 limbs / 2048-bit。
4. **V1（SHA256 commitment）仍存在**（§5.9）。對應 `prepare_link` / `show_link` / `disclosure`，與 paper 不一致；建議在 README 和 docs 裡更明確標 deprecated。
5. **Linking 粒度比 paper 粗**（§5.3）。Paper 對 witness column 綁定；我們對 commitment 公開值綁定。理論上 sound，但抽象層級差一階。

---

## 8. Verification cross-reference

| 主題 | Paper / zkID 位置 | 本 repo 位置 |
|---|---|---|
| Prepare relation | `paper/zkID_construction.tex:32-42` (C₁ 定義) | `circuits/passport_adapter/src/main.nr::main` (RSA + DG + commitment)、`circuits/sdjwt_adapter/src/main.nr::main` (ES256 + disclosure) |
| Show relation | `paper/zkID_construction.tex:74-83` (C₂ 定義) | `circuits/openac_show/src/main.nr::main` (ECDSA + commitment open + predicates + verify_show)、`circuits/x509_show/src/main.nr` |
| Hyrax / commit_W_shared | `wallet-unit-poc/openac-sdk/wasm/src/lib.rs:287` (`comm_W_shared` equality) | `mopro-binding/src/openac_v3.rs:218-221` (commitment 點相等) |
| Reblind | `wallet-unit-poc/openac-sdk/wasm/src/lib.rs:194-223` (`shared_blinds` + `reblind_in_memory`) | **無對應**（每次 prepare fresh prove） |
| ZK Spartan | `paper/zkID_construction.tex:91-149` | **無對應**（Noir/UltraPlonk 預設 ZK） |
| In-circuit ECDSA | `paper/zkID_construction.tex:80` (`ECDSA.verify(σ_nonce, m_1[1])`) | `circuits/openac_core/src/device.nr::verify_device_binding`、`circuits/openac_show/src/main.nr:96-98` |
| Pedersen commit | `paper/zkID_construction.tex:53` (`com(m_1, ..., m_N; r_1)`) | `circuits/openac_core/src/commit.nr::commit_attributes` (v2)、`commit_attributes_v3` (v3 Path A) |
| Predicate | `paper/zkID_construction.tex:79` (`p_i = f_i(...)`) | `circuits/openac_core/src/predicate.nr` |
| Domain separator | n/a | `circuits/openac_core/src/show.nr:6-9`、`mopro-binding/src/openac_v3.rs:36`、`Sources/OpenPassportSwift.swift:147-150` |

---

## 9. 建議後續動作

1. **明確標記 v1 為 deprecated**：在 `circuits/{prepare_link,show_link}/README` 與 `openAC.md` D1 段落提示新流程走 v3 / Path A。
2. **加上 prepare 緩存層**（在 mopro-binding 而非 circuit 內）：把 `link_rand` / `pk_digest` / artifact 在 wallet 內 cache 一個 TTL，模擬 paper 的 `prepareBatch` 攤平 prove 成本（不需要等 reblind 原語）。
3. **跑 paper 的 mobile bench 對標**（zkID 提供 iPhone17 數字）：等 mopro FFI 接好後做一輪 bench，對照 5.6 GB / 2.1 s prepare 的數字評估我們在 mobile 是否落地。
4. **把 `composite_show` 寫進 paper-style spec**：multi-credential bundle 是 paper 沒的；建議補一段 spec 描述 link tag 與 derive_x509_link_rand 的安全推導。
5. **驗證 `verify_commitment_in_proof` 的搜尋順序**：目前是 FIELD_BYTES-aligned scan；在 UltraHonk public input layout 改變時要更新（已寫在 noir.rs 註解但建議加 lint）。

---

## 10. 2026-04-26 Update — zkID 大幅重構後的差距

zkID 在 4 月 26 日（撰寫此補充當日）剛 ship：
- 把 `age-verifier.circom` 砍掉，改成 **Generalised Predicates** evaluator（`(claim_index, op, operand)` + postfix AND/OR/NOT）— 詳見 `../zkID/generalized-predicates/README.md`。
- 加入 **mDoc / mDL (ISO 18013-5)** 完整支援（`mdoc-claim-verifier.circom` 等）。
- 公開 v1.0.0 / v2.0.0 / v3.0.0 tag。

新差距與決策（2026-04-26 設計回顧）：

| 差距 | 評估 | Direction | 處理 |
|---|---|---|---|
| Hardcoded disclose flags + 個別 predicate 結果外洩 | 真不優雅但 passport-niche 可接受 | **B** | 記錄延後：`spec/predicate-generalization.md` |
| Swift API 三版本 free functions 不統一 | DX 痛點 | **C** | 立刻做 |
| 缺 mDoc / mDL adapter | EUDI 必要 | **D** | 排程做 |
| Path A / composite / CSCA-Merkle / SMT 沒有正式 spec | 戰略低 ROI 高 | **E** | 立刻做 |
| Verify time / mobile bench 缺失 | 對齊 zkID iPhone17 數字 | benchmark 補強 | 排程做（依賴 mopro FFI 接 iOS） |

**目前 benchmark 覆蓋（2026-04-26 量測）**：
- ✅ Gate count / artifact bytes：12 個 circuit 全覆蓋（`benchmark/scripts/{perf,size}-bench.sh`）
- ⚠️ Prove / verify time：只有 `disclosure`（v1）有 `bench_*` test in `mopro-binding/src/noir.rs:521-607`，標 `#[ignore]` 預設不跑
- ❌ v2 / v3 路徑沒有 prove / verify time bench
- ❌ Mobile 平台 bench 完全沒有（zkID 已公開 iPhone 17 / Pixel 10 Pro 數字）

zkID 4/26 mobile 對標（`../zkID/wallet-unit-poc/README.md`）：
- iPhone 17：Prepare prove 2102ms / Reblind 884ms / Verify 137ms（payload 1920 B）
- iPhone 17 Show（與 payload 無關）：Prove 85ms / Verify 13ms
- Peak memory：Prepare 2.27 GiB / Show 1.96 GiB
