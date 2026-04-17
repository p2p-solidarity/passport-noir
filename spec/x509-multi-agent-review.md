# X.509 Multi-Agent Review

> 目標：判斷 `ref/x509-*.md` 這組設計，是否已經足夠拿來同時驅動 `../passport-noir` 與 `../airmeishi`。
> 結論先講：**還不夠。現在比較像方向稿，不是可直接分工實作的 shared spec。**

---

## Status 2026-04-17 — Path A 採用後的更新

> 本段在原批評之前新增，不刪除原批評內容。
> Path A = in-circuit ECDSA-P256 device binding + `H(enclave_pk)` 進 Pedersen commitment。
> 見 `x509-design.md` Changelog。

### 已解決（addressed in this spec pass）

| Review 條目 | 解決方式 | 落腳處 |
|---|---|---|
| §2-A Secure Enclave device binding 自相矛盾 | Path A：`enclave_pk` 作 private witness，`device_sk` 永不進 circuit；`pk_digest = Poseidon(pk_x, pk_y)` 進 Pedersen | `x509-design.md §D2/Changelog`, `x509-circuits.md §2`, `x509-issues.md P0-C` |
| §2-B JSON normalize 未收斂 | v1 採 hardcoded-issuer-offset + `SHA256(payload_raw) == payload_b64_hash` hash-binding；canonical JSON 範例刪除；v2 in-circuit normalize 歸 research | `x509-design.md §D1`, `x509-issues.md P0-G`, `x509-ios.md Step 4` |
| §1-A 缺 ownership 契約 | 新建 `x509-contract.md §1` ownership matrix | `x509-contract.md` |
| §1-B 缺 artifact / version matrix | 新建 `x509-contract.md §3` + `x509-migration.md §5` | `x509-contract.md`, `x509-migration.md` |
| §1-C 缺 envelope / verifier contract | 新建 `x509-contract.md §4` prepare/show envelope schema + §4.3 verifier must-check list | `x509-contract.md §4` |
| §1-D 缺 trust anchor operational spec | 新建 `x509-contract.md §5` Mozilla Root snapshot policy / SMT staleness | `x509-contract.md §5` |
| §1-E 缺 migration plan | 新建 `x509-migration.md`（含 v2 → v3 breaking change、re-issue flow、phase order） | `x509-migration.md` |
| §3-D 新的 linkage 隱私副作用未明示 | `x509-design.md §D3` + `x509-ios.md` 安全摘要明寫 link_rand_p Keychain ThisDeviceOnly、換機要 re-issue | `x509-design.md`, `x509-ios.md` |
| §3-E gate / latency 研究估算 | Gate budget 重排為 Path A 版本（composite_show 只跑一次 ECDSA） | `x509-benchmark.md §3` |

### 部分處理（partially addressed）

| Review 條目 | 現況 | 待辦 |
|---|---|---|
| §2-C `airmeishi` OIDC ingestion 不存在 | 本 repo spec 側已定好 `x509-ios.md` 流程；實作仍是新子系統 | airmeishi 側 PR 另立（Phase 3 milestone） |
| §2-D 現有 proof path 與新路徑不同 | migration plan 已列順序；app fallback chain 要同步更新 | airmeishi `MoproProofService` 改動隨 Phase 2 release 一起出 |
| §2-E verifier 能力差距 | contract §4 已定義 show envelope；Swift verifier helper 仍待建 | `OpenPassportSwift.swift` 需加 `verifyV3Envelope()`（passport-noir Phase 2） |
| §3-A 三代並存風險 | migration 明列 v1 deprecated / v2 grace period / v3 target | 實作期間要實際退場 v1；benchmark matrix 要拆出三組 |
| §3-B release coupling 風險 | contract §7 fail-closed 表 + vk hash pinning 已寫清 | airmeishi `prepare_openpassport_build.sh` 要改成讀 `manifest.json` |
| §3-C trust badge 混淆 | contract §6 trust level 表 + 明確 downgrade semantics | airmeishi UI 實作要對齊 |

### 尚未處理（still open）

| Review 條目 | 原因 |
|---|---|
| §2-F 文檔 drift | 是 repo-wide 問題，需要建立「每次 app / circuit 改動必同步 spec」的工程紀律。目前只在 CLAUDE.md 的 Rules 段落有「先讀再改」，沒有自動化檢查 |
| §3-D 多裝置 holder 模型 | Path A 明確放棄；列為 Phase 7 research。若需要改支援 iCloud cross-device，需要重做 `pk_digest` 邊界 |
| P0-E passport revocation SMT | 只在 contract / migration 層級談；Noir circuit 側尚未實作（order of ship phase 6） |
| In-circuit Mozilla Root Merkle（P0-F v2） | Research scope；v1 仍用 off-chain snapshot |

### 下一個 Review cycle 建議

1. Phase 2 PR 出來之後，跑一次「circuit v3 vs. spec」對照檢查（gate 預算 / I/O / trust badge）。
2. airmeishi 接 Phase 3 OAuth ingestion 前，多 agent 再審一次 contract §4 envelope schema 是否能實際對接 app 的 `OIDCService` / `ProofVerifierService`。
3. 90 天 grace period 結束前，檢查是否還有殘留 v2 commitment 卡在使用者 device，避免硬升 v3 砍掉可用 credential。

---

（以下為原始 2026 年 4 月中完成的 multi-agent review，未改動）

---

## 1. 這份設計現在最缺的東西

### A. 缺「哪個 repo 負責什麼」的契約

目前 `x509-design.md` 只描述電路與流程，沒有定義：

- 哪些 circuit 由 `passport-noir` 擁有
- 哪些 verifier / envelope / storage schema 由 `airmeishi` 擁有
- 哪些東西是 shared contract，不能各自解讀

這會直接卡住兩邊的實作切分。現在的 repo 狀態其實已經分成兩條線：

- `passport-noir` v1 是 SHA256 OpenAC：`prepare_link` / `show_link` / `Sources/OpenPassportSwift.swift`
- `passport-noir` v2 才是 Pedersen：`circuits/passport_adapter`, `circuits/openac_show`, `mopro-binding/src/openac_v2.rs`
- `airmeishi` 現在只真正接到 `disclosure` 類型的 passport proving，沒有接 `jwt_x5c_adapter` / `x509_show` / `composite_show`

如果沒有 ownership matrix，這份 spec 會變成第三條平行架構。

### B. 缺 artifact / version matrix

對 `airmeishi` 來說，真正會壞掉的通常不是 circuit 理論，而是 artifact 對不起來。

目前 app 只同步：

- `openpassport_disclosure.json`
- `openpassport_srs.bin`

見 `../airmeishi/scripts/prepare_openpassport_build.sh:25-27`，以及候選來源只找 `disclosure.json`，見 `../airmeishi/scripts/prepare_openpassport_build.sh:43-47`。

但 `x509-*.md` 新增的是：

- `jwt_x5c_adapter`
- `sdjwt_adapter`
- `x509_show`
- `composite_show`

文件沒有定義：

- 這些 artifact 的檔名
- 由誰 build
- 何時 publish
- app bundle 要放哪些版本
- 哪個 verifier key hash 對應哪個 app release
- 如果 app 跟 package 版本不同步要怎麼 fail closed

沒有這一層，`airmeishi` 會一直掉回 fallback，而不是穩定使用新流程。

### C. 缺 proof envelope / verifier contract

`x509-circuits.md` 描述了 circuit I/O，但沒有定義 presentation envelope。

這對 `airmeishi` 是致命缺口，因為它現在的 verifier 只會認：

- compact JWT
- JSON VP
- Semaphore proof payload

見 `../airmeishi/solidarity/Services/Identity/ProofVerifierService.swift:15-88` 與 `../airmeishi/solidarity/Services/Identity/ProofVerifierService+VPToken.swift:8-57,119-253`。

文件缺少：

- prepare artifact JSON schema
- show presentation JSON schema
- verifier 要驗哪些 public inputs
- 哪些欄位要 signed / hashed / persisted
- OID4VP 裡怎麼包這種 proof

沒有這個 contract，`passport-noir` 就算把 circuit 做完，`airmeishi` 也接不起來。

### D. 缺 trust anchor / revocation 的 operational spec

`x509-design.md` 說 `jwt_x5c_adapter` trust anchor 是 Mozilla Root，`x509-issues.md` 也承認目前 verifier 可能過時，見 `./x509-design.md:21-26`、`./x509-issues.md:9-10`。

但整組文件沒有回答：

- Mozilla Root snapshot 由誰發版
- 更新頻率
- app offline 多久算過期
- revocation SMT root 來源、更新週期、簽章來源
- verifier 是否接受 stale root
- proof 產生時用的 root 與驗證時用的 root 是否必須一致

這是 shared spec 必須明寫的，否則兩 repo 會各自實作一套「看起來差不多」的 trust policy。

### E. 缺 migration plan

`passport-noir` 現況是：

- v1：SHA256 OpenAC，完整度較高，見 `../passport-noir/CLAUDE.md:146-193`
- v2：Pedersen OpenAC verifier 存在，但 re-randomization / batch 還是 `unimplemented!()`，見 `../passport-noir/mopro-binding/src/openac_v2.rs:158-205`

但 `x509-design.md` / `x509-circuits.md` 直接假設 Pedersen + UltraHonk + cross-link 已經是主線。

文件缺：

- 先站在 v1 還是直接跳 v2
- 何者是研究分支，何者是 app-ready
- `airmeishi` 先接哪一版
- 如何從 disclosure-only 過渡到 composite show

沒有 migration plan，團隊會把研究設計誤認成實作 baseline。

## 2. 現在文件和 repo 現況最嚴重的錯位

### A. Secure Enclave device binding 在文件裡是自相矛盾的

這是最大問題。

`x509-design.md` 說：

- D2: `device key 納入 Pedersen commitment`，見 `./x509-design.md:37-40`

但 `x509-circuits.md` 一開始又說：

- `Device binding 不進 commitment`，見 `./x509-circuits.md:14-16`

接著它又要求：

- `device_sk` 作為 private witness 進 circuit，見 `./x509-circuits.md:53-69`
- `assert link_rand == Poseidon(device_sk, SALT_LINK_RAND)`，見 `./x509-circuits.md:67-68`
- `jwt_x5c_adapter` 也把 `device_sk` 當 input，見 `./x509-circuits.md:186-214`

但 `x509-issues.md` 自己承認 `link_rand_p` 實際上只能由 Secure Enclave 對固定訊息簽名後再 hash 派生，見 `./x509-issues.md:21-35`。

這代表：

- 真正可取得的是「簽名結果」
- 不是 Secure Enclave private key 本身

所以文件現在同時在要求兩件不能同時成立的事：

1. key 不可匯出
2. key 本體要當 witness 餵進 circuit

如果照這個 spec 做，最後只有兩條路：

- 放棄 in-circuit device binding
- 或放棄 Secure Enclave，不可避免退回可匯出 software secret

這不是 implementation detail，而是設計基礎還沒定。

### B. JSON normalize 的說法還沒有收斂成可落地版本

`x509-ios.md` Step 4 把 payload decode 後重新排序，見 `./x509-ios.md:98-117`。

但 `x509-issues.md` 已經說明：

- canonical JSON 跟 JWS 被簽的 bytes 不是同一件事
- 不能直接 assert `norm_hash == jwt_signed_hash`
- 真正正確做法是把 raw payload bytes 拉進 circuit 做 decode + normalize，見 `./x509-issues.md:58-90`

也就是說目前文件同時存在兩個層級：

- 較便宜但不完整的 app-layer normalize
- 較正確但更重的 in-circuit decode/normalize

這需要明確標示 v1/v2，而不是混在同一套 spec 裡。

### C. `airmeishi` 根本還沒具備這份 x509 iOS flow 的 integration surface

`x509-ios.md` 假設：

- Universal Link callback
- PKCE code exchange
- issuer registry
- x5c/JWKS token pipeline

見 `./x509-ios.md:18-93`。

但 `airmeishi` 現有 OIDC service 主要是：

- 產生 `openid://` request
- parse `presentation_definition`
- submit `vp_token`

見 `../airmeishi/solidarity/Services/Identity/OIDCService.swift:64-112,198-357`。

它不是 OAuth identity ingestion service，也沒有這份文件描述的 `OIDCIssuer` registry / token exchange / x5c extraction pipeline。

也就是說，`x509-ios.md` 其實不是對現有 app 的增量設計，而是新子系統。

### D. `airmeishi` 當前 proof path 跟文件假設不同

app 現在的 passport proving 邏輯是：

- 優先用 disclosure circuit
- 沒有就 fallback 到 Semaphore
- 再不行就 SD-JWT fallback

見 `../airmeishi/solidarity/Services/ZK/MoproProofService.swift:32-126,141-224`。

而 build script 也只同步 disclosure circuit，見 `../airmeishi/scripts/prepare_openpassport_build.sh:25-27,43-47`。

這和 `x509-design.md` 想要的 `jwt_x5c_adapter -> composite_show` 路徑完全不是同一條。

### E. verifier 能力和新 proof 類型不相容

`passport-noir` 的 Swift helper `verifyOpenACLinking()` 目前只驗：

- prepare/show commitment 是否一致
- sod/mrz hash 是否一致
- challenge digest / scope tag 是否一致

見 `../passport-noir/Sources/OpenPassportSwift.swift:282-340`。

`airmeishi` 端則沒有對應的 x509/openac envelope verifier，只有 JWT / VP / Semaphore verifier，見：

- `../airmeishi/solidarity/Services/Identity/ProofVerifierService.swift:15-88`
- `../airmeishi/solidarity/Services/Identity/ProofVerifierService+VPToken.swift:8-57,119-253`

所以這份 spec 少了最關鍵的一段：**verifier contract 實際要落在哪個 repo。**

### F. 文件已經出現新舊狀態漂移

一個明顯例子是 passport master list：

- `airmeishi/claude.md` 說 `masterListURL` 沒設，`passiveAuthPassed` 永遠 false
- 但實際 code 已經會在 bundle 內有 `masterList.pem` 時設定，見 `../airmeishi/solidarity/Services/Identity/NFCPassportReaderService.swift:73-76`

這件事本身不是 x509 問題，但它說明：**現在文檔已經有 drift**。

在這種狀態下再新增一套跨 repo spec，如果沒有版本與 owner，漂移只會更快。

## 3. 如果照目前做法推進，會造成什麼

### A. 會把 `passport-noir` 拉成三代並存

你現在其實已經有：

- v1 SHA256 OpenAC
- v2 Pedersen OpenAC
- ref/x509 新方向

如果沒有 hard scope，`passport-noir` 會同時維護：

- 舊的 prepare/show
- 新的 passport_adapter/openac_show/device_binding
- 還沒存在的 jwt_x5c_adapter/x509_show/composite_show

後果是：

- benchmark matrix 爆炸
- spec check / cross-circuit check 要多套維護
- Swift helper / Rust verifier / app integration 各自分叉

### B. `airmeishi` 的 release 風險會明顯升高

每多一個 proving circuit，app release 就多一組 coupling：

- circuit JSON
- SRS
- VK hash
- bundle inclusion
- fallback policy

而現在 app 已經明確依賴 bundle 內有對的 artifact 才能開 proof，見 `../airmeishi/solidarity/Services/ZK/MoproProofService.swift:35-46,152-165`。

這代表：

- build 沒 sync 到正確 artifact，功能就 silently 掉 fallback
- 版本 mismatch，很可能不是 compile error，而是 runtime downgrade

### C. 產品 trust model 會被搞混

`airmeishi` 目前把 `mopro-noir` 和 `semaphore-zk` 都標成 `trustLevel = "green"`，見：

- `../airmeishi/solidarity/Services/ZK/MoproProofService.swift:84-85,105-106`
- `../airmeishi/solidarity/Services/ZK/MoproProofService+Fallbacks.swift:61-66`

但這兩種 proof 的語義根本不同：

- `mopro-noir` 是 document-bound proof
- `semaphore-zk` 是 group membership style fallback

如果再塞進 `x509` / `sdjwt_adapter` / `x509-only`，沒有重新定義 trust taxonomy，UI 會把不同安全語義包成同一個 badge。

### D. 會引入新的隱私副作用

現在 spec 把所有 credential linkage 的根綁在 `link_rand_p`，而 `link_rand_p` 又綁 device，見：

- `./x509-issues.md:15-35`
- `./x509-circuits.md:159-162`

這樣做的後果：

- 同一 device 上的多 credential 會天然可 cross-link
- 換手機 / 重置 Secure Enclave 後，link identity 會整個變掉
- iCloud restore 無法保證 continuity
- 多裝置 holder 模型幾乎不存在

如果這是刻意的，文件要把它寫成產品決策，而不是只當技術技巧。

### E. 會高估效能與低估 proving 成本

`x509-benchmark.md` 的 gate / latency 預算目前比較像研究估算，見 `./x509-benchmark.md:33-72`。

尤其幾個風險點：

- in-circuit ECDSA + Pedersen open + domain predicate 很可能比表上重
- JSON normalize 若要做對，成本高於目前 Step 4 的簡化版本
- browser verify / QR / BLE payload size 還沒跟真正 envelope 格式綁定

如果用這份 benchmark 當 merge gate，團隊會很快被假 target 綁死。

## 4. 我建議怎麼改這份 md 設計

不要直接擴寫現有 `x509-*.md` 成超大全能 spec。比較穩的是把它拆成三層。

### Layer 1: shared-contract（唯一 source of truth）

建議新增一份類似 `x509-contract.md`，只放跨 repo 不可各自發明的東西：

- proof types 與版本號
- artifact 命名
- envelope schema
- verifier inputs
- VK hash / trust anchor policy
- fallback downgrade semantics

### Layer 2: passport-noir-implementation

這層才描述：

- 先做哪個 circuit
- v1 / v2 / research 的邊界
- benchmark 與 test vector
- Rust verifier / Swift helper 的責任

### Layer 3: airmeishi-integration

這層專門回答 app 問題：

- 何時 bundle 哪些 artifact
- onboarding / OAuth / OID4VP flow 要怎麼改
- UI 怎麼呈現 trust downgrade
- 失敗時怎麼 fallback

## 5. 最小可行收斂版本

如果你想先讓這件事可執行，我建議先把範圍縮到下面這版：

1. `passport-noir` 先不要同時做 `jwt_x5c_adapter` 和 `sdjwt_adapter`。
2. 先決定 device binding 要不要真的進 circuit；如果 Secure Enclave 是硬需求，就先採 envelope-level binding，不要假設 `device_sk` witness 可行。
3. `airmeishi` 先只接一種新 proof type，並先定義 envelope schema 與 fallback 文案。
4. 把 artifact/version matrix 寫死，不然 app integration 會一直掉回 `disclosure` 或 fallback。

## 6. 一句話總結

這套 `x509-*.md` 的核心問題不是想法不夠，而是**同時混了研究設計、未定決策、以及 app-ready integration 假設**。  
如果直接拿來驅動 `../passport-noir` 和 `../airmeishi`，最大的代價不是寫不出來，而是兩個 repo 會開始各自實作「自己理解的版本」。
