# Circuit Benchmark Specification (Path A)

> 基準：zkID paper Table 3/4（Spartan + Hyrax）
> 目標系統：UltraHonk + barretenberg（mopro iOS）
> 測試設備：iPhone 15 Pro（A17 Pro）為主，Pixel 8 Pro 為次

---

## 1. 現有 passport-noir ACIR Gate 數（baseline.toml / 2026-04-01）

| Circuit | Gates | 備註 |
|---|---|---|
| passport_verifier | 11,736 | RSA-2048 驗簽 |
| data_integrity | 13,643 | DG hash chain |
| disclosure | 487 | Legacy v1 (SHA256) |
| prepare_link | 283 | Legacy v1 |
| show_link | 757 | Legacy v1 |
| passport_adapter (v2) | 25,535 | RSA + DG + Pedersen(4-arity) |
| openac_show (v2) | 1,432 | Predicate + commitment open |
| device_binding | 162 | ECDSA P-256 native black-box |

### Current measurement (2026-04-17, nargo 1.0.0-beta.19)

Measured by `nargo info --package <name>` after Path A v3 migration landed.
`jwt_x5c_adapter` re-measured 2026-04-17 after v3.1 optimisation pass.

| Circuit | ACIR Opcodes | Brillig | 對照預算 / 備註 |
|---|---|---|---|
| passport_verifier | 11,736 | 3,081 | unchanged |
| data_integrity | 13,643 | 1,092 | unchanged |
| disclosure | 487 | 331 | unchanged (v1 legacy) |
| prepare_link | 283 | 338 | unchanged (v1 legacy) |
| show_link | 757 | 921 | unchanged (v1 legacy) |
| **passport_adapter (v3.1)** | **36,223** | 5,947 | budget ≤ 50,000 ✅ (+10,498 vs v3.0; CSCA chain + revocation SMT) |
| openac_show (v3) | **1,752** | 420 | budget ≤ 3,000 ✅ (+320 vs v2, in-circuit ECDSA) |
| sdjwt_adapter (v3) | **5,807** | 855 | budget ≤ 40,000 ✅ (first measurement, no prior) |
| **jwt_x5c_adapter (v3.1)** | **20,859** | 6,122 | budget ≤ 65,000 ✅ (+75 vs single-issuer; multi-issuer dispatch) |
| x509_show (v3) | **549** | 72 | budget ≤ 5,000 ✅ |
| composite_show (v3) | **684** | 97 | budget ≤ 8,000 ✅ |
| device_binding | 162 | 0 | unchanged (standalone unit baseline) |

---

## 2. zkID Paper 基準（供對照）

| Phase | iPhone 17 | Pixel 10 Pro | Proof Size |
|---|---|---|---|
| Prepare（C₁） | 2,987 ms | 7,318 ms | 109 kB |
| Show（C₂ + reblind） | 129 ms | 465 ms | 40 kB |

UltraHonk proof size 較小（O(log n)），proving time 在同 gate 下比 Spartan 慢。
目標：Show ≤ Spartan，Prepare 可寬鬆（一次性）。

---

## 3. Path A Gate 預算（revised 2026-04-17）

| Circuit | Gate 預算 | 預估依據 |
|---|---|---|
| `passport_adapter` (v3.1) | ≤ 50,000 | v3 25,725 + CSCA→DSC RSA (~8k) + Master List Merkle depth-8 (~1.5k) + DSC SMT (~1k); measured 36,223 |
| `jwt_x5c_adapter` (Prepare, RSA variant) | ≤ 65,000 | RSA×2 (~25k×2) + SMT (~8k) + SHA256(payload) + Poseidon + Pedersen |
| `jwt_x5c_adapter` (Prepare, ECDSA variant) | ≤ 45,000 | RSA cert×2 + ES256 JWT verify + SHA256 + Poseidon + Pedersen |
| `sdjwt_adapter` (Prepare) | ≤ 40,000 | ECDSA issuer + SHA256×（1+MAX_DISC）+ MerkleRoot(depth=5) + Poseidon + Pedersen |
| `openac_show` (v3, passport-only) | ≤ 3,000 | v2 1,432 + ECDSA (~200) + Poseidon pk_digest + Pedersen 5-arity open |
| `x509_show` (v1) | ≤ 5,000 | Pedersen open + ECDSA + domain predicate + link_tag |
| `composite_show` (v1) | ≤ 8,000 | 2× Pedersen open + 1× ECDSA + 2 predicates + link_tag |

> **規則**：任何新增 gate 都要有明確功能對應。不可因「防禦性編碼」增加 gate。
> composite_show **只跑一次** ECDSA，因為兩個 commitment 共享同一個 `pk_digest`。

---

## 4. 效能目標

### Prepare（一次性，可在前景執行）

| Metric | Target | Hard Limit |
|---|---|---|
| Proving time（iPhone 15 Pro） | ≤ 15 s | 30 s |
| Proving time（Pixel 8 Pro） | ≤ 30 s | 60 s |
| Peak memory | ≤ 1.5 GB | 2 GB |
| Proof size | ≤ 150 kB | 300 kB |

### Show（每次 presentation，UX 關鍵）

| Metric | Target | Hard Limit |
|---|---|---|
| Proving time（iPhone 15 Pro） | ≤ 500 ms | 1,000 ms |
| Proving time（Pixel 8 Pro） | ≤ 1,500 ms | 3,000 ms |
| Peak memory | ≤ 512 MB | 1 GB |
| Proof size | ≤ 50 kB | 100 kB |

### Verification

| Metric | Target |
|---|---|
| barretenberg WASM verify | ≤ 200 ms |
| Native iOS verify | ≤ 50 ms |

---

## 5. Benchmark 執行規則

### 測量方法

```swift
func benchmarkPrepare(circuit: String, inputs: CircuitInputs, runs: Int = 3) -> BenchmarkResult {
    var times: [Double] = []
    var peakMemory: Int = 0
    for _ in 0..<runs {
        let memBefore = memoryFootprint()
        let start = CFAbsoluteTimeGetCurrent()
        _ = try MoproProver.prove(circuit: circuit, inputs: inputs)
        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let mem = memoryFootprint() - memBefore
        times.append(elapsed * 1000)
        peakMemory = max(peakMemory, mem)
    }
    return BenchmarkResult(
        medianMs: times.sorted()[runs / 2],
        peakMemoryMB: peakMemory / 1_048_576,
        runs: runs
    )
}
```

### 標準 Fixture（所有 Path A circuit 必附）

```
passport_adapter (v3):
  sod_hash: SHA256(dg1||dg2)
  dg_count: 2
  enclave_pk: 固定 test vector（見 openac_core::device tests）
  link_rand_p: 0x01..0x20

jwt_x5c_adapter_rsa_v1:
  issuer_format_tag: 1 (GoogleOIDCv1)
  cert chain: RSA-2048 leaf + intermediate（test vectors via Python cryptography）
  jwt_payload_raw: 2048 bytes mock Google id_token payload
  enclave_pk: same fixture as passport
  link_rand_p: same as passport（model single-device user）

sdjwt_adapter_v1:
  issuer_format_tag: 2 (UniversitySDJWTv1)
  sd_count: 16
  disclosures: 4
  enclave_pk: same
  link_rand_p: same

x509_show_v1:
  in_commitment: output from jwt_x5c_adapter_rsa_v1 fixture
  nonce: sample bytes
  target_domain: "ntu.edu.tw"
  link_mode: true
  scope: sample Field
  epoch: 1

composite_show_v1:
  passport + x509 both present（two commitments from fixtures above）
  age_threshold: 18
  target_domain: "ntu.edu.tw"
```

### 回歸測試規則

1. PR 必須附 `nargo info` gate delta
2. Gate 超過預算 10% → block merge
3. Show circuit proving time 超 Hard Limit → block merge
4. Prepare circuit 只在 Hard Limit 超標時 block
5. Proof size 超 Hard Limit → block（影響 QR / BLE 傳輸）
6. `device_binding` legacy circuit：保留作單元測試 baseline，不再出現在 show flow

### Gate Count 測量

```bash
nargo info --package <circuit_name>
```

---

## 6. 對照基準（zkID 論文 Table 2）

| System | Precomp | Prove | Verify | Proof |
|---|---|---|---|---|
| Longelflow | 14.7s | 680ms | 325ms | 202kB |
| Crescent | 0.2s | 237ms | 118ms | 16kB |
| **OpenAC（zkID）** | **3.1s** | **192ms** | **83ms** | **149.7kB** |
| **passport-noir Path A 目標** | **≤15s** | **≤500ms** | **≤200ms** | **≤150kB** |

---

## 7. 超出預算時的處理原則

1. **JSON parsing 太重** → v1 固定 offset（x509-issues P0-G）。v2 research 再談 in-circuit normalize。
2. **RSA×2 cert chain 超標** → 考慮只驗 leaf，issuer 信任放 app-level Mozilla Root check（需重新審視威脅模型）。
3. **MerkleRoot(depth=5) 太重** → 降到 depth=4（16 個 `_sd`），或改 Poseidon vector commit。
4. **Show circuit 超 Hard Limit** → 最後手段才拆分成 parallel proof；Path A 的共享 `pk_digest` 已經把 ECDSA 壓到一次。

---

## 8. 新增 baseline.toml 欄位（建議）

```toml
[gates]
passport_adapter_v3 = ?      # 首次 compile 後填
jwt_x5c_adapter_rsa_v1 = ?
jwt_x5c_adapter_ecdsa_v1 = ?
sdjwt_adapter_v1 = ?
openac_show_v3 = ?
x509_show_v1 = ?
composite_show_v1 = ?

[tests]
# 新 circuit 的最低測試門檻
jwt_x5c_adapter_rsa_v1 = { positive = 3, negative = 2, total = 5 }
jwt_x5c_adapter_ecdsa_v1 = { positive = 3, negative = 2, total = 5 }
sdjwt_adapter_v1 = { positive = 5, negative = 2, total = 7 }
x509_show_v1 = { positive = 4, negative = 3, total = 7 }
composite_show_v1 = { positive = 4, negative = 3, total = 7 }
```

首次建電路後跑 `nargo info` 填值，並在 PR description 寫下對應本文件 §3 的預算達成狀況。

---

## 9. `jwt_x5c_adapter` v3.1 優化（landed 2026-04-17）

**v3.1 量測：20,784 ACIR opcodes，對 §3 預算 65,000 為 ~32% 使用率 ✅。**
相較 v3.0 的 384,147 opcodes，**降幅 94.6%**。
記錄於 `benchmark/expected/baseline.toml::gates.jwt_x5c_adapter = 20784`，
`benchmark/spec.toml::circuits.jwt_x5c_adapter` 的 `gate_budget_status = "within_budget"`，
`known_deficit` flag 已移除。

### v3.0 → v3.1 改動

| 優化 | v3.0 | v3.1 | 效果 |
|---|---|---|---|
| SMT 節點雜湊 | `SHA256(left_bytes \|\| right_bytes)` → 64-byte block | `pedersen_hash([DOMAIN_SMT_NODE, left, right])` | **最大宗節省**：每節點 ~1.7k → ~300 opcodes |
| `SMT_DEPTH` | 128 (逐 byte path) | 32 (serial_number[0..4] 4-byte key) | 4.3B keyspace 對 Google OIDC + university issuers 足夠 |
| `JWT_PAYLOAD_LEN` | 4096 bytes (64 SHA256 blocks) | 1024 bytes (16 SHA256 blocks) | Google id_token 實測 <1KB；硬斷言 ≤1024 |
| email_domain 解析 | 4080 × 16-byte marker loop | `issuer_format_tag` 固定偏移分派（P0-G v1 設計） | 與 `spec/x509-issues.md §P0-G` 對齊 |
| openac_core 常數 | — | 新增 `DOMAIN_SMT_NODE = 0x736d7431` (ASCII "smt1") | SMT arity-3 pedersen_hash 輸出空間與既有 arity-2/5 調用分離 |

### 安全性考量（已評估）

- **SMT 碰撞阻力**：Pedersen hash on bn254 為 ~127-bit DLP 硬度；SHA256 為 128-bit。
  單 bit 差異在 depth-32 SMT 路徑偽造情境下無實際意義（需 32 次序列 second-preimage）。
- **Domain separation**：`DOMAIN_SMT_NODE` 明確分隔 SMT 節點輸出與 `DOMAIN_PK_DIGEST`（`device.nr`）、
  profile salts。任何未來新增的 arity-3 `pedersen_hash` 調用都必須選擇不同 domain constant。
- **Off-circuit CRL tooling**：`smt_root` 作為 public input 由 app 從靜態 snapshot 提供。
  若 v2 接實時 CRL aggregator，aggregator 的 tree-build 工具必須同步切 Grumpkin Pedersen
  + `DOMAIN_SMT_NODE`；此為跨 repo 協調項（見 `spec/x509-contract.md §5.2`）。
- **Fixed-offset 策略**：app 必須在 prepare 前 canonicalize JWT payload 到已知 field 順序。
  `issuer_format_tag = 1` (GoogleOIDCv1) 對應 `email_domain` 值在 offset 17；
  tag 不等於 1 的情況 circuit `assert false`，fail-closed。

### 剩餘 gate 組成（v3.1）

| 構成 | 估計 ACIR opcodes | 佔比 |
|---|---|---|
| RSA-2048 PKCS#1v1.5 leaf cert verify | ~5–6k | ~25% |
| RSA-2048 PKCS#1v1.5 issuer cert verify | ~5–6k | ~25% |
| RSA-2048 PKCS#1v1.5 JWT signature verify | ~5–6k | ~25% |
| SMT non-membership (depth 32, Pedersen) | ~1k | ~5% |
| JWT payload SHA256 (1024 bytes = 16 blocks) | ~2–3k | ~10–15% |
| Pedersen v3 + pk_digest + fixed-offset extract | < 2k | < 10% |

> 粗估：實際 `nargo info` 顯示 main ACIR = 20,784；上表各項需另跑 profiler 驗證。

### 未來選項（非 blocking）

1. **Move issuer RSA verify off-circuit** — 可省 ~5–6k，但威脅模型要重審（`spec/x509-contract.md §5.1`）
2. **Poseidon vector commit 取代 Pedersen SMT** — 需 Noir stdlib 支援 Poseidon，nargo 1.0.0-beta.19 尚未提供
3. **In-circuit base64 decode + JSON normalize** — 解除 fixed-offset 限制，P0-G v2 研究項

### Decision

**v3.1 達 spec 預算；不再視為 known deficit。**
UltraHonk proving time 預估 iPhone 15 Pro ≤ 10 s，進入 Prepare target (15 s) 內。

