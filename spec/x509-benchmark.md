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

| Circuit | ACIR Opcodes | Brillig | 對照預算 / 備註 |
|---|---|---|---|
| passport_verifier | 11,736 | 3,081 | unchanged |
| data_integrity | 13,643 | 1,092 | unchanged |
| disclosure | 487 | 331 | unchanged (v1 legacy) |
| prepare_link | 283 | 338 | unchanged (v1 legacy) |
| show_link | 757 | 921 | unchanged (v1 legacy) |
| passport_adapter (v3) | **25,725** | 4,202 | budget ≤ 26,200 ✅ (+190 vs v2) |
| openac_show (v3) | **1,752** | 420 | budget ≤ 3,000 ✅ (+320 vs v2, in-circuit ECDSA) |
| sdjwt_adapter (v3) | **5,807** | 855 | budget ≤ 40,000 ✅ (first measurement, no prior) |
| **jwt_x5c_adapter (v3)** | **384,147** | 9,466 | budget ≤ 65,000 ❌ **5.9× over target, optimization required** |
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
| `passport_adapter` (v3) | ≤ 26,200 | v2 25,535 + Poseidon pk_digest (~240) + Pedersen 5-arity (~500) |
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

## 9. Path A known-deficit — `jwt_x5c_adapter`

**當前量測（2026-04-17）：384,147 ACIR opcodes，對 §3 預算 65,000 為 5.9× 超標。**
記錄於 `benchmark/expected/baseline.toml::gates.jwt_x5c_adapter`，並在
`benchmark/spec.toml::circuits.jwt_x5c_adapter` 以 `known_deficit = true` +
`gate_budget_status = "overshoot"` 明確標註。

### Overshoot 來源（粗估）

| 構成 | 估計 ACIR opcodes | 佔比 |
|---|---|---|
| RSA-2048 PKCS#1v1.5 leaf cert verify | ~25k | 6–7% |
| RSA-2048 PKCS#1v1.5 issuer cert verify | ~25k | 6–7% |
| RSA-2048 PKCS#1v1.5 JWT signature verify (RS256) | ~25k | 6–7% |
| SMT non-membership, `SMT_DEPTH = 128` (逐 bit SHA256 pair hash) | ~255k | **66%** |
| JWT payload SHA256（`JWT_PAYLOAD_LEN = 4096` bytes → 64 blocks） | ~40k | 10% |
| email_domain 搜尋迴圈（4096 × 16-byte marker） | ~10k | 3% |
| Pedersen v3 + pk_digest + boilerplate | < 5k | < 2% |

結論：**SMT depth 128 的 JSON-like binary path hash 是主要爆量元兇**（SHA256 in-circuit × 128 次）。
RSA × 3 加起來約 75k，實際上已經跟原始預算同量級；把 RSA 壓下去邊際效益有限。

### Optimization paths for v3.1

1. **Reduce SMT depth（最有效）**
   `SMT_DEPTH = 128 → 32`，用 serial number 前 4 bytes 作 key
   （可涵蓋 4,294,967,296 個獨立序號；對 Google OIDC、university issuer 足夠）。
   預期省 ~75%（~190k opcodes），降到 ~190k 總量。
2. **Move issuer RSA verify off-circuit（信任換 gate）**
   只驗 leaf cert 的 RSA 簽章；把 issuer 的真實性委託給 app-level Mozilla Root 檢查。
   預期省 ~25k，但威脅模型要重審（見本文件 §7.2 和 `spec/x509-design.md`）。
3. **Accept current number（維持正確性，改 UX 文案）**
   Prepare 是 one-shot（每個 credential 只跑一次，結果快取），
   在 iPhone 15 Pro 上的 UltraHonk proving time 預估 30–60 s；
   可接受，但要在 onboarding UX 上明示「正在建立加密憑證，請稍候…」。
4. **（研究選項）Poseidon vector commit 取代 SMT**
   需要 Noir stdlib 支援 Poseidon in-circuit；nargo 1.0.0-beta.19 尚未提供。
   Phase 7 research spike。

### Decision

**Deferred to post-ship; current implementation is functionally correct.**
v3.0 以 384,147 opcodes 交付，release notes 註明 proving time 風險；
v3.1 規劃走 option #1（SMT depth 降階），目標把 opcode 壓回 <100k。

