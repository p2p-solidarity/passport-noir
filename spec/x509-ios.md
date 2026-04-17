# iOS OAuth + Prepare/Show Flow (Path A)

> 對應版本：circuit v3，adapter v1 / x509_show v1 / composite_show v1。
> 與 v0 差異：
>   - 移除 `normalizePayload()` Swift canonical JSON（密碼學不正確）
>   - App 傳 raw payload bytes，circuit 用 hash-binding 驗忠實度
>   - `link_rand_p` 改為 Keychain 隨機 bytes，非 enclave 派生
>   - Prepare/show 都需傳入 Secure Enclave **public key**（private witness to circuit）
>   - Show 階段由 Secure Enclave 對 `nonce_hash` 簽名 → ECDSA 簽章作 private witness

---

## 流程概覽

```
1. Universal Link OAuth callback（非 custom scheme）
2. PKCE code exchange
3. JWT header 找 x5c（優先）或 JWKS fallback
4. App 取 raw payload bytes（不做 normalize）
5. 取 Keychain link_rand_p（第一次則生成）
6. 取 Secure Enclave enclave_pk (public key)
7. Prepare circuit（前景 + progress UI）
8. Commitment → SwiftData
9. Show：verifier 給 nonce → SE sign → show circuit 生 proof → envelope
```

---

## Step 1：OAuth 啟動（PKCE）

```swift
func startOAuth(issuer: OIDCIssuer) {
    let verifier = PKCE.generateVerifier()        // 32 random bytes, base64url
    let challenge = PKCE.challenge(from: verifier)
    session.store(verifier: verifier, for: issuer)

    let url = issuer.authURL(
        clientID:      "solidarity-app",
        redirectURI:   "https://solidarity.gg/oauth",  // Universal Link，非 custom scheme
        scope:         "openid email",
        codeChallenge: challenge,
        method:        "S256"
    )
    webView.load(URLRequest(url: url))
}
```

---

## Step 2：攔截 callback

```swift
func scene(_ scene: UIScene, continue activity: NSUserActivity) {
    guard let url = activity.webpageURL,
          url.path == "/oauth",
          let code = url.queryValue("code"),
          let issuerID = url.queryValue("state")
    else { return }

    Task { await OAuthFlow.shared.handleCallback(code: code, issuerID: issuerID) }
}
```

---

## Step 3：Token exchange + x5c 擷取（P0-D 修復）

```swift
func handleCallback(code: String, issuerID: String) async throws {
    let issuer = registry.issuer(for: issuerID)
    let verifier = session.verifier(for: issuer)

    let tokens = try await issuer.exchangeCode(
        code: code,
        codeVerifier: verifier,
        redirectURI: "https://solidarity.gg/oauth"
    )

    let header = try JWT.header(tokens.idToken)

    // x5c 優先；不可行才 fallback JWKS
    let certChain: [Data]
    if let x5c = header.x5c, x5c.count >= 2 {
        certChain = try x5c.map {
            guard let d = Data(base64Encoded: $0) else { throw JWTError.malformedX5C }
            return d
        }
    } else {
        let jwks = try await issuer.fetchJWKS()
        let key = try jwks.key(kid: header.kid)
        guard let x5c = key.x5c, x5c.count >= 2 else { throw JWTError.noX5C }
        certChain = try x5c.map {
            guard let d = Data(base64Encoded: $0) else { throw JWTError.malformedX5C }
            return d
        }
    }

    try await prepareCircuit(idToken: tokens.idToken, certChain: certChain, issuer: issuer)
}
```

---

## Step 4：Payload hash-binding（**取代** `normalizePayload`）

```swift
/// 重要：**不**做 canonical JSON。JWS 簽的是 base64url(payload) bytes，
/// 不是 canonical JSON。電路只需要 app 傳 raw payload bytes，
/// 並 public-input `SHA256(raw_payload_bytes)` 讓 circuit 做 hash-binding。
func extractPayload(_ idToken: String) throws -> (rawPayload: Data, payloadB64Hash: Data, signedHash: Data) {
    let parts = idToken.split(separator: ".")
    guard parts.count == 3 else { throw JWTError.malformedJWT }

    let headerB64  = String(parts[0])
    let payloadB64 = String(parts[1])

    guard let rawPayload = Data(base64URLEncoded: payloadB64) else {
        throw JWTError.invalidPayload
    }

    // SHA256 over raw bytes (circuit hash-binding target)
    let payloadB64Hash = Data(SHA256.hash(data: rawPayload))

    // JWS signed hash: SHA256("header_b64.payload_b64")
    let signingInput = "\(headerB64).\(payloadB64)".data(using: .utf8)!
    let signedHash = Data(SHA256.hash(data: signingInput))

    return (rawPayload, payloadB64Hash, signedHash)
}
```

---

## Step 5：取 `link_rand_p`（Keychain 隨機 bytes，**非** enclave 派生）

```swift
enum LinkRandStore {
    static let service  = "gg.solidarity.openac"
    static let account  = "link_rand_p_v1"

    /// Return existing link_rand_p or generate and persist a new one.
    /// ThisDeviceOnly → iCloud backup 不會帶走。
    static func loadOrCreate() throws -> Data {
        if let existing = try keychainLoad(service: service, account: account) {
            return existing
        }
        var bytes = Data(count: 32)
        let result = bytes.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        guard result == errSecSuccess else { throw SecureStoreError.randomFailure }
        try keychainStore(
            service: service, account: account, value: bytes,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
        return bytes
    }
}
```

> **不**透過 Secure Enclave 簽章派生 `link_rand_p`。原因見 `x509-issues.md P0-C`。

---

## Step 6：取 Secure Enclave `enclave_pk`

```swift
enum EnclaveKeyStore {
    static let tag = "gg.solidarity.enclave.v1"

    /// 第一次呼叫建 key（不可匯出 private key），回傳 (pk_x, pk_y) 32-byte big-endian。
    static func ensureKey() throws -> EnclavePublicKey {
        if let existing = try loadExisting() { return existing }

        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage, .biometryAny],   // 依產品需求調 biometry
            nil
        )!

        let attrs: [CFString: Any] = [
            kSecAttrTokenID:        kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits:  256,
            kSecPrivateKeyAttrs:    [
                kSecAttrIsPermanent:    true,
                kSecAttrApplicationTag: tag,
                kSecAttrAccessControl:  access as Any,
            ],
        ]
        var err: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            throw SecureStoreError.enclaveKeygen(err!.takeRetainedValue())
        }
        return try extractPublicKey(privateKey: privateKey)
    }

    /// 取 uncompressed P-256 public key bytes (0x04 || x || y) → split 到 (x, y)
    private static func extractPublicKey(privateKey: SecKey) throws -> EnclavePublicKey {
        guard let pub = SecKeyCopyPublicKey(privateKey) else { throw SecureStoreError.pubkeyCopy }
        var err: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(pub, &err) as Data?,
              raw.count == 65, raw[0] == 0x04
        else { throw SecureStoreError.pubkeyFormat }
        return EnclavePublicKey(
            x: raw.subdata(in: 1..<33),
            y: raw.subdata(in: 33..<65)
        )
    }
}

struct EnclavePublicKey {
    let x: Data     // 32 bytes big-endian
    let y: Data     // 32 bytes big-endian
}
```

---

## Step 7：Prepare circuit（前景 + progress UI）

```swift
func prepareCircuit(idToken: String, certChain: [Data], issuer: OIDCIssuer) async throws {
    let (rawPayload, payloadB64Hash, signedHash) = try extractPayload(idToken)

    let leafTBS    = try X509Parser.tbs(from: certChain[0])
    let issuerTBS  = try X509Parser.tbs(from: certChain[1])

    let linkRandP = try LinkRandStore.loadOrCreate()
    let enclavePk = try EnclaveKeyStore.ensureKey()

    let smtWitness = try revocationStore
        .nonMembershipWitness(serial: X509Parser.serial(certChain[0]))

    let issuerFormatTag = issuer.circuitFormatTag   // e.g. 1 == GoogleOIDCv1

    let inputs = JWTCircuitInputs(
        // === PUBLIC ===
        issuerModulus:    X509Parser.modulus(certChain[1]),
        smtRoot:          revocationStore.currentRoot,
        jwtSignedHash:    signedHash,
        jwtPayloadB64Hash: payloadB64Hash,
        issuerFormatTag:  issuerFormatTag,

        // === PRIVATE ===
        leafTBS: leafTBS, issuerTBS: issuerTBS,
        leafSig: X509Parser.signature(certChain[0]),
        issuerSig: X509Parser.signature(certChain[1]),
        serialNumber: X509Parser.serial(certChain[0]),
        smtWitness: smtWitness,
        jwtPayloadRaw: rawPayload,         // ← 不做 normalize
        jwtSig: JWT.signature(idToken),

        // Path A 新增
        linkRandP:          linkRandP,
        enclavePkXBytes:    enclavePk.x,
        enclavePkYBytes:    enclavePk.y,
        enclavePkXField:    Field.fromBigEndian32(enclavePk.x),
        enclavePkYField:    Field.fromBigEndian32(enclavePk.y)
    )

    await MainActor.run {
        progressView.show(message: "驗證身份中… (~20 秒)")
    }
    let commitment = try await Task.detached(priority: .userInitiated) {
        try MoproProver.prove(circuit: "jwt_x5c_adapter_v1_rs256", inputs: inputs)
    }.value
    await MainActor.run { progressView.hide() }

    try credentialStore.save(commitment, type: .x509jwt, issuer: issuer.id)
}
```

---

## Step 8：Show flow（ECDSA sign by Secure Enclave）

```swift
func showCircuit(
    credential: StoredCredential,
    verifierNonce: Data,
    scope: Data,
    linkMode: Bool
) async throws -> ShowEnvelope {

    let nonceHash = Data(SHA256.hash(data: verifierNonce))

    // Secure Enclave 簽 nonce_hash → 取 DER signature → 轉成 r||s 64 bytes
    let rawSignature = try EnclaveKeyStore.signDER(nonceHash)
    let sig64 = try ECDSA.derToFixedRS(rawSignature)

    let linkRandP = try LinkRandStore.loadOrCreate()
    let enclavePk = try EnclaveKeyStore.ensureKey()

    let inputs = ShowCircuitInputs(
        // === PUBLIC ===
        inCommitment:       credential.commitment,
        nonceHash:          nonceHash,
        targetDomain:       credential.targetDomain,
        linkScope:          Field.fromBytes(scope),
        epoch:              Epoch.current,
        linkMode:           linkMode,

        // === PRIVATE ===
        attrHi:             credential.attrHi,
        attrLo:             credential.attrLo,
        pkDigest:           credential.pkDigest,
        linkRand:           credential.linkRand,
        enclavePkXField:    Field.fromBigEndian32(enclavePk.x),
        enclavePkYField:    Field.fromBigEndian32(enclavePk.y),
        enclavePkXBytes:    enclavePk.x,
        enclavePkYBytes:    enclavePk.y,
        signature:          sig64
    )

    let proof = try await MoproProver.prove(circuit: "x509_show_v1", inputs: inputs)
    return envelopeBuilder.build(proof: proof, credential: credential, linkMode: linkMode)
}
```

---

## Step 9：X.509-only fallback

用戶沒有護照時，直接走 `x509_show`，不觸碰 passport circuit：

- `link_rand_p` 仍從 Keychain 生成（不依賴護照 prepare 存在）。
- `enclave_pk` 仍是同一支 Secure Enclave key。
- 最終 envelope 中 `proofType = x509_v1`，trust badge 依 `x509-contract.md §6` 表決定。

---

## 安全 / 隱私摘要

| 風險 | 解法 |
|---|---|
| Custom scheme 劫持 | Universal Links（`https://solidarity.gg/oauth`） |
| PKCE 缺失 | 每次 auth 生成 code_verifier |
| AIA fetch MITM | x5c 從 JWT header 直接取，fallback 才用 JWKS |
| x5c malformed crash | guard + throw，非 force-unwrap |
| 背景 proof 被 cancel | 前景執行 + progress UI |
| JSON 被 app 改動 | `SHA256(payload_raw) == payload_b64_hash`（circuit 驗） |
| device_sk 洩漏 | device_sk 永不匯出也永不進 circuit；electronic 綁定靠 pk_digest |
| enclave_pk 公開 | enclave_pk 作 private witness，verifier 只看到 pk_digest（不在 public output） |
| link_rand_p 洩漏 | Keychain ThisDeviceOnly；洩漏只造成「同一裝置」可連 credential，但不會跨裝置重建 |
| 換手機 continuity | 明確產品決策：v3 不支援 iCloud cross-device。需要時走 re-issue flow（見 x509-migration.md） |
