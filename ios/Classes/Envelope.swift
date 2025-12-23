import Foundation
import CryptoKit
import Security

class EnvelopeCrypto {
    private let keyTag : String // Change to your app id
    private let aesKeySize = 32 // 256 bits
    private let gcmNonceSize = 12
    private let gcmTagSize = 16
    private let envelopeVersion = 1
    private let hkdfInfo = "envelope-wrapping".data(using: .utf8)!
    
    init(keyTag: String) {
        self.keyTag = keyTag
        _ = try? ensurePersistentKey()
    }
    
    // MARK: - Public API
    
    /// Encrypts the given plaintext string using envelope encryption.
    ///
    /// This method performs the following steps:
    /// 1. Generates a random Data Encryption Key (DEK).
    /// 2. Encrypts the plaintext using AES-GCM with the DEK.
    /// 3. Generates an ephemeral EC key pair for key agreement.
    /// 4. Retrieves the persistent keystore public key.
    /// 5. Performs ECDH key agreement to derive a shared secret.
    /// 6. Derives a Key Encryption Key (KEK) from the shared secret using HKDF.
    /// 7. Wraps (encrypts) the DEK using the KEK with AES-GCM.
    /// 8. Constructs an envelope containing all necessary cryptographic material and metadata,
    ///    serializes it to JSON, and encodes it as a Base64 string.
    ///
    /// - Parameter plain: The plaintext string to encrypt.
    /// - Returns: A Base64-encoded JSON envelope containing the encrypted data and cryptographic parameters.
    /// - Throws: An error if encryption or key operations fail.
    func getEncryptedString(plain: String) throws -> String {
        let plainBytes = Data(plain.utf8)
        
        // 1. Generate DEK
        let dek = SymmetricKey(size: .bits256)
        
        // 2. Encrypt plaintext with DEK (AES-GCM)
        let dataNonce = Data((0..<gcmNonceSize).map { _ in UInt8.random(in: 0...255) })
        let sealedBox = try AES.GCM.seal(plainBytes, using: dek, nonce: AES.GCM.Nonce(data: dataNonce))
        let ciphertext = sealedBox.ciphertext
        let dataTag = sealedBox.tag
        
        // 3. Create ephemeral EC key pair
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let ephemeralPub = ephemeralPriv.publicKey
        let ephemeralPubData = ephemeralPub.x963Representation
        
        // 4. Get persistent keystore public key
        // Note: The publicKey property of the wrapper works correctly for both paths.
        let keystorePub = try getKeyStorePublicKey()
        
        // 5. ECDH: derive shared secret
        let sharedSecret = try ephemeralPriv.sharedSecretFromKeyAgreement(with: keystorePub)
        
        // 6. HKDF -> KEK
        let kek = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(repeating: 0, count: 32),
            sharedInfo: hkdfInfo,
            outputByteCount: aesKeySize
        )
        
        // 7. Wrap DEK using KEK (AES-GCM)
        let dekNonce = Data((0..<gcmNonceSize).map { _ in UInt8.random(in: 0...255) })
        let dekSealed = try AES.GCM.seal(dek.withUnsafeBytes { Data($0) }, using: kek, nonce: AES.GCM.Nonce(data: dekNonce))
        let wrappedDekCipher = dekSealed.ciphertext
        let wrappedDekTag = dekSealed.tag
        
        // 8. Build envelope JSON and Base64 encode
        let envelope = Envelope(
            version: envelopeVersion,
            ephemeralPub: ephemeralPubData.base64EncodedString(),
            wrappedDEK: wrappedDekCipher.base64EncodedString(),
            dekNonce: dekNonce.base64EncodedString(),
            dekTag: wrappedDekTag.base64EncodedString(),
            dataNonce: dataNonce.base64EncodedString(),
            ciphertext: ciphertext.base64EncodedString(),
            dataTag: dataTag.base64EncodedString()
        )
        let envData = try JSONEncoder().encode(envelope)
        return envData.base64EncodedString()
    }
    
    /// Decrypts a base64-encoded envelope and returns the decrypted string.
    ///
    /// - Parameter envelopeBase64: The base64-encoded envelope string.
    /// - Throws: An error if the envelope is invalid, fields are missing, or decryption fails.
    /// - Returns: The decrypted plaintext string.
    func getDecryptedString(envelopeBase64: String) throws -> String {
        guard let envData = Data(base64Encoded: envelopeBase64) else {
            throw NSError(domain: "Envelope", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid envelope"])
        }
        let envelope = try JSONDecoder().decode(Envelope.self, from: envData)
        
        let ephemeralPubB64 = envelope.ephemeralPub
        let wrappedDEKB64 = envelope.wrappedDEK
        let dekNonceB64 = envelope.dekNonce
        let dekTagB64 = envelope.dekTag
        let dataNonceB64 = envelope.dataNonce
        let ciphertextB64 = envelope.ciphertext
        let dataTagB64 = envelope.dataTag
        
        guard let ephemeralPubData = Data(base64Encoded: ephemeralPubB64),
              let wrappedDEK = Data(base64Encoded: wrappedDEKB64),
              let dekNonce = Data(base64Encoded: dekNonceB64),
              let dekTag = Data(base64Encoded: dekTagB64),
              let dataNonce = Data(base64Encoded: dataNonceB64),
              let ciphertext = Data(base64Encoded: ciphertextB64),
              let dataTag = Data(base64Encoded: dataTagB64)
        else {
            throw NSError(domain: "Envelope", code: -2, userInfo: [NSLocalizedDescriptionKey: "Missing envelope fields"])
        }
        
        // Recreate ephemeral public key
        let ephemeralPub = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPubData)
        
        // Retrieve keystore private key
        let keystorePriv = try getKeyStorePrivateKey()
        
        // --- KEK DERIVATION: Correctly handling Secure Enclave vs. Simulator ---
        let kek: SymmetricKey
        let salt = Data(repeating: 0, count: 32)
        
        switch keystorePriv {
            case .regular(let key):
                // Simulator path: Use standard CryptoKit ECDH and HKDF
                let sharedSecret = try key.sharedSecretFromKeyAgreement(with: ephemeralPub)
                kek = sharedSecret.hkdfDerivedSymmetricKey(
                    using: SHA256.self,
                    salt: salt,
                    sharedInfo: hkdfInfo,
                    outputByteCount: aesKeySize
                )
                
            case .secureEnclave(let secKey):
                // Device/Secure Enclave path: Use Security framework for ECDH, then manual HKDF
                
                // 1. Convert CryptoKit ephemeral public key to SecKey format
                let publicKeyData = ephemeralPub.x963Representation
                var error: Unmanaged<CFError>?
                guard let peerPublicKey = SecKeyCreateWithData(publicKeyData as CFData, [
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                    kSecAttrKeySizeInBits as String: 256
                ] as CFDictionary, &error) else {
                    if let err = error?.takeRetainedValue() { throw err }
                    throw NSError(domain: "EnvelopeCrypto", code: -5, userInfo: [NSLocalizedDescriptionKey: "Failed to create peer public key"])
                }
                
                // 2. Perform key agreement using Security framework
                let parameters: [String: Any] = [:]
                guard let sharedSecretData = SecKeyCopyKeyExchangeResult(secKey, .ecdhKeyExchangeStandard, peerPublicKey, parameters as CFDictionary, &error) as Data? else {
                    if let err = error?.takeRetainedValue() { throw err }
                    throw NSError(domain: "EnvelopeCrypto", code: -6, userInfo: [NSLocalizedDescriptionKey: "Key agreement failed"])
                }
                
                // 3. Perform manual HKDF using the raw shared secret data
                kek = performHKDF(
                    inputKeyMaterial: sharedSecretData,
                    salt: salt,
                    info: hkdfInfo,
                    outputByteCount: aesKeySize
                )
        }
        // --- END KEK DERIVATION ---
        
        // Unwrap DEK using KEK (AES-GCM)
        let dekBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: dekNonce), ciphertext: wrappedDEK, tag: dekTag)
        let dekRaw = try AES.GCM.open(dekBox, using: kek)
        let dek = SymmetricKey(data: dekRaw)
        
        // Use DEK to decrypt data
        let dataBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: dataNonce), ciphertext: ciphertext, tag: dataTag)
        let plain = try AES.GCM.open(dataBox, using: dek)
        
        return String(data: plain, encoding: .utf8)!
    }
    
    // MARK: - Persistent EC Key in Keychain
    
    /// Ensures that a persistent private key exists in the Keychain.
    /// - Throws: An error if the key cannot be retrieved or created.
    private func ensurePersistentKey() throws {
        do {
            _ = try getKeyStorePrivateKey()
            // Key exists, nothing to do
        } catch let error as NSError {
            #if DEBUG
            print("[EnvelopeCrypto] Keychain error: domain=\(error.domain) code=\(error.code)")
            #endif
            if error.domain == "Keychain" && (error.code == Int(errSecItemNotFound) || error.code == -3) {
                // Key not found or invalid, delete any existing key and create a new one
                let tag = keyTag.data(using: .utf8)!
                let deleteQuery: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
                ]
                let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
                #if DEBUG
                print("[EnvelopeCrypto] Deleted old key, status: \(deleteStatus)")
                #endif
#if targetEnvironment(simulator)
                // Simulator: Use CryptoKit to generate key and store rawRepresentation in Keychain
                let privateKey = P256.KeyAgreement.PrivateKey()
                let keyData = privateKey.rawRepresentation
                let addQuery: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecValueData as String: keyData,
                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                ]
                let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
                #if DEBUG
                print("[EnvelopeCrypto] Added CryptoKit key to Keychain, status: \(addStatus)")
                #endif
#else
                // Device: Use Secure Enclave
                let access = SecAccessControlCreateWithFlags(
                    nil,
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                    .privateKeyUsage,
                    nil
                )!
                let attributes: [String: Any] = [
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecAttrKeySizeInBits as String: 256,
                    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                    kSecPrivateKeyAttrs as String: [
                        kSecAttrIsPermanent as String: true,
                        kSecAttrApplicationTag as String: tag,
                        kSecAttrAccessControl as String: access
                    ]
                ]
                var error: Unmanaged<CFError>?
                guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                    if let err = error?.takeRetainedValue() {
                        #if DEBUG
                        print("[EnvelopeCrypto] SecKeyCreateRandomKey error: \(err)")
                        #endif
                        throw err
                    } else {
                        #if DEBUG
                        print("[EnvelopeCrypto] Unknown error creating key")
                        #endif
                        throw NSError(domain: "EnvelopeCrypto", code: -100, userInfo: [NSLocalizedDescriptionKey: "Unknown error creating key"])
                    }
                }
                // Optionally, you can export the public key if needed
                _ = SecKeyCopyPublicKey(privateKey)
#endif
            } else {
                // Other error, rethrow
                throw error
            }
        }
    }
    
    /// Retrieves the private key for key agreement from the iOS Keychain using the specified application tag.
    /// - Throws: An `NSError` if the key cannot be found or retrieved from the Keychain, or if the key data is invalid.
    /// - Returns: A `PrivateKeyWrapper` instance.
    private func getKeyStorePrivateKey() throws -> PrivateKeyWrapper {
        let tag = keyTag.data(using: .utf8)!
#if targetEnvironment(simulator)
        // Simulator: retrieve raw key data and use CryptoKit initializer
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnData as String: true,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status != errSecSuccess {
            #if DEBUG
            print("[EnvelopeCrypto] SecItemCopyMatching failed: status=\(status)")
            #endif
            throw NSError(domain: "Keychain", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "SecItemCopyMatching failed with status \(status)"])
        }
        guard let keyData = item as? Data else {
            #if DEBUG
            print("[EnvelopeCrypto] Key data not found or invalid (simulator)")
            #endif
            throw NSError(domain: "Keychain", code: -3, userInfo: [NSLocalizedDescriptionKey: "Key data not found or invalid (simulator)"])
        }
        do {
            return .regular(try P256.KeyAgreement.PrivateKey(rawRepresentation: keyData))
        } catch {
            #if DEBUG
            print("[EnvelopeCrypto] Failed to create P256.KeyAgreement.PrivateKey (simulator): \(error)")
            #endif
            throw error
        }
#else
        // Device: retrieve Secure Enclave key reference
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status != errSecSuccess {
            #if DEBUG
            print("[EnvelopeCrypto] SecItemCopyMatching failed (device): status=\(status)")
            #endif
            throw NSError(domain: "Keychain", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "SecItemCopyMatching failed (device) with status \(status)"])
        }
        guard let itemRef = item, CFGetTypeID(itemRef) == SecKeyGetTypeID() else {
            #if DEBUG
            print("[EnvelopeCrypto] SecKey not found or invalid (device)")
            #endif
            throw NSError(domain: "Keychain", code: -3, userInfo: [NSLocalizedDescriptionKey: "SecKey not found or invalid (device)"])
        }
        let secKey = (itemRef as! SecKey)
        // Store SecKey directly for Secure Enclave
        return .secureEnclave(secKey)
#endif
    }
    
    /// Retrieves the public key associated with the private key stored in the key store.
    ///
    /// - Returns: The `P256.KeyAgreement.PublicKey` corresponding to the stored private key.
    /// - Throws: An error if the private key cannot be retrieved from the key store.
    private func getKeyStorePublicKey() throws -> P256.KeyAgreement.PublicKey {
        let priv = try getKeyStorePrivateKey()
        return priv.publicKey
    }
}

struct Envelope: Codable {
    let version: Int
    let ephemeralPub: String
    let wrappedDEK: String
    let dekNonce: String
    let dekTag: String
    let dataNonce: String
    let ciphertext: String
    let dataTag: String
}

// Helper to perform HKDF manually (needed for Secure Enclave keys)
private func performHKDF(inputKeyMaterial: Data, salt: Data, info: Data, outputByteCount: Int) -> SymmetricKey {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    let prk = HMAC<SHA256>.authenticationCode(for: inputKeyMaterial, using: SymmetricKey(data: salt))
    
    // HKDF-Expand: OKM = T(1) || T(2) || ... || T(N) where each T is HMAC-SHA256(PRK, T(i-1) || info || i)
    var okm = Data()
    var t = Data()
    let n = (outputByteCount + 31) / 32 // Number of 32-byte blocks needed
    
    for i in 1...n {
        var input = t
        input.append(info)
        input.append(UInt8(i))
        t = Data(HMAC<SHA256>.authenticationCode(for: input, using: SymmetricKey(data: prk.withUnsafeBytes { Data($0) })))
        okm.append(t)
    }
    
    return SymmetricKey(data: okm.prefix(outputByteCount))
}

// Type-erased wrapper for private keys to support both regular and Secure Enclave keys
private enum PrivateKeyWrapper {
    case regular(P256.KeyAgreement.PrivateKey)
    case secureEnclave(SecKey) // Store SecKey directly for Secure Enclave keys
    
    // This computed property handles getting the public key for both cases
    var publicKey: P256.KeyAgreement.PublicKey {
        switch self {
            case .regular(let key):
                return key.publicKey
            case .secureEnclave(let secKey):
                // Extract public key from SecKey
                guard let publicSecKey = SecKeyCopyPublicKey(secKey) else {
                    fatalError("Failed to get public key from SecKey")
                }
                var error: Unmanaged<CFError>?
                // SecKeyCopyExternalRepresentation returns the public key in X9.63 format for EC keys
                guard let publicKeyData = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data? else {
                    if let err = error?.takeRetainedValue() {
                        fatalError("Failed to export public key: \(err)")
                    }
                    fatalError("Failed to export public key")
                }
                do {
                    // Try to create from x963 representation
                    return try P256.KeyAgreement.PublicKey(x963Representation: publicKeyData)
                } catch {
                    fatalError("Failed to create public key from SecKey: \(error)")
                }
        }
    }
}
