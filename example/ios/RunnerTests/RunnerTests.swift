import Flutter
import UIKit
import XCTest

@testable import rspl_secure_vault

/// Unit tests for RSPL Secure Vault iOS implementation.
///
/// Run these tests from Xcode or via: flutter test integration_test
class RunnerTests: XCTestCase {

    private let testKeyTag = "com.rishabhsoft.rspl_secure_vault.test"
    
    override func setUp() {
        super.setUp()
        // Clean up any existing test keys
        cleanupTestKey()
    }
    
    override func tearDown() {
        cleanupTestKey()
        super.tearDown()
    }
    
    private func cleanupTestKey() {
        let tag = testKeyTag.data(using: .utf8)!
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        SecItemDelete(deleteQuery as CFDictionary)
    }

    // MARK: - Plugin Tests
    
    func testPluginInitialize() throws {
        let plugin = RsplSecureVaultPlugin()
        let request = InitRequest(bundleId: testKeyTag)
        
        XCTAssertNoThrow(try plugin.initialize(request: request))
    }
    
    func testPluginEncryptReturnsResponse() throws {
        let plugin = RsplSecureVaultPlugin()
        let initRequest = InitRequest(bundleId: testKeyTag)
        try plugin.initialize(request: initRequest)
        
        let encryptRequest = EncryptRequest(plainText: "test data")
        let response = try plugin.encrypt(request: encryptRequest)
        
        XCTAssertNotNil(response.cipherText)
        XCTAssertFalse(response.cipherText!.isEmpty)
    }
    
    func testPluginDecryptReturnsOriginalData() throws {
        let plugin = RsplSecureVaultPlugin()
        let initRequest = InitRequest(bundleId: testKeyTag)
        try plugin.initialize(request: initRequest)
        
        let plainText = "sensitive data"
        let encryptRequest = EncryptRequest(plainText: plainText)
        let encryptResponse = try plugin.encrypt(request: encryptRequest)
        
        let decryptRequest = DecryptRequest(cipherText: encryptResponse.cipherText)
        let decryptResponse = try plugin.decrypt(request: decryptRequest)
        
        XCTAssertEqual(decryptResponse.plainText, plainText)
    }
    
    func testPluginThrowsWhenNotInitialized() {
        let plugin = RsplSecureVaultPlugin()
        let request = EncryptRequest(plainText: "test")
        
        XCTAssertThrowsError(try plugin.encrypt(request: request)) { error in
            if let vaultError = error as? RsplSecureVaultIOSError {
                XCTAssertEqual(vaultError.code, "UNINITIALIZED")
            }
        }
    }

    // MARK: - Basic Encryption/Decryption Tests
    
    func testEncryptAndDecryptSimpleString() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = "Hello, World!"
        
        let encrypted = try crypto.getEncryptedString(plain: plainText)
        XCTAssertFalse(encrypted.isEmpty)
        XCTAssertNotEqual(encrypted, plainText)
        
        let decrypted = try crypto.getDecryptedString(envelopeBase64: encrypted)
        XCTAssertEqual(decrypted, plainText)
    }
    
    func testEncryptAndDecryptEmptyString() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = ""
        
        let encrypted = try crypto.getEncryptedString(plain: plainText)
        let decrypted = try crypto.getDecryptedString(envelopeBase64: encrypted)
        
        XCTAssertEqual(decrypted, plainText)
    }
    
    func testEncryptAndDecryptUnicodeCharacters() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = "你好世界 🔐🛡️ مرحبا Привет"
        
        let encrypted = try crypto.getEncryptedString(plain: plainText)
        let decrypted = try crypto.getDecryptedString(envelopeBase64: encrypted)
        
        XCTAssertEqual(decrypted, plainText)
    }
    
    func testEncryptAndDecryptSpecialCharacters() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = "!@#$%^&*()_+-=[]{}|;':\",./<>?\\`~"
        
        let encrypted = try crypto.getEncryptedString(plain: plainText)
        let decrypted = try crypto.getDecryptedString(envelopeBase64: encrypted)
        
        XCTAssertEqual(decrypted, plainText)
    }
    
    func testEncryptAndDecryptLongString() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = String(repeating: "a", count: 10000)
        
        let encrypted = try crypto.getEncryptedString(plain: plainText)
        let decrypted = try crypto.getDecryptedString(envelopeBase64: encrypted)
        
        XCTAssertEqual(decrypted, plainText)
    }
    
    func testEncryptAndDecryptMultilineString() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = "Line 1\nLine 2\nLine 3\n\tIndented"
        
        let encrypted = try crypto.getEncryptedString(plain: plainText)
        let decrypted = try crypto.getDecryptedString(envelopeBase64: encrypted)
        
        XCTAssertEqual(decrypted, plainText)
    }
    
    func testEncryptAndDecryptJsonString() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = "{\"token\": \"abc123\", \"user\": {\"id\": 1, \"name\": \"Test\"}}"
        
        let encrypted = try crypto.getEncryptedString(plain: plainText)
        let decrypted = try crypto.getDecryptedString(envelopeBase64: encrypted)
        
        XCTAssertEqual(decrypted, plainText)
    }

    // MARK: - Envelope Structure Tests
    
    func testEnvelopeContainsAllRequiredFields() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let encrypted = try crypto.getEncryptedString(plain: "test")
        
        // Decode the base64 envelope
        guard let envData = Data(base64Encoded: encrypted),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: envData) else {
            XCTFail("Failed to decode envelope")
            return
        }
        
        // Verify all required fields via the Envelope struct
        XCTAssertNotNil(envelope.version)
        XCTAssertNotNil(envelope.ephemeralPub)
        XCTAssertNotNil(envelope.wrappedDEK)
        XCTAssertNotNil(envelope.dekNonce)
        XCTAssertNotNil(envelope.dekTag)
        XCTAssertNotNil(envelope.dataNonce)
        XCTAssertNotNil(envelope.ciphertext)
        XCTAssertNotNil(envelope.dataTag)
    }
    
    func testEnvelopeVersionIs1() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let encrypted = try crypto.getEncryptedString(plain: "test")
        
        guard let envData = Data(base64Encoded: encrypted),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: envData) else {
            XCTFail("Failed to decode envelope")
            return
        }
        
        XCTAssertEqual(envelope.version, 1)
    }
    
    func testEnvelopeNoncesAreCorrectSize() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let encrypted = try crypto.getEncryptedString(plain: "test")
        
        guard let envData = Data(base64Encoded: encrypted),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: envData) else {
            XCTFail("Failed to decode envelope")
            return
        }
        
        // Nonces should be 12 bytes (96 bits) when base64 decoded
        guard let dekNonce = Data(base64Encoded: envelope.dekNonce),
              let dataNonce = Data(base64Encoded: envelope.dataNonce) else {
            XCTFail("Failed to decode nonces")
            return
        }
        
        XCTAssertEqual(dekNonce.count, 12, "DEK nonce should be 12 bytes")
        XCTAssertEqual(dataNonce.count, 12, "Data nonce should be 12 bytes")
    }
    
    func testEnvelopeTagsAreCorrectSize() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let encrypted = try crypto.getEncryptedString(plain: "test")
        
        guard let envData = Data(base64Encoded: encrypted),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: envData) else {
            XCTFail("Failed to decode envelope")
            return
        }
        
        // Tags should be 16 bytes (128 bits) when base64 decoded
        guard let dekTag = Data(base64Encoded: envelope.dekTag),
              let dataTag = Data(base64Encoded: envelope.dataTag) else {
            XCTFail("Failed to decode tags")
            return
        }
        
        XCTAssertEqual(dekTag.count, 16, "DEK tag should be 16 bytes")
        XCTAssertEqual(dataTag.count, 16, "Data tag should be 16 bytes")
    }

    // MARK: - Uniqueness Tests
    
    func testEachEncryptionProducesUniqueOutput() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = "Same text"
        
        let encrypted1 = try crypto.getEncryptedString(plain: plainText)
        let encrypted2 = try crypto.getEncryptedString(plain: plainText)
        
        // Each encryption should produce different ciphertext
        XCTAssertNotEqual(encrypted1, encrypted2, "Encryptions should be unique")
        
        // But both should decrypt to the same plaintext
        XCTAssertEqual(try crypto.getDecryptedString(envelopeBase64: encrypted1), plainText)
        XCTAssertEqual(try crypto.getDecryptedString(envelopeBase64: encrypted2), plainText)
    }
    
    func testEphemeralKeyIsUniquePerEncryption() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        
        let encrypted1 = try crypto.getEncryptedString(plain: "test1")
        let encrypted2 = try crypto.getEncryptedString(plain: "test2")
        
        guard let envData1 = Data(base64Encoded: encrypted1),
              let envData2 = Data(base64Encoded: encrypted2),
              let envelope1 = try? JSONDecoder().decode(Envelope.self, from: envData1),
              let envelope2 = try? JSONDecoder().decode(Envelope.self, from: envData2) else {
            XCTFail("Failed to decode envelopes")
            return
        }
        
        XCTAssertNotEqual(envelope1.ephemeralPub, envelope2.ephemeralPub,
                          "Ephemeral public keys should be unique")
    }
    
    func testNoncesAreUniquePerEncryption() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        
        let encrypted1 = try crypto.getEncryptedString(plain: "test")
        let encrypted2 = try crypto.getEncryptedString(plain: "test")
        
        guard let envData1 = Data(base64Encoded: encrypted1),
              let envData2 = Data(base64Encoded: encrypted2),
              let envelope1 = try? JSONDecoder().decode(Envelope.self, from: envData1),
              let envelope2 = try? JSONDecoder().decode(Envelope.self, from: envData2) else {
            XCTFail("Failed to decode envelopes")
            return
        }
        
        XCTAssertNotEqual(envelope1.dekNonce, envelope2.dekNonce,
                          "DEK nonces should be unique")
        XCTAssertNotEqual(envelope1.dataNonce, envelope2.dataNonce,
                          "Data nonces should be unique")
    }

    // MARK: - Tampering Detection Tests
    
    func testTamperedCiphertextFailsDecryption() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let encrypted = try crypto.getEncryptedString(plain: "sensitive data")
        
        // Decode, tamper, re-encode
        guard var envData = Data(base64Encoded: encrypted),
              var envelope = try? JSONDecoder().decode(Envelope.self, from: envData) else {
            XCTFail("Failed to decode envelope")
            return
        }
        
        // Create a mutable copy of envelope with tampered ciphertext
        let originalCiphertext = envelope.ciphertext
        let tamperedCiphertext = "AAAA" + String(originalCiphertext.dropFirst(4))
        
        let tamperedEnvelope = Envelope(
            version: envelope.version,
            ephemeralPub: envelope.ephemeralPub,
            wrappedDEK: envelope.wrappedDEK,
            dekNonce: envelope.dekNonce,
            dekTag: envelope.dekTag,
            dataNonce: envelope.dataNonce,
            ciphertext: tamperedCiphertext,
            dataTag: envelope.dataTag
        )
        
        let tamperedData = try JSONEncoder().encode(tamperedEnvelope)
        let tamperedBase64 = tamperedData.base64EncodedString()
        
        XCTAssertThrowsError(try crypto.getDecryptedString(envelopeBase64: tamperedBase64))
    }
    
    func testTamperedTagFailsDecryption() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let encrypted = try crypto.getEncryptedString(plain: "sensitive data")
        
        guard let envData = Data(base64Encoded: encrypted),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: envData) else {
            XCTFail("Failed to decode envelope")
            return
        }
        
        // Tamper with data tag
        let originalTag = envelope.dataTag
        let tamperedTag = "AAAA" + String(originalTag.dropFirst(4))
        
        let tamperedEnvelope = Envelope(
            version: envelope.version,
            ephemeralPub: envelope.ephemeralPub,
            wrappedDEK: envelope.wrappedDEK,
            dekNonce: envelope.dekNonce,
            dekTag: envelope.dekTag,
            dataNonce: envelope.dataNonce,
            ciphertext: envelope.ciphertext,
            dataTag: tamperedTag
        )
        
        let tamperedData = try JSONEncoder().encode(tamperedEnvelope)
        let tamperedBase64 = tamperedData.base64EncodedString()
        
        XCTAssertThrowsError(try crypto.getDecryptedString(envelopeBase64: tamperedBase64))
    }
    
    func testInvalidBase64FailsDecryption() {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        
        XCTAssertThrowsError(try crypto.getDecryptedString(envelopeBase64: "not-valid-base64!!!"))
    }
    
    func testMalformedJsonFailsDecryption() {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        
        // Valid base64 but not valid JSON
        let invalidJson = Data("not json".utf8).base64EncodedString()
        
        XCTAssertThrowsError(try crypto.getDecryptedString(envelopeBase64: invalidJson))
    }

    // MARK: - Key Persistence Tests
    
    func testKeyPersistsAcrossInstances() throws {
        // First instance encrypts
        let crypto1 = EnvelopeCrypto(keyTag: testKeyTag)
        let encrypted = try crypto1.getEncryptedString(plain: "persistent test")
        
        // Second instance with same tag should be able to decrypt
        let crypto2 = EnvelopeCrypto(keyTag: testKeyTag)
        let decrypted = try crypto2.getDecryptedString(envelopeBase64: encrypted)
        
        XCTAssertEqual(decrypted, "persistent test")
    }
    
    func testDifferentKeyTagsAreIsolated() throws {
        let tag1 = testKeyTag + ".tag1"
        let tag2 = testKeyTag + ".tag2"
        
        defer {
            // Cleanup
            for tag in [tag1, tag2] {
                let tagData = tag.data(using: .utf8)!
                let deleteQuery: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tagData,
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
                ]
                SecItemDelete(deleteQuery as CFDictionary)
            }
        }
        
        let crypto1 = EnvelopeCrypto(keyTag: tag1)
        let crypto2 = EnvelopeCrypto(keyTag: tag2)
        
        let encrypted = try crypto1.getEncryptedString(plain: "test")
        
        // crypto2 should fail to decrypt because it uses a different key
        XCTAssertThrowsError(try crypto2.getDecryptedString(envelopeBase64: encrypted))
    }

    // MARK: - Performance Tests
    
    func testEncryptionPerformance() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let plainText = String(repeating: "a", count: 1000)
        
        measure {
            for _ in 0..<10 {
                _ = try? crypto.getEncryptedString(plain: plainText)
            }
        }
    }
    
    func testDecryptionPerformance() throws {
        let crypto = EnvelopeCrypto(keyTag: testKeyTag)
        let encrypted = try crypto.getEncryptedString(plain: String(repeating: "a", count: 1000))
        
        measure {
            for _ in 0..<10 {
                _ = try? crypto.getDecryptedString(envelopeBase64: encrypted)
            }
        }
    }

    // MARK: - Request/Response Data Class Tests
    
    func testInitRequestWithBundleId() {
        let request = InitRequest(bundleId: "com.example.test")
        XCTAssertEqual(request.bundleId, "com.example.test")
    }
    
    func testInitRequestWithNilBundleId() {
        let request = InitRequest()
        XCTAssertNil(request.bundleId)
    }
    
    func testEncryptRequestWithPlainText() {
        let request = EncryptRequest(plainText: "secret")
        XCTAssertEqual(request.plainText, "secret")
    }
    
    func testDecryptRequestWithCipherText() {
        let request = DecryptRequest(cipherText: "encrypted")
        XCTAssertEqual(request.cipherText, "encrypted")
    }
    
    func testEncryptResponseWithCipherText() {
        let response = EncryptResponse(cipherText: "encrypted_result")
        XCTAssertEqual(response.cipherText, "encrypted_result")
    }
    
    func testDecryptResponseWithPlainText() {
        let response = DecryptResponse(plainText: "decrypted_result")
        XCTAssertEqual(response.plainText, "decrypted_result")
    }
}
