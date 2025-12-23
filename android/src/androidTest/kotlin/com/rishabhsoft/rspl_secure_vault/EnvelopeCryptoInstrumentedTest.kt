package com.rishabhsoft.rspl_secure_vault

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * Instrumentation tests for EnvelopeCrypto.
 * These tests require an Android device or emulator to run.
 * 
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class EnvelopeCryptoInstrumentedTest {

    private lateinit var context: Context
    private val testKeyAlias = "com.rishabhsoft.rspl_secure_vault.test"

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        // Clean up any existing test keys
        cleanupTestKey()
    }

    private fun cleanupTestKey() {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(testKeyAlias)) {
                ks.deleteEntry(testKeyAlias)
            }
        } catch (e: Exception) {
            // Ignore cleanup errors
        }
    }

    // ============================================
    // Basic Encryption/Decryption Tests
    // ============================================

    @Test
    fun testEncryptAndDecryptSimpleString() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = "Hello, World!"

        val encrypted = crypto.getEncryptedString(plainText)
        assertNotNull(encrypted)
        assertNotEquals(plainText, encrypted)

        val decrypted = crypto.getDecryptedString(encrypted)
        assertEquals(plainText, decrypted)
    }

    @Test
    fun testEncryptAndDecryptEmptyString() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = ""

        val encrypted = crypto.getEncryptedString(plainText)
        assertNotNull(encrypted)

        val decrypted = crypto.getDecryptedString(encrypted)
        assertEquals(plainText, decrypted)
    }

    @Test
    fun testEncryptAndDecryptUnicodeCharacters() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = "你好世界 🔐🛡️ مرحبا Привет"

        val encrypted = crypto.getEncryptedString(plainText)
        val decrypted = crypto.getDecryptedString(encrypted)

        assertEquals(plainText, decrypted)
    }

    @Test
    fun testEncryptAndDecryptSpecialCharacters() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = "!@#\$%^&*()_+-=[]{}|;':\",./<>?\\`~"

        val encrypted = crypto.getEncryptedString(plainText)
        val decrypted = crypto.getDecryptedString(encrypted)

        assertEquals(plainText, decrypted)
    }

    @Test
    fun testEncryptAndDecryptLongString() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = "a".repeat(10000)

        val encrypted = crypto.getEncryptedString(plainText)
        val decrypted = crypto.getDecryptedString(encrypted)

        assertEquals(plainText, decrypted)
    }

    @Test
    fun testEncryptAndDecryptMultilineString() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = "Line 1\nLine 2\nLine 3\n\tIndented"

        val encrypted = crypto.getEncryptedString(plainText)
        val decrypted = crypto.getDecryptedString(encrypted)

        assertEquals(plainText, decrypted)
    }

    @Test
    fun testEncryptAndDecryptJsonString() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = """{"token": "abc123", "user": {"id": 1, "name": "Test"}}"""

        val encrypted = crypto.getEncryptedString(plainText)
        val decrypted = crypto.getDecryptedString(encrypted)

        assertEquals(plainText, decrypted)
    }

    // ============================================
    // Envelope Structure Tests
    // ============================================

    @Test
    fun testEnvelopeContainsAllRequiredFields() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val encrypted = crypto.getEncryptedString("test")

        // Decode the base64 envelope
        val envBytes = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
        val envelope = JSONObject(String(envBytes, Charsets.UTF_8))

        // Verify all required fields
        assertTrue("Missing version", envelope.has("version"))
        assertTrue("Missing ephemeralPub", envelope.has("ephemeralPub"))
        assertTrue("Missing wrappedDEK", envelope.has("wrappedDEK"))
        assertTrue("Missing dekNonce", envelope.has("dekNonce"))
        assertTrue("Missing dekTag", envelope.has("dekTag"))
        assertTrue("Missing dataNonce", envelope.has("dataNonce"))
        assertTrue("Missing ciphertext", envelope.has("ciphertext"))
        assertTrue("Missing dataTag", envelope.has("dataTag"))
    }

    @Test
    fun testEnvelopeVersionIs1() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val encrypted = crypto.getEncryptedString("test")

        val envBytes = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
        val envelope = JSONObject(String(envBytes, Charsets.UTF_8))

        assertEquals(1, envelope.getInt("version"))
    }

    @Test
    fun testEnvelopeNoncesAreCorrectSize() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val encrypted = crypto.getEncryptedString("test")

        val envBytes = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
        val envelope = JSONObject(String(envBytes, Charsets.UTF_8))

        // Nonces should be 12 bytes (96 bits) when base64 decoded
        val dekNonce = android.util.Base64.decode(envelope.getString("dekNonce"), android.util.Base64.NO_WRAP)
        val dataNonce = android.util.Base64.decode(envelope.getString("dataNonce"), android.util.Base64.NO_WRAP)

        assertEquals("DEK nonce should be 12 bytes", 12, dekNonce.size)
        assertEquals("Data nonce should be 12 bytes", 12, dataNonce.size)
    }

    @Test
    fun testEnvelopeTagsAreCorrectSize() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val encrypted = crypto.getEncryptedString("test")

        val envBytes = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
        val envelope = JSONObject(String(envBytes, Charsets.UTF_8))

        // Tags should be 16 bytes (128 bits) when base64 decoded
        val dekTag = android.util.Base64.decode(envelope.getString("dekTag"), android.util.Base64.NO_WRAP)
        val dataTag = android.util.Base64.decode(envelope.getString("dataTag"), android.util.Base64.NO_WRAP)

        assertEquals("DEK tag should be 16 bytes", 16, dekTag.size)
        assertEquals("Data tag should be 16 bytes", 16, dataTag.size)
    }

    // ============================================
    // Uniqueness Tests
    // ============================================

    @Test
    fun testEachEncryptionProducesUniqueOutput() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = "Same text"

        val encrypted1 = crypto.getEncryptedString(plainText)
        val encrypted2 = crypto.getEncryptedString(plainText)

        // Each encryption should produce different ciphertext
        assertNotEquals("Encryptions should be unique", encrypted1, encrypted2)

        // But both should decrypt to the same plaintext
        assertEquals(plainText, crypto.getDecryptedString(encrypted1))
        assertEquals(plainText, crypto.getDecryptedString(encrypted2))
    }

    @Test
    fun testEphemeralKeyIsUniquePerEncryption() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)

        val encrypted1 = crypto.getEncryptedString("test1")
        val encrypted2 = crypto.getEncryptedString("test2")

        val envBytes1 = android.util.Base64.decode(encrypted1, android.util.Base64.NO_WRAP)
        val envBytes2 = android.util.Base64.decode(encrypted2, android.util.Base64.NO_WRAP)

        val envelope1 = JSONObject(String(envBytes1, Charsets.UTF_8))
        val envelope2 = JSONObject(String(envBytes2, Charsets.UTF_8))

        // Ephemeral public keys should be different
        assertNotEquals(
            "Ephemeral public keys should be unique",
            envelope1.getString("ephemeralPub"),
            envelope2.getString("ephemeralPub")
        )
    }

    @Test
    fun testNoncesAreUniquePerEncryption() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)

        val encrypted1 = crypto.getEncryptedString("test")
        val encrypted2 = crypto.getEncryptedString("test")

        val envBytes1 = android.util.Base64.decode(encrypted1, android.util.Base64.NO_WRAP)
        val envBytes2 = android.util.Base64.decode(encrypted2, android.util.Base64.NO_WRAP)

        val envelope1 = JSONObject(String(envBytes1, Charsets.UTF_8))
        val envelope2 = JSONObject(String(envBytes2, Charsets.UTF_8))

        // Nonces should be different (statistically almost certain)
        assertNotEquals(
            "DEK nonces should be unique",
            envelope1.getString("dekNonce"),
            envelope2.getString("dekNonce")
        )
        assertNotEquals(
            "Data nonces should be unique",
            envelope1.getString("dataNonce"),
            envelope2.getString("dataNonce")
        )
    }

    // ============================================
    // Tampering Detection Tests
    // ============================================

    @Test(expected = Exception::class)
    fun testTamperedCiphertextFailsDecryption() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val encrypted = crypto.getEncryptedString("sensitive data")

        // Decode, tamper, re-encode
        val envBytes = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
        val envelope = JSONObject(String(envBytes, Charsets.UTF_8))

        // Tamper with ciphertext
        val originalCiphertext = envelope.getString("ciphertext")
        val tamperedCiphertext = "AAAA" + originalCiphertext.substring(4)
        envelope.put("ciphertext", tamperedCiphertext)

        val tamperedEnvelope = android.util.Base64.encodeToString(
            envelope.toString().toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
        )

        // This should throw due to GCM tag verification failure
        crypto.getDecryptedString(tamperedEnvelope)
    }

    @Test(expected = Exception::class)
    fun testTamperedTagFailsDecryption() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val encrypted = crypto.getEncryptedString("sensitive data")

        val envBytes = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
        val envelope = JSONObject(String(envBytes, Charsets.UTF_8))

        // Tamper with data tag
        val originalTag = envelope.getString("dataTag")
        val tamperedTag = "AAAA" + originalTag.substring(4)
        envelope.put("dataTag", tamperedTag)

        val tamperedEnvelope = android.util.Base64.encodeToString(
            envelope.toString().toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
        )

        // This should throw due to GCM tag verification failure
        crypto.getDecryptedString(tamperedEnvelope)
    }

    @Test(expected = Exception::class)
    fun testInvalidBase64FailsDecryption() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)

        // Invalid base64 string
        crypto.getDecryptedString("not-valid-base64!!!")
    }

    @Test(expected = Exception::class)
    fun testMalformedJsonFailsDecryption() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)

        // Valid base64 but not valid JSON
        val invalidJson = android.util.Base64.encodeToString(
            "not json".toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
        )

        crypto.getDecryptedString(invalidJson)
    }

    @Test(expected = Exception::class)
    fun testMissingFieldFailsDecryption() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)

        // Valid JSON but missing required fields
        val incompleteEnvelope = JSONObject().apply {
            put("version", 1)
            put("ephemeralPub", "test")
            // Missing other fields
        }

        val encoded = android.util.Base64.encodeToString(
            incompleteEnvelope.toString().toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
        )

        crypto.getDecryptedString(encoded)
    }

    // ============================================
    // Key Persistence Tests
    // ============================================

    @Test
    fun testKeyPersistsAcrossInstances() {
        // First instance encrypts
        val crypto1 = EnvelopeCrypto(context, testKeyAlias)
        val encrypted = crypto1.getEncryptedString("persistent test")

        // Second instance with same alias should be able to decrypt
        val crypto2 = EnvelopeCrypto(context, testKeyAlias)
        val decrypted = crypto2.getDecryptedString(encrypted)

        assertEquals("persistent test", decrypted)
    }

    @Test
    fun testDifferentKeyAliasesAreIsolated() {
        val alias1 = testKeyAlias + ".alias1"
        val alias2 = testKeyAlias + ".alias2"

        try {
            val crypto1 = EnvelopeCrypto(context, alias1)
            val crypto2 = EnvelopeCrypto(context, alias2)

            val encrypted = crypto1.getEncryptedString("test")

            // crypto2 should fail to decrypt because it uses a different key
            try {
                crypto2.getDecryptedString(encrypted)
                fail("Should have thrown exception when decrypting with wrong key")
            } catch (e: Exception) {
                // Expected - different keys cannot decrypt each other's data
            }
        } finally {
            // Cleanup
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            try { ks.deleteEntry(alias1) } catch (e: Exception) {}
            try { ks.deleteEntry(alias2) } catch (e: Exception) {}
        }
    }

    // ============================================
    // Performance Tests
    // ============================================

    @Test
    fun testEncryptionPerformance() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val plainText = "a".repeat(1000)

        val startTime = System.currentTimeMillis()
        repeat(10) {
            crypto.getEncryptedString(plainText)
        }
        val endTime = System.currentTimeMillis()

        val avgTime = (endTime - startTime) / 10
        // Each encryption should complete in reasonable time (< 500ms)
        assertTrue("Encryption took too long: ${avgTime}ms", avgTime < 500)
    }

    @Test
    fun testDecryptionPerformance() {
        val crypto = EnvelopeCrypto(context, testKeyAlias)
        val encrypted = crypto.getEncryptedString("a".repeat(1000))

        val startTime = System.currentTimeMillis()
        repeat(10) {
            crypto.getDecryptedString(encrypted)
        }
        val endTime = System.currentTimeMillis()

        val avgTime = (endTime - startTime) / 10
        // Each decryption should complete in reasonable time (< 500ms)
        assertTrue("Decryption took too long: ${avgTime}ms", avgTime < 500)
    }
}



