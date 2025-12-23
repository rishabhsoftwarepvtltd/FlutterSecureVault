package com.rishabhsoft.rspl_secure_vault

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import java.security.spec.ECGenParameterSpec
import javax.crypto.Mac

/**
 * EnvelopeCrypto provides secure envelope encryption using:
 * - AES-256-GCM for data encryption
 * - ECDH P-256 for key agreement
 * - HKDF-SHA256 for key derivation
 * 
 * Key storage strategy:
 * - API 31+: EC key directly in Android Keystore with PURPOSE_AGREE_KEY
 * - API 24-30: AES master key in Keystore, EC key encrypted and stored in SharedPreferences
 */
class EnvelopeCrypto(private val context: Context, private val keyAlias: String) {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val EC_CURVE = "secp256r1" // P-256
        private const val AES_KEY_SIZE_BITS = 256
        private const val GCM_NONCE_SIZE = 12 // bytes
        private const val GCM_TAG_SIZE_BITS = 128
        private const val ENVELOPE_VERSION = 1
        private val HKDF_INFO = "envelope-wrapping".toByteArray(Charsets.UTF_8)
        
        // For API < 31, we use AES key to wrap EC key
        private const val PREFS_NAME = "rspl_secure_vault_keys"
        private const val PREF_EC_PRIVATE_KEY = "_ec_priv"
        private const val PREF_EC_PUBLIC_KEY = "_ec_pub"
        private const val PREF_EC_NONCE = "_ec_nonce"
        private const val AES_KEY_ALIAS_SUFFIX = "_aes_wrapper"
    }

    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    init {
        ensurePersistentKey()
    }

    // Public API
    @Throws(Exception::class)
    fun getEncryptedString(plain: String): String {
        val plainBytes = plain.toByteArray(Charsets.UTF_8)

        // 1) Generate DEK (random 32 bytes)
        val dek = ByteArray(AES_KEY_SIZE_BITS / 8)
        SecureRandom().nextBytes(dek)

        // 2) Encrypt plaintext with DEK (AES-GCM)
        val dataNonce = ByteArray(GCM_NONCE_SIZE)
        SecureRandom().nextBytes(dataNonce)
        val (ciphertext, dataTag) = aesGcmEncrypt(dek, dataNonce, plainBytes, null)

        // 3) Create ephemeral EC key pair
        val ephemeralKeyPair = generateEphemeralECKeyPair()
        val ephemeralPriv = ephemeralKeyPair.private
        val ephemeralPubEncoded = ephemeralKeyPair.public.encoded // X.509

        // 4) Get persistent public key (works for both API paths)
        val keystorePub = getPublicKey() ?: throw IllegalStateException("Public key missing")

        // 5) ECDH: derive shared secret using ephemeral private key and stored public key
        val sharedSecret = performKeyAgreement(ephemeralPriv, keystorePub)

        // 6) HKDF -> KEK (32 bytes)
        val kek = hkdfSha256(sharedSecret, null, HKDF_INFO, AES_KEY_SIZE_BITS / 8)

        // 7) Wrap DEK using KEK -> AES-GCM
        val dekNonce = ByteArray(GCM_NONCE_SIZE)
        SecureRandom().nextBytes(dekNonce)
        val (wrappedDekCipher, wrappedDekTag) = aesGcmEncrypt(kek, dekNonce, dek, null)

        // 8) Build envelope JSON and Base64 encode
        val envelope = JSONObject().apply {
            put("version", ENVELOPE_VERSION)
            put("ephemeralPub", Base64.encodeToString(ephemeralPubEncoded, Base64.NO_WRAP))
            put("wrappedDEK", Base64.encodeToString(wrappedDekCipher, Base64.NO_WRAP))
            put("dekNonce", Base64.encodeToString(dekNonce, Base64.NO_WRAP))
            put("dekTag", Base64.encodeToString(wrappedDekTag, Base64.NO_WRAP))
            put("dataNonce", Base64.encodeToString(dataNonce, Base64.NO_WRAP))
            put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            put("dataTag", Base64.encodeToString(dataTag, Base64.NO_WRAP))
        }
        val envBytes = envelope.toString().toByteArray(Charsets.UTF_8)
        return Base64.encodeToString(envBytes, Base64.NO_WRAP)
    }

    @Throws(Exception::class)
    fun getDecryptedString(envelopeBase64: String): String? {
        val envBytes = Base64.decode(envelopeBase64, Base64.NO_WRAP)
        val envelope = JSONObject(String(envBytes, Charsets.UTF_8))

        val ephemeralPubB64 = envelope.getString("ephemeralPub")
        val wrappedDEKB64 = envelope.getString("wrappedDEK")
        val dekNonceB64 = envelope.getString("dekNonce")
        val dekTagB64 = envelope.getString("dekTag")
        val dataNonceB64 = envelope.getString("dataNonce")
        val ciphertextB64 = envelope.getString("ciphertext")
        val dataTagB64 = envelope.getString("dataTag")

        val ephemeralPubBytes = Base64.decode(ephemeralPubB64, Base64.NO_WRAP)
        val wrappedDEK = Base64.decode(wrappedDEKB64, Base64.NO_WRAP)
        val dekNonce = Base64.decode(dekNonceB64, Base64.NO_WRAP)
        val dekTag = Base64.decode(dekTagB64, Base64.NO_WRAP)
        val dataNonce = Base64.decode(dataNonceB64, Base64.NO_WRAP)
        val ciphertext = Base64.decode(ciphertextB64, Base64.NO_WRAP)
        val dataTag = Base64.decode(dataTagB64, Base64.NO_WRAP)

        // Recreate peer public key (the ephemeral public key from encryption)
        val keyFactory = KeyFactory.getInstance("EC")
        val x509Spec = X509EncodedKeySpec(ephemeralPubBytes)
        val ephemeralPub = keyFactory.generatePublic(x509Spec) as PublicKey

        // Retrieve our private key and perform ECDH
        val privateKey = getPrivateKey() ?: throw IllegalStateException("Private key missing")
        
        // ECDH shared secret using our private key and the ephemeral public key
        val sharedSecret = performKeyAgreement(privateKey, ephemeralPub)

        // HKDF -> KEK
        val kek = hkdfSha256(sharedSecret, null, HKDF_INFO, AES_KEY_SIZE_BITS / 8)

        // Unwrap DEK using KEK (AES-GCM)
        val dek = aesGcmDecrypt(kek, dekNonce, wrappedDEK, dekTag, null)
            ?: throw AEADBadTagException("DEK unwrap failed")

        // Use DEK to decrypt data
        val plain = aesGcmDecrypt(dek, dataNonce, ciphertext, dataTag, null)
            ?: throw AEADBadTagException("Data decryption failed")

        return String(plain, Charsets.UTF_8)
    }

    // ========================================================================
    // Key Management - Different strategies for API 31+ vs API 24-30
    // ========================================================================

    private fun ensurePersistentKey() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // API 31+: Use EC key directly in Keystore with PURPOSE_AGREE_KEY
            ensureKeystoreECKey()
        } else {
            // API 24-30: Use AES key in Keystore to wrap a software EC key
            ensureWrappedECKey()
        }
    }

    /**
     * API 31+: Create EC key directly in Android Keystore with PURPOSE_AGREE_KEY
     */
    private fun ensureKeystoreECKey() {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (!ks.containsAlias(keyAlias)) {
                val kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
                )
                
                val purposes = KeyProperties.PURPOSE_AGREE_KEY or KeyProperties.PURPOSE_SIGN
                
                val builder = KeyGenParameterSpec.Builder(keyAlias, purposes)
                    .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setUserAuthenticationRequired(false)
                    .setKeySize(256)

                // Request StrongBox if available (API 28+)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    val pm = context.packageManager
                    if (pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                        builder.setIsStrongBoxBacked(true)
                    }
                }

                kpg.initialize(builder.build())
                kpg.generateKeyPair()
            }
        } catch (e: Exception) {
            throw RuntimeException("Keystore EC key generation failed", e)
        }
    }

    /**
     * API 24-30: Create AES key in Keystore, generate software EC key, and wrap it
     */
    private fun ensureWrappedECKey() {
        val aesAlias = keyAlias + AES_KEY_ALIAS_SUFFIX
        val privKeyPref = keyAlias + PREF_EC_PRIVATE_KEY
        val pubKeyPref = keyAlias + PREF_EC_PUBLIC_KEY
        val noncePref = keyAlias + PREF_EC_NONCE

        // Check if we already have a wrapped key
        if (prefs.contains(privKeyPref) && prefs.contains(pubKeyPref)) {
            // Verify AES key still exists
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(aesAlias)) {
                return // Already set up
            }
            // AES key missing, need to regenerate everything
            prefs.edit()
                .remove(privKeyPref)
                .remove(pubKeyPref)
                .remove(noncePref)
                .apply()
        }

        // Ensure AES wrapper key exists in Keystore
        ensureAESWrapperKey(aesAlias)

        // Generate new EC key pair in software
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec(EC_CURVE))
        val keyPair = kpg.generateKeyPair()

        // Encrypt the EC private key using AES key from Keystore
        val privateKeyBytes = keyPair.private.encoded
        val publicKeyBytes = keyPair.public.encoded

        val aesKey = getAESWrapperKey(aesAlias)
        
        // Let cipher generate its own IV (required for Keystore-backed keys)
        val (encryptedPrivateKey, generatedNonce) = aesGcmEncryptWithKeystoreKey(aesKey, privateKeyBytes)

        // Store encrypted private key and public key
        prefs.edit()
            .putString(privKeyPref, Base64.encodeToString(encryptedPrivateKey, Base64.NO_WRAP))
            .putString(pubKeyPref, Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP))
            .putString(noncePref, Base64.encodeToString(generatedNonce, Base64.NO_WRAP))
            .apply()
    }

    /**
     * Create AES-256 key in Android Keystore for wrapping EC key
     */
    private fun ensureAESWrapperKey(alias: String) {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(alias)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
            )
            
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)

            // Request StrongBox if available (API 28+)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val pm = context.packageManager
                if (pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                    builder.setIsStrongBoxBacked(true)
                }
            }

            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        }
    }

    private fun getAESWrapperKey(alias: String): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(alias, null) as KeyStore.SecretKeyEntry
        return entry.secretKey
    }

    // ========================================================================
    // Key Retrieval - Unified interface for both API paths
    // ========================================================================

    private fun getPublicKey(): PublicKey? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            getKeystorePublicKey()
        } else {
            getWrappedPublicKey()
        }
    }

    private fun getPrivateKey(): PrivateKey? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            getKeystorePrivateKey()
        } else {
            getWrappedPrivateKey()
        }
    }

    /**
     * API 31+: Get public key directly from Keystore
     */
    private fun getKeystorePublicKey(): PublicKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry ?: return null
        return entry.certificate.publicKey
    }

    /**
     * API 31+: Get private key directly from Keystore
     */
    private fun getKeystorePrivateKey(): PrivateKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry ?: return null
        return entry.privateKey
    }

    /**
     * API 24-30: Get public key from SharedPreferences
     */
    private fun getWrappedPublicKey(): PublicKey? {
        val pubKeyPref = keyAlias + PREF_EC_PUBLIC_KEY
        val pubKeyB64 = prefs.getString(pubKeyPref, null) ?: return null
        val pubKeyBytes = Base64.decode(pubKeyB64, Base64.NO_WRAP)
        
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(X509EncodedKeySpec(pubKeyBytes))
    }

    /**
     * API 24-30: Decrypt and return private key
     */
    private fun getWrappedPrivateKey(): PrivateKey? {
        val aesAlias = keyAlias + AES_KEY_ALIAS_SUFFIX
        val privKeyPref = keyAlias + PREF_EC_PRIVATE_KEY
        val noncePref = keyAlias + PREF_EC_NONCE

        val encryptedPrivKeyB64 = prefs.getString(privKeyPref, null) ?: return null
        val ivB64 = prefs.getString(noncePref, null) ?: return null

        val encryptedPrivKey = Base64.decode(encryptedPrivKeyB64, Base64.NO_WRAP)
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)

        val aesKey = getAESWrapperKey(aesAlias)
        val privateKeyBytes = aesGcmDecryptWithKeystoreKey(aesKey, iv, encryptedPrivKey)
            ?: throw IllegalStateException("Failed to decrypt private key")

        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))
    }

    // ========================================================================
    // Cryptographic Helpers
    // ========================================================================

    private fun generateEphemeralECKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        val spec = ECGenParameterSpec(EC_CURVE)
        kpg.initialize(spec)
        return kpg.generateKeyPair()
    }

    private fun performKeyAgreement(priv: PrivateKey, pub: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    // AES-GCM with byte array key (for DEK operations)
    private fun aesGcmEncrypt(keyBytes: ByteArray, nonce: ByteArray, plain: ByteArray, aad: ByteArray?): Pair<ByteArray, ByteArray> {
        val keySpec = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(GCM_TAG_SIZE_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        aad?.let { cipher.updateAAD(it) }
        val ctWithTag = cipher.doFinal(plain)
        val ctLen = ctWithTag.size - (GCM_TAG_SIZE_BITS / 8)
        val ct = ctWithTag.copyOfRange(0, ctLen)
        val tag = ctWithTag.copyOfRange(ctLen, ctWithTag.size)
        return Pair(ct, tag)
    }

    private fun aesGcmDecrypt(keyBytes: ByteArray, nonce: ByteArray, ciphertext: ByteArray, tag: ByteArray, aad: ByteArray?): ByteArray? {
        val keySpec = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(GCM_TAG_SIZE_BITS, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        aad?.let { cipher.updateAAD(it) }
        val combined = ByteBuffer.allocate(ciphertext.size + tag.size).apply {
            put(ciphertext)
            put(tag)
        }.array()
        return try {
            cipher.doFinal(combined)
        } catch (e: AEADBadTagException) {
            null
        }
    }

    // AES-GCM with Keystore SecretKey - let cipher generate IV (required for Keystore keys)
    private fun aesGcmEncryptWithKeystoreKey(key: SecretKey, plain: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Don't provide IV - let Keystore generate it
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val ciphertextWithTag = cipher.doFinal(plain)
        // Get the IV that was generated
        val iv = cipher.iv
        return Pair(ciphertextWithTag, iv)
    }

    private fun aesGcmDecryptWithKeystoreKey(key: SecretKey, iv: ByteArray, ciphertextWithTag: ByteArray): ByteArray? {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(GCM_TAG_SIZE_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
        return try {
            cipher.doFinal(ciphertextWithTag)
        } catch (e: AEADBadTagException) {
            null
        }
    }

    // HKDF-SHA256 (extract+expand)
    private fun hkdfSha256(sharedSecret: ByteArray, salt: ByteArray?, info: ByteArray?, outputLen: Int): ByteArray {
        val actualSalt = salt ?: ByteArray(32) { 0.toByte() }
        // Extract
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(actualSalt, "HmacSHA256"))
        val prk = mac.doFinal(sharedSecret)
        // Expand
        val okm = ByteArray(outputLen)
        var previous = ByteArray(0)
        var generated = 0
        var counter = 1.toByte()
        val mac2 = Mac.getInstance("HmacSHA256")
        mac2.init(SecretKeySpec(prk, "HmacSHA256"))
        val infoBytes = info ?: ByteArray(0)
        while (generated < outputLen) {
            mac2.reset()
            mac2.update(previous)
            mac2.update(infoBytes)
            mac2.update(counter)
            val block = mac2.doFinal()
            val toCopy = minOf(block.size, outputLen - generated)
            System.arraycopy(block, 0, okm, generated, toCopy)
            generated += toCopy
            previous = block
            counter = (counter + 1).toByte()
        }
        return okm
    }
}
