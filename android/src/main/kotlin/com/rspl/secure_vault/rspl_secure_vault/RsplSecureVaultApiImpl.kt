package com.rspl.secure_vault.rspl_secure_vault

import com.rspl.secure_vault.rspl_secure_vault.RsplSecureVaultApi
import com.rspl.secure_vault.rspl_secure_vault.InitRequest
import com.rspl.secure_vault.rspl_secure_vault.EncryptRequest
import com.rspl.secure_vault.rspl_secure_vault.DecryptRequest
import com.rspl.secure_vault.rspl_secure_vault.EncryptResponse
import com.rspl.secure_vault.rspl_secure_vault.DecryptResponse
import com.rspl.secure_vault.rspl_secure_vault.RsplSecureVaultAndroidError
import android.content.Context

class RsplSecureVaultApiImpl 
(private val context: Context, private var bundleId: String) : RsplSecureVaultApi {


  override fun initialize(request: InitRequest) {
    bundleId = request.bundleId ?: "";
  }

  override fun encrypt(request: EncryptRequest): EncryptResponse {
    val envelopeCrypto = EnvelopeCrypto(context = context, keyAlias = bundleId)
    val encryptedData = envelopeCrypto.getEncryptedString(request.plainText ?: "")
    return EncryptResponse(cipherText = encryptedData)
  }

  override fun decrypt(request: DecryptRequest): DecryptResponse {
    val envelopeCrypto = EnvelopeCrypto(context = context, keyAlias = bundleId)
    val decryptedData = envelopeCrypto.getDecryptedString(request.cipherText ?: "")
    return DecryptResponse(plainText = decryptedData)
  }
}