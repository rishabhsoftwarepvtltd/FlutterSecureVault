package com.rishabhsoft.rspl_secure_vault

import io.flutter.embedding.engine.plugins.FlutterPlugin
import com.rishabhsoft.rspl_secure_vault.RsplSecureVaultApi

/** RsplSecureVaultPlugin */
class RsplSecureVaultPlugin :
    FlutterPlugin {
   

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        val api = RsplSecureVaultApiImpl(flutterPluginBinding.applicationContext, flutterPluginBinding.applicationContext.packageName)
        RsplSecureVaultApi.setUp(flutterPluginBinding.binaryMessenger, api)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        RsplSecureVaultApi.setUp(binding.binaryMessenger, null)
    }
}
