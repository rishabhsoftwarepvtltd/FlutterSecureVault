import Flutter
import UIKit

public class RsplSecureVaultPlugin: NSObject, FlutterPlugin, RsplSecureVaultApi {

  private var bundleId: String?

  public static func register(with registrar: FlutterPluginRegistrar) {
    let instance = RsplSecureVaultPlugin()
    RsplSecureVaultApiSetup.setUp(binaryMessenger: registrar.messenger(), api: instance)
  }

  func initialize(request: InitRequest) throws {
    self.bundleId = request.bundleId
  }

  func encrypt(request: EncryptRequest) throws -> EncryptResponse {
    guard let bundleId = self.bundleId else {
      throw RsplSecureVaultIOSError(code: "UNINITIALIZED", message: "Plugin not initialized. Call initialize() first.", details: nil)
    }
    guard let plainText = request.plainText else {
      throw RsplSecureVaultIOSError(code: "INVALID_ARGUMENT", message: "plainText is nil", details: nil)
    }
    let crypto = EnvelopeCrypto(keyTag: bundleId)
    let cipherText = try crypto.getEncryptedString(plain: plainText)
    return EncryptResponse(cipherText: cipherText)
  }

  func decrypt(request: DecryptRequest) throws -> DecryptResponse {
    guard let bundleId = self.bundleId else {
      throw RsplSecureVaultIOSError(code: "UNINITIALIZED", message: "Plugin not initialized. Call initialize() first.", details: nil)
    }
    guard let cipherText = request.cipherText else {
      throw RsplSecureVaultIOSError(code: "INVALID_ARGUMENT", message: "cipherText is nil", details: nil)
    }
    let crypto = EnvelopeCrypto(keyTag: bundleId)
    let plainText = try crypto.getDecryptedString(envelopeBase64: cipherText)
    return DecryptResponse(plainText: plainText)
  }
}
