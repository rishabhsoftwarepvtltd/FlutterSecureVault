import 'package:pigeon/pigeon.dart';

class InitRequest {
  String? bundleId;
}

class EncryptRequest {
  String? plainText;
}

class DecryptRequest {
  String? cipherText;
}

class EncryptResponse {
  String? cipherText;
}

class DecryptResponse {
  String? plainText;
}

@ConfigurePigeon(
  PigeonOptions(
    kotlinOut:
        'android/src/main/kotlin/com/rishabhsoft/rspl_secure_vault/RsplSecureVaultApi.kt',
    swiftOut: 'ios/Classes/RsplSecureVaultApi.swift',
    dartOut: 'lib/src/common_platform/rspl_secure_vault_api.dart',
    kotlinOptions: KotlinOptions(
      errorClassName: 'RsplSecureVaultAndroidError',
      package: 'com.rishabhsoft.rspl_secure_vault',
      includeErrorClass: true,
    ),
    swiftOptions: SwiftOptions(errorClassName: 'RsplSecureVaultIOSError'),
    dartPackageName: 'rspl_secure_vault',
  ),
)
@HostApi()
abstract class RsplSecureVaultApi {
  void initialize(InitRequest request);
  EncryptResponse encrypt(EncryptRequest request);
  DecryptResponse decrypt(DecryptRequest request);
}
