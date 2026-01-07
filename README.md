# Secure Vault

[![pub package](https://img.shields.io/pub/v/rspl_secure_vault.svg)](https://pub.dev/packages/rspl_secure_vault) [![License: Rishabh Software](https://img.shields.io/badge/License-Rishabh%20Software-blue.svg)](LICENSE) [![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/rishabhsoftwarepvtltd/FlutterSecureVault) [![Flutter](https://img.shields.io/badge/Flutter-3.3.0%2B-02569B.svg?logo=flutter&logoColor=white)](https://flutter.dev) [![Dart](https://img.shields.io/badge/Dart-3.0.0%2B-0175C2.svg?logo=dart&logoColor=white)](https://dart.dev) [![Platform](https://img.shields.io/badge/platform-android%20|%20ios-blue.svg)](https://github.com/rishabhsoftwarepvtltd/FlutterSecureVault) [![Security Audit](https://img.shields.io/badge/Security%20Audit-Passed-brightgreen.svg)](SECURITY_AUDIT.md)

This is a **secure-by-default** Flutter plugin for storing sensitive data. It provides automatic encryption using envelope encryption with platform-specific hardware-backed key management (iOS Secure Enclave/Keychain and Android Keystore).

> **⚠️ Security Notice**: While this package implements industry-standard encryption (AES-256-GCM), always conduct independent security audits for production applications handling sensitive data. See [Important Notes for Production Use](#important-notes-for-production-use) for details.

---

## Quick Start

```dart
import 'package:rspl_secure_vault/rspl_secure_vault.dart';

final vault = RsplSecureVault();
await vault.initialize(bundleId: 'com.example.app');

// Store and retrieve - that's it!
await vault.store('token', 'secret-value');
final value = await vault.retrieve('token'); // Returns: 'secret-value'
```

---

## Table of Contents

- [Features](#features)
- [Platform Support](#platform-support)
- [Android API Support](#android-api-support)
- [Requirements](#requirements)
- [Permissions Required](#permissions-required)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Error Handling](#error-handling)
- [Limitations](#limitations)
- [Architecture](#architecture)
- [Security Audit](#security-audit)
- [Security Details](#security-details)
- [Design Philosophy](#design-philosophy)
- [Security Model & Limitations](#security-model--limitations)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Important Notes for Production Use](#important-notes-for-production-use)
- [Compliance & Standards](#compliance--standards)
- [FAQ](#faq)
- [Folder Structure](#folder-structure)
- [Example](#example)
- [Acknowledgments](#acknowledgments)
- [Contributing](#contributing)
- [User Privacy Notes](#user-privacy-notes)
- [Author, Maintainers & Acknowledgements](#author-maintainers--acknowledgements)
- [License](#license)

---

## Features

- 🔐 **Secure by Default**: All data is automatically encrypted before storage
- 🛡️ **Hardware-Backed Security**:
  - **iOS**: Secure Enclave + Keychain
  - **Android**: Android Keystore with StrongBox support (when available)
- 🎯 **Simple API**: Just `store`, `retrieve`, `remove`, and `clear`
- 🔒 **Envelope Encryption**: AES-256-GCM with unique keys per operation
- 🔑 **Secure Key Exchange**: ECDH (P-256/secp256r1) for key agreement
- ✅ **Tamper Detection**: GCM authentication tags prevent data modification
- 📱 **Cross-Platform**: Unified API for iOS and Android
- 🚫 **Hard to Misuse**: No configuration options that could weaken security
- 🔄 **Backup/Restore Safe**: Automatic detection and handling of orphaned data

## Platform Support

| Platform | Minimum Version | Notes |
|----------|-----------------|-------|
| **Android** | API 24 (Android 7.0+) | Full hardware-backed security |
| **iOS** | iOS 13.0+ | Secure Enclave on supported devices |

## Android API Support

| API Level | Android Version | ECDH Implementation | Notes |
|-----------|-----------------|---------------------|-------|
| **31+** | Android 12+ | Native Keystore ECDH | Best performance, direct hardware support |
| **24-30** | Android 7-11 | AES-wrapped EC key | Hybrid approach, same security level |

> **Note**: On API 24-30, the package uses an AES master key in Keystore to protect the EC key, since `PURPOSE_AGREE_KEY` was only added in API 31. Security is equivalent; only the internal implementation differs.

## Requirements

- **Dart**: >=3.0.0 <4.0.0
- **Flutter**: Flutter 3.3.0+ based on Dart 3.0.0
- **iOS**: >=13.0
- **Android**: API 24+ (Android 7.0+)

## Permissions Required

- **Android**: No explicit permissions required (Keystore access is automatic)
- **iOS**: No explicit permissions required (Keychain/Secure Enclave access is automatic)

## Getting Started

### 1) Install

Add the dependency to your `pubspec.yaml`:

```yaml
dependencies:
  rspl_secure_vault: ^0.0.2
```

Then run:

```bash
flutter pub get
```

### 2) Import

```dart
import 'package:rspl_secure_vault/rspl_secure_vault.dart';
```

### 3) Initialize (Recommended: in main())

```dart
import 'package:flutter/material.dart';
import 'package:rspl_secure_vault/rspl_secure_vault.dart';

late final RsplSecureVault vault;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  vault = RsplSecureVault();
  await vault.initialize(bundleId: 'com.example.myapp');
  
  runApp(const MyApp());
}
```

> **Best Practice**: Initialize once in `main()` before `runApp()`. This ensures the vault is ready before any widget needs it and catches initialization errors early.

### Bundle ID Clarification

**Bundle ID Usage**: Use your app's actual bundle identifier (iOS) or application ID (Android). 

```dart
// Use your actual app identifier
await vault.initialize(bundleId: 'com.yourcompany.yourapp');
```

⚠️ **Important**: 
- The same bundle ID must be used consistently across app launches
- Changing the bundle ID will make existing data **unreadable** (keys are tied to the identifier)
- Different bundle IDs create completely separate key stores (useful for multi-app scenarios)

## Usage

### Basic Usage

```dart
import 'package:rspl_secure_vault/rspl_secure_vault.dart';

// Create and initialize the vault (do this once at app startup)
final vault = RsplSecureVault();
await vault.initialize(bundleId: 'com.example.myapp');

// Store sensitive data (automatically encrypted)
await vault.store('api_token', 'secret-token-value');
await vault.store('refresh_token', 'refresh-token-value');

// Retrieve data (automatically decrypted)
final token = await vault.retrieve('api_token');
print('Token: $token');

// Check if a key exists
if (await vault.containsKey('api_token')) {
  print('Token exists!');
}

// Remove specific data
await vault.remove('api_token');

// Clear all stored data
await vault.clear();
```

### Common Use Cases

#### Storing Authentication Tokens

```dart
class AuthService {
  final _vault = RsplSecureVault();
  
  Future<void> saveTokens({
    required String accessToken,
    required String refreshToken,
  }) async {
    await _vault.store('access_token', accessToken);
    await _vault.store('refresh_token', refreshToken);
  }
  
  Future<String?> getAccessToken() => _vault.retrieve('access_token');
  Future<String?> getRefreshToken() => _vault.retrieve('refresh_token');
  
  Future<void> clearTokens() async {
    await _vault.remove('access_token');
    await _vault.remove('refresh_token');
  }
}
```

#### Storing API Keys

```dart
class ApiKeyManager {
  final _vault = RsplSecureVault();
  
  Future<void> saveApiKey(String serviceName, String apiKey) async {
    await _vault.store('api_key_$serviceName', apiKey);
  }
  
  Future<String?> getApiKey(String serviceName) async {
    return await _vault.retrieve('api_key_$serviceName');
  }
}
```

### Complete Example with Error Handling

```dart
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:rspl_secure_vault/rspl_secure_vault.dart';

class SecureStorageService {
  final _vault = RsplSecureVault();
  bool _isInitialized = false;

  Future<void> initialize() async {
    if (_isInitialized) return;
    
    try {
      await _vault.initialize(bundleId: 'com.example.myapp');
      _isInitialized = true;
    } on PlatformException catch (e) {
      debugPrint('Failed to initialize vault: ${e.message}');
      rethrow;
    }
  }

  Future<void> saveToken(String token) async {
    try {
      await _vault.store('auth_token', token);
    } on PlatformException catch (e) {
      debugPrint('Failed to save token: ${e.message}');
      rethrow;
    }
  }

  Future<String?> getToken() async {
    try {
      return await _vault.retrieve('auth_token');
    } on PlatformException catch (e) {
      debugPrint('Failed to retrieve token: ${e.message}');
      return null;
    }
  }

  Future<void> clearToken() async {
    try {
      await _vault.remove('auth_token');
    } on PlatformException catch (e) {
      debugPrint('Failed to clear token: ${e.message}');
    }
  }

  Future<void> logout() async {
    try {
      await _vault.clear();
    } on PlatformException catch (e) {
      debugPrint('Failed to clear vault: ${e.message}');
    }
  }
}
```

## API Reference

### RsplSecureVault

The main class for secure storage operations. Uses a singleton pattern.

#### Constructor

```dart
final vault = RsplSecureVault();
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `isInitialized` | `bool` | Whether the vault has been initialized |

#### Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `initialize({required String bundleId, bool clearOnKeyMismatch = true})` | `Future<void>` | Initializes the vault with the app's bundle ID |
| `store(String key, String value)` | `Future<void>` | Stores a value securely (encrypted) |
| `retrieve(String key)` | `Future<String?>` | Retrieves and decrypts a value |
| `remove(String key)` | `Future<void>` | Removes a specific key-value pair |
| `clear()` | `Future<void>` | Removes all stored values |
| `containsKey(String key)` | `Future<bool>` | Checks if a key exists |

## Error Handling

All methods throw `PlatformException` on errors:

```dart
try {
  await vault.store('key', 'value');
} on PlatformException catch (e) {
  switch (e.code) {
    case 'UNINITIALIZED':
      print('Vault not initialized. Call initialize() first.');
      break;
    case 'INVALID_KEY':
      print('Key cannot be empty.');
      break;
    case 'INVALID_VALUE':
      print('Value cannot be empty.');
      break;
    case 'ENCRYPTION_FAILED':
      print('Encryption operation failed. Check device security settings.');
      break;
    case 'DECRYPTION_FAILED':
      print('Decryption failed. Data may be corrupted or keys changed.');
      break;
    default:
      print('Operation failed: ${e.message}');
  }
}
```

### Error Codes

| Code | Description | Common Cause |
|------|-------------|--------------|
| `UNINITIALIZED` | Vault not initialized | Forgot to call `initialize()` |
| `INVALID_KEY` | Key is empty | Passed empty string as key |
| `INVALID_VALUE` | Value is empty | Passed empty string as value |
| `ENCRYPTION_FAILED` | Encryption operation failed | Device security issue or key generation failure |
| `DECRYPTION_FAILED` | Decryption operation failed | Data corruption or key mismatch (backup/restore) |
| `channel-error` | Platform channel error | Native code exception |

## Limitations

### Data Size Recommendations

| Use Case | Recommended | Notes |
|----------|-------------|-------|
| Auth tokens | ✅ Ideal | Typically < 2KB |
| API keys | ✅ Ideal | Typically < 1KB |
| Small JSON configs | ✅ Good | < 10KB |
| Large data (> 100KB) | ⚠️ Not recommended | Use file encryption instead |
| Binary data / Files | ❌ Not supported | Strings only |

### Concurrency

- **Thread-safe**: Multiple simultaneous operations are supported
- **Initialization**: Race-condition protected (concurrent `initialize()` calls are safe)
- **Atomic operations**: Each store/retrieve is atomic

### Storage Limits

- **Keys**: Any non-empty string (recommended: < 256 characters)
- **Values**: Any non-empty string (recommended: < 1MB for performance)
- **Total entries**: Limited by device storage (FlutterSecureStorage backend)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Flutter App                          │
│                         │                               │
│                  RsplSecureVault                        │
│                    (Simple API)                         │
│           store / retrieve / remove / clear             │
├─────────────────────────────────────────────────────────┤
│                Internal Implementation                  │
│  ┌─────────────────────┐  ┌─────────────────────────┐   │
│  │  Encryption Layer   │  │  FlutterSecureStorage   │   │
│  │  (Envelope Crypto)  │  │  (Persistent Storage)   │   │
│  └─────────────────────┘  └─────────────────────────┘   │
└─────────────────────────┬───────────────────────────────┘
                          │ Platform Channel
┌─────────────────────────┴───────────────────────────────┐
│              Native Implementation                      │
├──────────────────────┬──────────────────────────────────┤
│        iOS           │            Android               │
│  ┌────────────────┐  │  ┌────────────────────────────┐  │
│  │ Secure Enclave │  │  │      Android Keystore      │  │
│  │   + Keychain   │  │  │  (StrongBox if available)  │  │
│  └────────────────┘  │  └────────────────────────────┘  │
└──────────────────────┴──────────────────────────────────┘
```

### Envelope Encryption Flow

```
┌─────────────────────────────────────────────────────────┐
│                    ENCRYPTION                           │
├─────────────────────────────────────────────────────────┤
│  1. Generate random DEK (Data Encryption Key)           │
│                    ↓                                    │
│  2. Encrypt plaintext with DEK using AES-256-GCM        │
│                    ↓                                    │
│  3. Derive KEK via ECDH + HKDF                          │
│     (Ephemeral key + Device master key)                 │
│                    ↓                                    │
│  4. Wrap DEK with KEK using AES-256-GCM                 │
│                    ↓                                    │
│  5. Store envelope: {wrappedDEK, ciphertext, nonces...} │
└─────────────────────────────────────────────────────────┘
```

## Security Audit

This package has undergone an internal security code review covering:

- ✅ API design and misuse prevention
- ✅ Key lifecycle management
- ✅ Encryption implementation (AES-256-GCM)
- ✅ Nonce/IV handling
- ✅ Envelope encryption architecture
- ✅ Platform security (Secure Enclave / Android Keystore)
- ✅ Error handling and logging practices
- ✅ Backup/restore orphaned data handling

**Audit Result**: 62/62 checks passed

📄 **[View Full Security Audit Report](SECURITY_AUDIT.md)**

> ⚠️ **Note**: This is an internal code review, not a formal third-party penetration test. Users requiring certified audits should engage qualified security firms.

## Security Details

### Envelope Encryption Flow

1. **Key Generation**: Random 256-bit Data Encryption Key (DEK) generated per operation
2. **Data Encryption**: Plain text encrypted with AES-256-GCM using DEK
3. **Key Wrapping**: DEK wrapped using Key Encryption Key (KEK) derived via ECDH
4. **Secure Storage**: Encrypted data stored in FlutterSecureStorage
5. **Hardware Keys**: Master keys protected by Secure Enclave (iOS) or Keystore (Android)

### Cryptographic Parameters

| Parameter | Value | Standard |
|-----------|-------|----------|
| Data Encryption | AES-256-GCM | NIST SP 800-38D |
| Key Agreement | ECDH P-256 (secp256r1) | NIST SP 800-56A |
| Key Derivation | HKDF-SHA256 | RFC 5869 |
| GCM Nonce Size | 96 bits (12 bytes) | NIST recommended |
| GCM Tag Size | 128 bits (16 bytes) | NIST recommended |

## Design Philosophy

This package follows a **secure-by-default** approach:

1. **No Encryption Options**: Users cannot disable or configure encryption
2. **No Storage Selection**: All data goes to secure storage automatically
3. **Simple API**: Hard to misuse - just store and retrieve
4. **Automatic Key Management**: Keys are managed internally using hardware security
5. **Single Responsibility**: This package only does secure storage, nothing else

## Security Model & Limitations

### What This Package Protects Against

- ✅ **Data at rest**: All stored data is encrypted with AES-256-GCM
- ✅ **Key extraction**: Master keys are stored in hardware-backed secure storage (Secure Enclave/Keystore)
- ✅ **Data tampering**: GCM authentication tags detect any modification to encrypted data
- ✅ **Key reuse attacks**: Each encryption operation uses a fresh Data Encryption Key (DEK)

### What This Package Does NOT Protect Against

- ❌ **Rooted/Jailbroken devices**: On compromised devices, hardware security guarantees may be bypassed. This package does not detect or block usage on such devices.
- ❌ **Runtime memory attacks**: Decrypted data exists briefly in memory during retrieval. Memory-scraping malware on a compromised device could potentially access this data.
- ❌ **App-level compromise**: If your app itself is compromised (e.g., through malicious dependencies or code injection), stored secrets may be exposed.
- ❌ **Side-channel attacks**: This package does not implement countermeasures against timing attacks or other side-channel vulnerabilities.
- ❌ **iOS data persistence**: On iOS, Keychain data persists after app uninstall. If your threat model requires data deletion on uninstall, implement additional cleanup logic.

### Recommendations

1. **Server-side validation**: Never rely solely on local secure storage for critical security decisions. Always validate important data server-side.
2. **Sensitive data minimization**: Store only what's necessary. Consider token expiration and rotation strategies.
3. **Defense in depth**: Use this package as one layer of your security strategy, not the only layer.
4. **User authentication**: Consider requiring user authentication (biometrics/PIN) for accessing highly sensitive data.

## Best Practices

1. **Initialize Once**: Call `initialize()` once in `main()` before `runApp()`
2. **Use Unique Bundle IDs**: Use your actual app identifier consistently
3. **Handle Errors**: Always wrap API calls in try-catch blocks
4. **Check Initialization**: Use `isInitialized` property if needed
5. **Don't Store Large Data**: This is designed for secrets, not bulk storage
6. **Regular Updates**: Keep the package and dependencies updated for security patches
7. **Data Minimization**: Only store data that you actually need
8. **Access Control**: Implement proper access controls in your application layer
9. **Security Testing**: Test your app's behavior in various security scenarios
10. **Graceful Degradation**: Design your app to handle storage failures gracefully

## Troubleshooting

### iOS Simulator
- Secure Enclave is not available on simulators
- The plugin falls back to standard Keychain storage

### Android Emulator
- StrongBox is not available on emulators
- The plugin uses software-backed Android Keystore

### Data Persistence After App Uninstall

| Platform | Behavior | Reason |
|----------|----------|--------|
| **Android** | Data **deleted** on uninstall | Keystore keys tied to app; removed with app |
| **iOS** | Data **persists** after uninstall | Keychain is system-level storage |

**Android**: When you uninstall and reinstall, all stored data becomes unreadable because the encryption keys are deleted with the app.

**iOS**: Keychain items persist across app uninstalls by default. Your encrypted data remains accessible after reinstall.

**Recommendations**:
- Design your app to handle missing data gracefully on both platforms
- For iOS, if you need a "fresh start" on reinstall, consider clearing vault data on first launch
- Don't rely on uninstall to clear sensitive data on iOS

### Backup/Restore & Device Migration

When users restore from cloud backup (Google Backup, iCloud) or migrate to a new device:

| What Transfers | What Does NOT Transfer |
|----------------|------------------------|
| Encrypted data (stored in secure storage) | Encryption keys (device-bound in Keystore/Keychain) |

**Result**: Restored data exists but cannot be decrypted → "orphaned data"

**Built-in Solution**: The vault automatically detects and handles this:

```dart
// Default behavior: automatically clear orphaned data
await vault.initialize(bundleId: 'com.example.app');

// Optional: disable auto-clear if you have custom recovery logic
await vault.initialize(
  bundleId: 'com.example.app',
  clearOnKeyMismatch: false,  // NOT recommended unless you handle it yourself
);

// Safe to call concurrently - only one initialization will run
await Future.wait([
  vault.initialize(bundleId: 'com.example.app'),
  vault.initialize(bundleId: 'com.example.app'),
]); // ✅ No race condition
```

**How it works**:
1. On first `initialize()`, the vault stores a validation "canary" value
2. On subsequent launches, it tries to decrypt the canary
3. If decryption fails (keys changed), it clears ALL orphaned data
4. Fresh data can then be stored with the new device's keys

**Important**: Data stored before backup/restore will be lost. This is by design - the keys are device-bound for security. Plan your app's data strategy accordingly (e.g., re-fetch tokens from server after restore).

---

## Important Notes for Production Use

### Security Disclaimer

> ⚠️ **Important**: While RSPL Secure Vault implements industry-standard encryption (AES-256-GCM) and follows security best practices, **no software can guarantee 100% security**. Always conduct your own security audits and compliance reviews before using in production applications, especially those handling sensitive data.

### Security Considerations

| Consideration | Description |
|---------------|-------------|
| **Audit Required** | Perform independent security audits for applications handling sensitive data |
| **Compliance** | Verify that your implementation meets your specific regulatory requirements |
| **Key Management** | The security of your data depends on the platform's secure storage implementation |
| **Testing** | Thoroughly test encryption/decryption flows in your specific use case |
| **Root/Jailbreak** | This package does not include root/jailbreak detection - consider adding RASP tools if needed |

### Legal & Compliance

| Area | Your Responsibility |
|------|---------------------|
| **Compliance** | You are responsible for ensuring compliance with applicable laws and regulations |
| **Data Protection** | Review data protection requirements for your jurisdiction and industry |
| **User Consent** | Ensure proper user consent for data collection and storage |
| **Backup Strategy** | Implement appropriate backup and recovery procedures for your use case |
| **Data Retention** | Define and enforce data retention policies |

### Recommendation for Mission-Critical Applications

For mission-critical applications handling highly sensitive data (financial, healthcare, etc.), consider additional security measures:

- **Certificate Pinning**: Protect API communications
- **Runtime Application Self-Protection (RASP)**: Detect and respond to runtime threats
- **Regular Penetration Testing**: Engage third-party security firms
- **Biometric Authentication**: Add extra layer for sensitive operations
- **Obfuscation**: Protect your app code from reverse engineering

---

## Compliance & Standards

RSPL Secure Vault is designed to help meet common regulatory requirements by providing a secure foundation:

### Healthcare (HIPAA)

| Requirement | How This Package Helps |
|-------------|------------------------|
| Encryption of PHI at rest | ✅ AES-256-GCM encryption for all sensitive data |
| Key management | ✅ Platform keychain/keystore for encryption keys |
| Access controls | 🔸 Implement app-level controls |
| Audit trails | 🔸 Implement app-level logging |

### Financial (PCI DSS)

| Requirement | How This Package Helps |
|-------------|------------------------|
| Strong cryptography | ✅ AES-256-GCM encryption |
| Key management | ✅ Platform secure storage |
| Data protection | ✅ Envelope encryption for payment data |
| Tamper detection | ✅ GCM authentication tags |

### Enterprise (SOC 2)

| Requirement | How This Package Helps |
|-------------|------------------------|
| Data encryption at rest | ✅ All data encrypted before storage |
| Access controls | 🔸 Implement app-level controls |
| Security monitoring | 🔸 Implement app-level monitoring |

### GDPR

| Requirement | How This Package Helps |
|-------------|------------------------|
| Data protection | ✅ Encryption protects personal information |
| Right to deletion | ✅ `clear()` and `remove()` methods |
| Data minimization | 🔸 Only store what you need |
| No telemetry | ✅ This package collects no analytics or telemetry |

> **Legend**: ✅ = Provided by this package | 🔸 = Implement in your application

> ⚠️ **Important**: While RSPL Secure Vault provides security foundations, **you are responsible** for ensuring your complete application meets regulatory requirements. Conduct security audits and compliance reviews before production deployment.

---

## FAQ

### General Questions

**Q: Is this package production-ready?**

A: Yes, but always conduct your own security review for sensitive applications. See our [Security Audit](SECURITY_AUDIT.md) for details.

**Q: Does this work on web/desktop?**

A: No, this package is designed specifically for mobile platforms (iOS/Android) where hardware-backed security is available.

### Security Questions

**Q: Can I disable encryption for better performance?**

A: No, and this is intentional. The package is designed to be secure by default with no way to accidentally store unencrypted data.

**Q: What happens if the device is rooted/jailbroken?**

A: Hardware security guarantees may be bypassed on compromised devices. Consider adding RASP (Runtime Application Self-Protection) tools for additional protection.

**Q: Are my keys backed up to the cloud?**

A: No, encryption keys are stored in the device's Secure Enclave (iOS) or Keystore (Android) and are not included in cloud backups by design.

### Technical Questions

**Q: Why does `retrieve()` return `null` instead of throwing?**

A: `null` indicates the key doesn't exist, which is a normal condition. Exceptions are reserved for actual errors (initialization failure, decryption failure, etc.).

**Q: Can I store binary data?**

A: The API accepts strings only. For binary data, encode as Base64 first:

```dart
import 'dart:convert';
final bytes = Uint8List.fromList([1, 2, 3]);
await vault.store('binary_data', base64Encode(bytes));
final retrieved = base64Decode(await vault.retrieve('binary_data')!);
```

**Q: Is the initialization thread-safe?**

A: Yes, concurrent calls to `initialize()` are handled safely - only one initialization runs, others wait for it to complete.

---

## Folder Structure

```
rspl_secure_vault/
├─ lib/
│  ├─ rspl_secure_vault.dart              # Main package export
│  └─ src/
│     ├─ rspl_secure_vault.dart           # Main vault implementation
│     └─ common_platform/
│        └─ rspl_secure_vault_api.dart    # Internal platform API
├─ android/                               # Android native implementation
├─ ios/                                   # iOS native implementation
├─ example/                               # Example app
└─ test/                                  # Unit tests
```

## Example

For a complete working example, see the [example app on GitHub](https://github.com/rishabhsoftwarepvtltd/FlutterSecureVault/tree/main/example).

## Acknowledgments

- Built with [Pigeon](https://pub.dev/packages/pigeon) for type-safe platform channel communication
- Uses [flutter_secure_storage](https://pub.dev/packages/flutter_secure_storage) for secure persistence
- Uses [CryptoKit](https://developer.apple.com/documentation/cryptokit) on iOS
- Uses [Android Keystore](https://developer.android.com/training/articles/keystore) on Android

## Contributing

Contributions welcome! Please read:

- [CONTRIBUTING.md](CONTRIBUTING.md) – setup, branch strategy, commit convention
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

Run checks before push:
- `dart format .`
- `flutter analyze`
- `flutter test`

## User Privacy Notes

- This package does not collect any user information or share data with third-party services.

## Author, Maintainers & Acknowledgements

- Developed by **[Rishabh Software](https://www.rishabhsoft.com/)**.
- Thanks to the Flutter community for the amazing packages used in this project.

## License

This package is licensed under the **Rishabh Software Source Available License (Non-Commercial) V.1**.

- ✅ Free for personal projects, learning, academic purposes, and evaluation
- ✅ You may modify and fork for non-commercial use
- ❌ Commercial use requires a separate license

For licensing inquiries, refer to [LICENSE](LICENSE) for contact details.

## Made by Rishabh Software Team

[Github](https://github.com/rishabhsoftwarepvtltd) • [Website](https://www.rishabhsoft.com/services/mobile-app-development)

## Contact

Have questions, suggestions, or feedback? We'd love to hear from you!

📧 **Email**: [opensource@rishabhsoft.com](mailto:opensource@rishabhsoft.com)

🌐 **Contact Us**: https://www.rishabhsoft.com/contact-us