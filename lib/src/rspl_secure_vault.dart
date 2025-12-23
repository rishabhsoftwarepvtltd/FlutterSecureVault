import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:rspl_secure_vault/src/common_platform/rspl_secure_vault_api.dart';

/// A secure-by-default vault for storing sensitive data in Flutter apps.
///
/// This class provides a simple, high-level API for securely storing and
/// retrieving sensitive data. All data is automatically encrypted using
/// envelope encryption with hardware-backed key storage before being
/// persisted to secure storage.
///
/// ## Features
///
/// - **Automatic Encryption**: All data is encrypted before storage
/// - **Hardware-Backed Security**: Uses iOS Secure Enclave and Android Keystore
/// - **Simple API**: Just `store`, `retrieve`, `remove`, and `clear`
/// - **Secure by Default**: No configuration needed, encryption is always on
///
/// ## Usage
///
/// ```dart
/// // Create and initialize the vault
/// final vault = RsplSecureVault();
/// await vault.initialize(bundleId: 'com.example.myapp');
///
/// // Store sensitive data
/// await vault.store('api_token', 'secret-token-value');
///
/// // Retrieve data
/// final token = await vault.retrieve('api_token');
///
/// // Remove specific data
/// await vault.remove('api_token');
///
/// // Clear all stored data
/// await vault.clear();
/// ```
///
/// ## Security
///
/// - Uses AES-256-GCM for data encryption
/// - ECDH (P-256) for key agreement
/// - HKDF-SHA256 for key derivation
/// - Hardware-backed key storage when available
class RsplSecureVault {
  RsplSecureVault._();

  static RsplSecureVault? _instance;

  /// Returns the singleton instance of [RsplSecureVault].
  ///
  /// This ensures only one vault instance exists throughout the app lifecycle.
  factory RsplSecureVault() {
    _instance ??= RsplSecureVault._();
    return _instance!;
  }

  final _api = RsplSecureVaultApi();

  late final FlutterSecureStorage _storage;

  bool _isInitialized = false;
  bool _isInitializing = false;
  Completer<void>? _initCompleter;

  /// Whether the vault has been initialized.
  ///
  /// Returns `true` if [initialize] has been called successfully.
  bool get isInitialized => _isInitialized;

  /// Resets the singleton instance for testing purposes only.
  ///
  /// This method should ONLY be used in tests to reset state between test cases.
  /// Using this in production code will cause undefined behavior.
  @visibleForTesting
  static void resetForTesting() {
    _instance?._isInitialized = false;
    _instance?._isInitializing = false;
    _instance?._initCompleter = null;
    _instance = null;
  }

  // Internal key used to verify encryption keys are valid (not orphaned from backup/restore)
  static const String _keyValidationCanary = '_rspl_vault_key_check';
  static const String _canaryValue = 'vault_keys_valid';

  /// Initializes the secure vault.
  ///
  /// This must be called before any other vault operations.
  /// The [bundleId] is used to namespace encryption keys in the platform's
  /// secure storage (Keychain on iOS, Keystore on Android).
  ///
  /// ## Backup/Restore Handling
  ///
  /// When [clearOnKeyMismatch] is `true` (default), the vault automatically
  /// detects and clears orphaned data from cloud backup/restore or device
  /// migration scenarios where:
  /// - Encrypted data was restored from a backup
  /// - But encryption keys were NOT restored (keys are device-bound)
  ///
  /// This prevents users from being stuck with unreadable data.
  ///
  /// ## What happens with clearOnKeyMismatch: false
  ///
  /// - Old data remains in storage but is **unreadable** (encrypted with old keys)
  /// - New data uses current keys (works normally)
  /// - Calling [retrieve] on old data will throw [PlatformException]
  /// - You MUST handle decryption failures in your app logic
  ///
  /// Only set to `false` if you:
  /// 1. Have a server backup of sensitive data, OR
  /// 2. Can gracefully handle partial data loss, OR
  /// 3. Want to implement custom migration logic
  ///
  /// Throws [PlatformException] if initialization fails.
  ///
  /// Example:
  /// ```dart
  /// final vault = RsplSecureVault();
  /// await vault.initialize(bundleId: 'com.example.myapp');
  /// ```
  Future<void> initialize({
    required String bundleId,
    bool clearOnKeyMismatch = true,
  }) async {
    // Already initialized - return immediately
    if (_isInitialized) return;

    // Currently initializing - wait for completion (prevents race condition)
    if (_isInitializing) {
      await _initCompleter?.future;
      return;
    }

    // Start initialization
    _isInitializing = true;
    _initCompleter = Completer<void>();

    try {
      await _api.initialize(InitRequest(bundleId: bundleId));

      _storage = FlutterSecureStorage(
        aOptions: const AndroidOptions(
          encryptedSharedPreferences: true,
        ),
        iOptions: IOSOptions(
          accountName: bundleId,
          accessibility: KeychainAccessibility.first_unlock_this_device,
        ),
      );

      // Validate that encryption keys are accessible (detect backup/restore orphaned data)
      if (clearOnKeyMismatch) {
        await _validateOrClearOrphanedData();
      }

      _isInitialized = true;
      _initCompleter!.complete();
      // coverage:ignore-start
      // Platform initialization failures are tested via integration tests on real devices.
      // Unit tests cannot reliably simulate native Keystore/Keychain failures.
    } catch (e) {
      _initCompleter!.completeError(e);
      rethrow;
      // coverage:ignore-end
    } finally {
      _isInitializing = false;
    }
  }

  /// Validates that stored data can be decrypted with current keys.
  ///
  /// If validation fails (keys changed due to backup/restore), clears all
  /// orphaned data that can no longer be decrypted.
  Future<void> _validateOrClearOrphanedData() async {
    try {
      // Check if canary exists
      final encryptedCanary = await _storage.read(key: _keyValidationCanary);

      if (encryptedCanary == null) {
        // Fresh install or data was cleared - store new canary
        await _storeCanaryWithRecovery();
        return;
      }

      // Try to decrypt the canary to verify keys work
      try {
        final decryptResponse = await _api.decrypt(
          DecryptRequest(cipherText: encryptedCanary),
        );

        if (decryptResponse.plainText == _canaryValue) {
          // Keys are valid, data is accessible
          return;
        }

        // Canary decrypted but value doesn't match - suspicious (corruption or tampering)
        if (kDebugMode) {
          debugPrint(
            '⚠️ [RsplSecureVault] Canary mismatch: expected "$_canaryValue", '
            'got "${decryptResponse.plainText}" - clearing data',
          );
        }
      } on PlatformException catch (e) {
        // Expected: keys don't match (backup/restore scenario)
        if (kDebugMode) {
          debugPrint(
            '🔄 [RsplSecureVault] Clearing orphaned data (keys mismatch): ${e.code}',
          );
        }
      }

      // Keys mismatch detected - clear all orphaned data
      await _storage.deleteAll();

      // Store new canary with current keys
      await _storeCanaryWithRecovery();
      // coverage:ignore-start
      // Storage system errors (e.g., Keychain/Keystore corruption) cannot be
      // simulated in unit tests. Covered by integration tests on real devices.
    } on PlatformException catch (e) {
      // Storage system error - log but don't crash initialization
      if (kDebugMode) {
        debugPrint(
          '⚠️ [RsplSecureVault] Canary validation error: ${e.code} - ${e.message}',
        );
      }
      // Attempt recovery
      await _storeCanaryWithRecovery();
      // coverage:ignore-end
    }
  }

  /// Stores the validation canary with error recovery.
  Future<void> _storeCanaryWithRecovery() async {
    try {
      await _storeCanary();
      // coverage:ignore-start
      // Canary encryption failures after successful init are rare edge cases
      // that require specific hardware/platform states. Covered by integration tests.
    } catch (e) {
      // Log the error but don't fail initialization
      // User can still use the vault, just won't detect future key mismatches
      if (kDebugMode) {
        debugPrint('⚠️ [RsplSecureVault] Failed to store validation canary: $e');
      }
      // Note: Initialization proceeds without canary
      // Next launch will think it's a fresh install and store a new canary
      // coverage:ignore-end
    }
  }

  /// Stores the validation canary with current encryption keys.
  Future<void> _storeCanary() async {
    final encryptResponse = await _api.encrypt(
      EncryptRequest(plainText: _canaryValue),
    );

    final encryptedCanary = encryptResponse.cipherText;
    if (encryptedCanary != null && encryptedCanary.isNotEmpty) {
      await _storage.write(key: _keyValidationCanary, value: encryptedCanary);
    }
  }

  void _ensureInitialized() {
    if (!_isInitialized) {
      throw PlatformException(
        code: 'UNINITIALIZED',
        message: 'RsplSecureVault has not been initialized. '
            'Call initialize() before using other methods.',
      );
    }
  }

  /// Stores a value securely with the given key.
  ///
  /// The [value] is automatically encrypted using envelope encryption
  /// with hardware-backed keys before being stored in secure storage.
  ///
  /// If a value already exists for the given [key], it will be overwritten.
  ///
  /// Throws [PlatformException] if:
  /// - The vault is not initialized
  /// - Encryption fails
  /// - Storage operation fails
  ///
  /// Example:
  /// ```dart
  /// await vault.store('user_token', 'abc123xyz');
  /// await vault.store('refresh_token', 'refresh456');
  /// ```
  Future<void> store(String key, String value) async {
    _ensureInitialized();

    if (key.isEmpty) {
      throw PlatformException(
        code: 'INVALID_KEY',
        message: 'Key cannot be empty.',
      );
    }

    if (value.isEmpty) {
      throw PlatformException(
        code: 'INVALID_VALUE',
        message: 'Value cannot be empty.',
      );
    }

    // Encrypt the value
    final encryptResponse = await _api.encrypt(
      EncryptRequest(plainText: value),
    );

    final encryptedValue = encryptResponse.cipherText;
    if (encryptedValue == null || encryptedValue.isEmpty) {
      throw PlatformException(
        code: 'ENCRYPTION_FAILED',
        message: 'Failed to encrypt the value.',
      );
    }

    // Store encrypted value
    await _storage.write(key: key, value: encryptedValue);
  }

  /// Retrieves and decrypts a value for the given key.
  ///
  /// Returns the decrypted value if found, or `null` if no value exists
  /// for the given [key].
  ///
  /// Throws [PlatformException] if:
  /// - The vault is not initialized
  /// - Decryption fails (e.g., data corruption or tampering detected)
  ///
  /// Example:
  /// ```dart
  /// final token = await vault.retrieve('user_token');
  /// if (token != null) {
  ///   print('Token found: $token');
  /// } else {
  ///   print('No token stored');
  /// }
  /// ```
  Future<String?> retrieve(String key) async {
    _ensureInitialized();

    if (key.isEmpty) {
      throw PlatformException(
        code: 'INVALID_KEY',
        message: 'Key cannot be empty.',
      );
    }

    // Read encrypted value from storage
    final encryptedValue = await _storage.read(key: key);

    if (encryptedValue == null || encryptedValue.isEmpty) {
      return null;
    }

    // Decrypt the value
    final decryptResponse = await _api.decrypt(
      DecryptRequest(cipherText: encryptedValue),
    );

    return decryptResponse.plainText;
  }

  /// Removes the value associated with the given key.
  ///
  /// Does nothing if no value exists for the given [key].
  ///
  /// Throws [PlatformException] if:
  /// - The vault is not initialized
  /// - Storage deletion fails
  ///
  /// Example:
  /// ```dart
  /// await vault.remove('user_token');
  /// ```
  Future<void> remove(String key) async {
    _ensureInitialized();

    if (key.isEmpty) {
      throw PlatformException(
        code: 'INVALID_KEY',
        message: 'Key cannot be empty.',
      );
    }

    await _storage.delete(key: key);
  }

  /// Clears all stored values from the vault.
  ///
  /// This removes all key-value pairs stored through this vault.
  ///
  /// Throws [PlatformException] if:
  /// - The vault is not initialized
  /// - Storage clearing fails
  ///
  /// Example:
  /// ```dart
  /// await vault.clear();
  /// ```
  Future<void> clear() async {
    _ensureInitialized();

    await _storage.deleteAll();
  }

  /// Checks if a value exists for the given key.
  ///
  /// Returns `true` if a value exists, `false` otherwise.
  ///
  /// Throws [PlatformException] if:
  /// - The vault is not initialized
  ///
  /// Example:
  /// ```dart
  /// if (await vault.containsKey('user_token')) {
  ///   print('Token exists');
  /// }
  /// ```
  Future<bool> containsKey(String key) async {
    _ensureInitialized();

    if (key.isEmpty) {
      throw PlatformException(
        code: 'INVALID_KEY',
        message: 'Key cannot be empty.',
      );
    }

    return await _storage.containsKey(key: key);
  }
}

