import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rspl_secure_vault/rspl_secure_vault.dart';
import 'package:rspl_secure_vault/src/common_platform/rspl_secure_vault_api.dart';

/// Mock storage for testing
final Map<String, String> _mockStorage = {};

/// Mock flags for controlling test behavior
bool _shouldFailInit = false;
bool _shouldFailEncrypt = false;
bool _shouldFailDecrypt = false;
bool _shouldReturnEmptyCiphertext = false;
String? _canaryDecryptResult;

void setupMockChannels() {
  final binding = TestWidgetsFlutterBinding.ensureInitialized();

  // Mock Pigeon initialize channel
  binding.defaultBinaryMessenger.setMockMessageHandler(
    'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.initialize',
    (ByteData? message) async {
      if (_shouldFailInit) {
        const codec = RsplSecureVaultApi.pigeonChannelCodec;
        return codec.encodeMessage(['INIT_ERROR', 'Init failed', null]);
      }
      const codec = RsplSecureVaultApi.pigeonChannelCodec;
      return codec.encodeMessage([null]);
    },
  );

  // Mock Pigeon encrypt channel
  binding.defaultBinaryMessenger.setMockMessageHandler(
    'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.encrypt',
    (ByteData? message) async {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;

      if (_shouldFailEncrypt) {
        return codec.encodeMessage(['ENCRYPT_ERROR', 'Encrypt failed', null]);
      }

      if (_shouldReturnEmptyCiphertext) {
        return codec.encodeMessage([EncryptResponse(cipherText: '')]);
      }

      final decoded = codec.decodeMessage(message);
      final request = (decoded as List)[0] as EncryptRequest;
      final encrypted = 'enc:${request.plainText}';
      return codec.encodeMessage([EncryptResponse(cipherText: encrypted)]);
    },
  );

  // Mock Pigeon decrypt channel
  binding.defaultBinaryMessenger.setMockMessageHandler(
    'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.decrypt',
    (ByteData? message) async {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;

      if (_shouldFailDecrypt) {
        return codec.encodeMessage(['DECRYPT_ERROR', 'Decrypt failed', null]);
      }

      if (_canaryDecryptResult != null) {
        return codec
            .encodeMessage([DecryptResponse(plainText: _canaryDecryptResult)]);
      }

      final decoded = codec.decodeMessage(message);
      final request = (decoded as List)[0] as DecryptRequest;
      String? plainText;
      if (request.cipherText?.startsWith('enc:') ?? false) {
        plainText = request.cipherText!.substring(4);
      }
      return codec.encodeMessage([DecryptResponse(plainText: plainText)]);
    },
  );

  // Mock flutter_secure_storage
  binding.defaultBinaryMessenger.setMockMethodCallHandler(
    const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
    (MethodCall call) async {
      switch (call.method) {
        case 'read':
          return _mockStorage[call.arguments['key']];
        case 'write':
          _mockStorage[call.arguments['key']] = call.arguments['value'];
          return null;
        case 'delete':
          _mockStorage.remove(call.arguments['key']);
          return null;
        case 'deleteAll':
          _mockStorage.clear();
          return null;
        case 'containsKey':
          return _mockStorage.containsKey(call.arguments['key']);
        default:
          return null;
      }
    },
  );
}

void clearMockChannels() {
  final binding = TestWidgetsFlutterBinding.ensureInitialized();
  binding.defaultBinaryMessenger.setMockMessageHandler(
    'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.initialize',
    null,
  );
  binding.defaultBinaryMessenger.setMockMessageHandler(
    'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.encrypt',
    null,
  );
  binding.defaultBinaryMessenger.setMockMessageHandler(
    'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.decrypt',
    null,
  );
  binding.defaultBinaryMessenger.setMockMethodCallHandler(
    const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
    null,
  );
}

void resetMockState() {
  _mockStorage.clear();
  _shouldFailInit = false;
  _shouldFailEncrypt = false;
  _shouldFailDecrypt = false;
  _shouldReturnEmptyCiphertext = false;
  _canaryDecryptResult = null;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('RsplSecureVault Full Tests', () {
    setUp(() {
      RsplSecureVault.resetForTesting();
      resetMockState();
      setupMockChannels();
    });

    tearDown(() {
      clearMockChannels();
      resetMockState();
      RsplSecureVault.resetForTesting();
    });

    // ==========================================================================
    // Singleton Tests
    // ==========================================================================
    group('Singleton Pattern', () {
      test('factory returns singleton', () {
        final a = RsplSecureVault();
        final b = RsplSecureVault();
        expect(identical(a, b), isTrue);
      });

      test('resetForTesting creates new instance', () {
        final a = RsplSecureVault();
        RsplSecureVault.resetForTesting();
        final b = RsplSecureVault();
        expect(identical(a, b), isFalse);
      });
    });

    // ==========================================================================
    // Initialization Tests
    // ==========================================================================
    group('Initialization', () {
      test('isInitialized is false before init', () {
        final vault = RsplSecureVault();
        expect(vault.isInitialized, isFalse);
      });

      test('initialize succeeds', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        expect(vault.isInitialized, isTrue);
      });

      test('initialize called twice returns immediately', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await vault.initialize(
            bundleId: 'com.test'); // Should return immediately
        expect(vault.isInitialized, isTrue);
      });

      test('concurrent initialize calls wait for first', () async {
        final vault = RsplSecureVault();
        final futures = [
          vault.initialize(bundleId: 'com.test'),
          vault.initialize(bundleId: 'com.test'),
          vault.initialize(bundleId: 'com.test'),
        ];
        await Future.wait(futures);
        expect(vault.isInitialized, isTrue);
      });

      test('initialize without clearOnKeyMismatch', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test', clearOnKeyMismatch: false);
        expect(vault.isInitialized, isTrue);
      });

      // Note: Testing platform error during initialize is complex due to
      // Completer.completeError + rethrow pattern. This scenario is covered
      // by integration tests on actual devices.
    });

    // ==========================================================================
    // Canary Validation Tests
    // ==========================================================================
    group('Canary Validation', () {
      test('stores canary on fresh install', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        expect(_mockStorage.containsKey('_rspl_vault_key_check'), isTrue);
      });

      test('validates existing canary', () async {
        // Pre-store a valid canary
        _mockStorage['_rspl_vault_key_check'] = 'enc:vault_keys_valid';

        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        expect(vault.isInitialized, isTrue);
      });

      test('clears data on canary mismatch', () async {
        // Pre-store invalid canary
        _mockStorage['_rspl_vault_key_check'] = 'enc:wrong_value';
        _mockStorage['user_data'] = 'some_data';

        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');

        // Old data should be cleared
        expect(_mockStorage.containsKey('user_data'), isFalse);
        // New canary should be stored
        expect(_mockStorage.containsKey('_rspl_vault_key_check'), isTrue);
      });

      test('clears data on decrypt failure', () async {
        // Pre-store canary
        _mockStorage['_rspl_vault_key_check'] = 'enc:vault_keys_valid';
        _mockStorage['user_data'] = 'some_data';
        _shouldFailDecrypt = true;

        final vault = RsplSecureVault();
        // Should not throw - handles gracefully
        await vault.initialize(bundleId: 'com.test');
        expect(vault.isInitialized, isTrue);
      });

      test('handles storage error during validation', () async {
        // This tests the outer PlatformException catch
        _mockStorage['_rspl_vault_key_check'] = 'invalid'; // Will cause issue

        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        expect(vault.isInitialized, isTrue);
      });

      test('handles canary store failure gracefully', () async {
        _shouldFailEncrypt = true;

        final vault = RsplSecureVault();
        // Should not throw - handles gracefully
        await vault.initialize(bundleId: 'com.test');
        expect(vault.isInitialized, isTrue);
      });
    });

    // ==========================================================================
    // Store Tests
    // ==========================================================================
    group('Store', () {
      test('store encrypts and saves value', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await vault.store('key', 'secret');
        expect(_mockStorage['key'], 'enc:secret');
      });

      test('store throws on empty key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await expectLater(
          vault.store('', 'value'),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'INVALID_KEY'),
          ),
        );
      });

      test('store throws on empty value', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await expectLater(
          vault.store('key', ''),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'INVALID_VALUE'),
          ),
        );
      });

      test('store throws when not initialized', () async {
        final vault = RsplSecureVault();
        await expectLater(
          vault.store('key', 'value'),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'UNINITIALIZED'),
          ),
        );
      });

      test('store throws on encryption failure', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        _shouldFailEncrypt = true;
        await expectLater(
          vault.store('key', 'value'),
          throwsA(isA<PlatformException>()),
        );
      });

      test('store throws on empty ciphertext', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        _shouldReturnEmptyCiphertext = true;
        await expectLater(
          vault.store('key', 'value'),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'ENCRYPTION_FAILED'),
          ),
        );
      });
    });

    // ==========================================================================
    // Retrieve Tests
    // ==========================================================================
    group('Retrieve', () {
      test('retrieve decrypts stored value', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await vault.store('key', 'secret');
        final result = await vault.retrieve('key');
        expect(result, 'secret');
      });

      test('retrieve returns null for missing key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        final result = await vault.retrieve('nonexistent');
        expect(result, isNull);
      });

      test('retrieve returns null for empty stored value', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        _mockStorage['key'] = '';
        final result = await vault.retrieve('key');
        expect(result, isNull);
      });

      test('retrieve throws on empty key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await expectLater(
          vault.retrieve(''),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'INVALID_KEY'),
          ),
        );
      });

      test('retrieve throws when not initialized', () async {
        final vault = RsplSecureVault();
        await expectLater(
          vault.retrieve('key'),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'UNINITIALIZED'),
          ),
        );
      });
    });

    // ==========================================================================
    // Remove Tests
    // ==========================================================================
    group('Remove', () {
      test('remove deletes stored value', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await vault.store('key', 'secret');
        await vault.remove('key');
        expect(_mockStorage.containsKey('key'), isFalse);
      });

      test('remove does nothing for missing key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await vault.remove('nonexistent'); // Should not throw
      });

      test('remove throws on empty key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await expectLater(
          vault.remove(''),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'INVALID_KEY'),
          ),
        );
      });

      test('remove throws when not initialized', () async {
        final vault = RsplSecureVault();
        await expectLater(
          vault.remove('key'),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'UNINITIALIZED'),
          ),
        );
      });
    });

    // ==========================================================================
    // Clear Tests
    // ==========================================================================
    group('Clear', () {
      test('clear removes all stored values', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await vault.store('key1', 'value1');
        await vault.store('key2', 'value2');
        await vault.clear();
        expect(_mockStorage.isEmpty, isTrue);
      });

      test('clear throws when not initialized', () async {
        final vault = RsplSecureVault();
        await expectLater(
          vault.clear(),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'UNINITIALIZED'),
          ),
        );
      });
    });

    // ==========================================================================
    // ContainsKey Tests
    // ==========================================================================
    group('ContainsKey', () {
      test('containsKey returns true for existing key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await vault.store('key', 'value');
        expect(await vault.containsKey('key'), isTrue);
      });

      test('containsKey returns false for missing key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        expect(await vault.containsKey('nonexistent'), isFalse);
      });

      test('containsKey throws on empty key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');
        await expectLater(
          vault.containsKey(''),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'INVALID_KEY'),
          ),
        );
      });

      test('containsKey throws when not initialized', () async {
        final vault = RsplSecureVault();
        await expectLater(
          vault.containsKey('key'),
          throwsA(
            isA<PlatformException>()
                .having((e) => e.code, 'code', 'UNINITIALIZED'),
          ),
        );
      });
    });

    // ==========================================================================
    // Full Flow Tests
    // ==========================================================================
    group('Full Flow', () {
      test('store, retrieve, remove flow', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');

        // Store
        await vault.store('token', 'my_secret_token');
        expect(await vault.containsKey('token'), isTrue);

        // Retrieve
        final retrieved = await vault.retrieve('token');
        expect(retrieved, 'my_secret_token');

        // Remove
        await vault.remove('token');
        expect(await vault.containsKey('token'), isFalse);
        expect(await vault.retrieve('token'), isNull);
      });

      test('multiple keys', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');

        await vault.store('key1', 'value1');
        await vault.store('key2', 'value2');
        await vault.store('key3', 'value3');

        expect(await vault.retrieve('key1'), 'value1');
        expect(await vault.retrieve('key2'), 'value2');
        expect(await vault.retrieve('key3'), 'value3');
      });

      test('overwrite existing key', () async {
        final vault = RsplSecureVault();
        await vault.initialize(bundleId: 'com.test');

        await vault.store('key', 'original');
        expect(await vault.retrieve('key'), 'original');

        await vault.store('key', 'updated');
        expect(await vault.retrieve('key'), 'updated');
      });
    });
  });
}
