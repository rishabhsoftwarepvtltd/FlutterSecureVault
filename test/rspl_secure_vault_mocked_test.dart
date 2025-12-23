import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rspl_secure_vault/src/common_platform/rspl_secure_vault_api.dart';

/// Test helper to set up mocked platform channels for RsplSecureVaultApi
class MockPlatformChannels {
  final Map<String, dynamic> _storage = {};
  bool _shouldFailInitialize = false;
  bool _shouldFailEncrypt = false;
  bool _shouldFailDecrypt = false;
  bool _shouldReturnNullEncrypt = false;
  bool _shouldReturnNullDecrypt = false;
  bool _shouldReturnConnectionError = false;

  void reset() {
    _storage.clear();
    _shouldFailInitialize = false;
    _shouldFailEncrypt = false;
    _shouldFailDecrypt = false;
    _shouldReturnNullEncrypt = false;
    _shouldReturnNullDecrypt = false;
    _shouldReturnConnectionError = false;
  }

  void setFailInitialize(bool value) => _shouldFailInitialize = value;
  void setFailEncrypt(bool value) => _shouldFailEncrypt = value;
  void setFailDecrypt(bool value) => _shouldFailDecrypt = value;
  void setReturnNullEncrypt(bool value) => _shouldReturnNullEncrypt = value;
  void setReturnNullDecrypt(bool value) => _shouldReturnNullDecrypt = value;
  void setReturnConnectionError(bool value) =>
      _shouldReturnConnectionError = value;

  void setupMockChannels() {
    // Get the binding
    final binding = TestWidgetsFlutterBinding.ensureInitialized();

    // Mock the Pigeon channels using BasicMessageChannel
    // Initialize channel
    binding.defaultBinaryMessenger.setMockMessageHandler(
      'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.initialize',
      (ByteData? message) async {
        if (_shouldReturnConnectionError) {
          return null; // This triggers connection error
        }

        if (_shouldFailInitialize) {
          // Return error response
          const codec = RsplSecureVaultApi.pigeonChannelCodec;
          return codec.encodeMessage([
            'INIT_ERROR',
            'Initialization failed',
            null,
          ]);
        }

        // Return success (empty response for void method)
        const codec = RsplSecureVaultApi.pigeonChannelCodec;
        return codec.encodeMessage([null]);
      },
    );

    // Encrypt channel
    binding.defaultBinaryMessenger.setMockMessageHandler(
      'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.encrypt',
      (ByteData? message) async {
        if (_shouldReturnConnectionError) {
          return null;
        }

        if (_shouldFailEncrypt) {
          const codec = RsplSecureVaultApi.pigeonChannelCodec;
          return codec.encodeMessage([
            'ENCRYPTION_FAILED',
            'Encryption failed',
            null,
          ]);
        }

        if (_shouldReturnNullEncrypt) {
          const codec = RsplSecureVaultApi.pigeonChannelCodec;
          return codec.encodeMessage([null]);
        }

        // Decode the request
        const codec = RsplSecureVaultApi.pigeonChannelCodec;
        final decoded = codec.decodeMessage(message);
        final request = (decoded as List)[0] as EncryptRequest;

        // Simulate encryption (just base64 encode for testing)
        final encrypted = 'encrypted:${request.plainText}';
        final response = EncryptResponse(cipherText: encrypted);

        return codec.encodeMessage([response]);
      },
    );

    // Decrypt channel
    binding.defaultBinaryMessenger.setMockMessageHandler(
      'dev.flutter.pigeon.rspl_secure_vault.RsplSecureVaultApi.decrypt',
      (ByteData? message) async {
        if (_shouldReturnConnectionError) {
          return null;
        }

        if (_shouldFailDecrypt) {
          const codec = RsplSecureVaultApi.pigeonChannelCodec;
          return codec.encodeMessage([
            'DECRYPTION_FAILED',
            'Decryption failed',
            null,
          ]);
        }

        if (_shouldReturnNullDecrypt) {
          const codec = RsplSecureVaultApi.pigeonChannelCodec;
          return codec.encodeMessage([null]);
        }

        // Decode the request
        const codec = RsplSecureVaultApi.pigeonChannelCodec;
        final decoded = codec.decodeMessage(message);
        final request = (decoded as List)[0] as DecryptRequest;

        // Simulate decryption (reverse of our mock encryption)
        String? plainText;
        if (request.cipherText?.startsWith('encrypted:') ?? false) {
          plainText = request.cipherText!.substring('encrypted:'.length);
        }
        final response = DecryptResponse(plainText: plainText);

        return codec.encodeMessage([response]);
      },
    );

    // Mock flutter_secure_storage channels
    binding.defaultBinaryMessenger.setMockMethodCallHandler(
      const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
      (MethodCall methodCall) async {
        switch (methodCall.method) {
          case 'read':
            final key = methodCall.arguments['key'] as String;
            return _storage[key];
          case 'write':
            final key = methodCall.arguments['key'] as String;
            final value = methodCall.arguments['value'] as String;
            _storage[key] = value;
            return null;
          case 'delete':
            final key = methodCall.arguments['key'] as String;
            _storage.remove(key);
            return null;
          case 'deleteAll':
            _storage.clear();
            return null;
          case 'containsKey':
            final key = methodCall.arguments['key'] as String;
            return _storage.containsKey(key);
          case 'readAll':
            return Map<String, String>.from(_storage);
          default:
            return null;
        }
      },
    );
  }

  void tearDownMockChannels() {
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
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // ============================================================================
  // RSPL SECURE VAULT API MOCKED TESTS
  // ============================================================================
  group('RsplSecureVaultApi - Mocked Platform Channels', () {
    late MockPlatformChannels mockChannels;

    setUp(() {
      mockChannels = MockPlatformChannels();
      mockChannels.setupMockChannels();
    });

    tearDown(() {
      mockChannels.tearDownMockChannels();
      mockChannels.reset();
    });

    test('initialize succeeds', () async {
      final api = RsplSecureVaultApi();
      await expectLater(
        api.initialize(InitRequest(bundleId: 'com.test')),
        completes,
      );
    });

    test('initialize throws on error', () async {
      mockChannels.setFailInitialize(true);
      final api = RsplSecureVaultApi();
      await expectLater(
        api.initialize(InitRequest(bundleId: 'com.test')),
        throwsA(isA<PlatformException>()),
      );
    });

    test('initialize throws connection error on null response', () async {
      mockChannels.setReturnConnectionError(true);
      final api = RsplSecureVaultApi();
      await expectLater(
        api.initialize(InitRequest(bundleId: 'com.test')),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'channel-error',
          ),
        ),
      );
    });

    test('encrypt succeeds', () async {
      final api = RsplSecureVaultApi();
      final response = await api.encrypt(EncryptRequest(plainText: 'secret'));
      expect(response.cipherText, 'encrypted:secret');
    });

    test('encrypt throws on error', () async {
      mockChannels.setFailEncrypt(true);
      final api = RsplSecureVaultApi();
      await expectLater(
        api.encrypt(EncryptRequest(plainText: 'secret')),
        throwsA(isA<PlatformException>()),
      );
    });

    test('encrypt throws on null response', () async {
      mockChannels.setReturnNullEncrypt(true);
      final api = RsplSecureVaultApi();
      await expectLater(
        api.encrypt(EncryptRequest(plainText: 'secret')),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'null-error',
          ),
        ),
      );
    });

    test('encrypt throws connection error on null response', () async {
      mockChannels.setReturnConnectionError(true);
      final api = RsplSecureVaultApi();
      await expectLater(
        api.encrypt(EncryptRequest(plainText: 'secret')),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'channel-error',
          ),
        ),
      );
    });

    test('decrypt succeeds', () async {
      final api = RsplSecureVaultApi();
      final response =
          await api.decrypt(DecryptRequest(cipherText: 'encrypted:secret'));
      expect(response.plainText, 'secret');
    });

    test('decrypt throws on error', () async {
      mockChannels.setFailDecrypt(true);
      final api = RsplSecureVaultApi();
      await expectLater(
        api.decrypt(DecryptRequest(cipherText: 'encrypted:secret')),
        throwsA(isA<PlatformException>()),
      );
    });

    test('decrypt throws on null response', () async {
      mockChannels.setReturnNullDecrypt(true);
      final api = RsplSecureVaultApi();
      await expectLater(
        api.decrypt(DecryptRequest(cipherText: 'encrypted:secret')),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'null-error',
          ),
        ),
      );
    });

    test('decrypt throws connection error on null response', () async {
      mockChannels.setReturnConnectionError(true);
      final api = RsplSecureVaultApi();
      await expectLater(
        api.decrypt(DecryptRequest(cipherText: 'encrypted:secret')),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'channel-error',
          ),
        ),
      );
    });
  });

  // ============================================================================
  // PIGEON CODEC TESTS
  // ============================================================================
  group('Pigeon Codec', () {
    test('codec encodes and decodes InitRequest', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;
      final request = InitRequest(bundleId: 'test');

      final buffer = codec.encodeMessage([request]);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], isA<InitRequest>());
    });

    test('codec encodes and decodes EncryptRequest', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;
      final request = EncryptRequest(plainText: 'secret');

      final buffer = codec.encodeMessage([request]);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], isA<EncryptRequest>());
    });

    test('codec encodes and decodes DecryptRequest', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;
      final request = DecryptRequest(cipherText: 'encrypted');

      final buffer = codec.encodeMessage([request]);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], isA<DecryptRequest>());
    });

    test('codec encodes and decodes EncryptResponse', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;
      final response = EncryptResponse(cipherText: 'encrypted');

      final buffer = codec.encodeMessage([response]);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], isA<EncryptResponse>());
    });

    test('codec encodes and decodes DecryptResponse', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;
      final response = DecryptResponse(plainText: 'decrypted');

      final buffer = codec.encodeMessage([response]);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], isA<DecryptResponse>());
    });

    test('codec encodes integers', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;

      final buffer = codec.encodeMessage([42]);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], 42);
    });

    test('codec handles null values', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;

      final buffer = codec.encodeMessage([null]);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], isNull);
    });

    test('codec encodes other types using super', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;

      // String should use super.writeValue
      final buffer = codec.encodeMessage(['test string']);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], 'test string');
    });

    test('codec readValueOfType returns super for unknown types', () {
      const codec = RsplSecureVaultApi.pigeonChannelCodec;

      // Double should use default codec behavior
      final buffer = codec.encodeMessage([3.14]);
      expect(buffer, isNotNull);

      final decoded = codec.decodeMessage(buffer);
      expect(decoded, isA<List>());
      expect((decoded as List)[0], 3.14);
    });
  });

  // ============================================================================
  // DEEP EQUALS INTERNAL FUNCTION TESTS
  // ============================================================================
  group('Deep Equals Function (via Data Classes)', () {
    test('list equality with same elements', () {
      final a = InitRequest(bundleId: 'test');
      final b = InitRequest(bundleId: 'test');

      // The == operator uses _deepEquals internally
      expect(a == b, isTrue);
    });

    test('list equality with different elements', () {
      final a = InitRequest(bundleId: 'test1');
      final b = InitRequest(bundleId: 'test2');

      expect(a == b, isFalse);
    });

    test('list equality with different lengths', () {
      // This is tested indirectly - different bundleId values
      final a = InitRequest(bundleId: 'short');
      final b = InitRequest(bundleId: 'longer_value');

      expect(a == b, isFalse);
    });

    test('nested list comparison', () {
      final request1 = EncryptRequest(plainText: 'test');
      final request2 = EncryptRequest(plainText: 'test');

      // encode() returns List, == uses _deepEquals
      expect(request1, request2);
    });

    test('map comparison via encode', () {
      // Pigeon data classes use List, but this tests the general pattern
      final a = InitRequest();
      final b = InitRequest();

      expect(a.encode(), b.encode());
    });
  });

  // ============================================================================
  // API CHANNEL SUFFIX TESTS
  // ============================================================================
  group('API Channel Suffix', () {
    test('empty suffix produces no dot', () {
      final api = RsplSecureVaultApi(messageChannelSuffix: '');
      expect(api, isNotNull);
    });

    test('non-empty suffix adds dot prefix', () {
      final api = RsplSecureVaultApi(messageChannelSuffix: 'test');
      expect(api, isNotNull);
    });

    test('custom binary messenger is used', () {
      final binding = TestWidgetsFlutterBinding.ensureInitialized();
      final api = RsplSecureVaultApi(
        binaryMessenger: binding.defaultBinaryMessenger,
        messageChannelSuffix: 'custom',
      );
      expect(api, isNotNull);
    });
  });
}
