// This is a basic Flutter integration test.
//
// Since integration tests run in a full Flutter application, they can interact
// with the host side of a plugin implementation, unlike Dart unit tests.
//
// For more information about Flutter integration tests, please see
// https://flutter.dev/to/integration-testing

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'package:rspl_secure_vault/rspl_secure_vault.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('RsplSecureVault Integration Tests', () {
    late RsplSecureVault vault;

    setUpAll(() async {
      vault = RsplSecureVault();
      await vault.initialize(bundleId: 'com.example.rspl_secure_vault.test');
    });

    testWidgets('vault initializes successfully', (WidgetTester tester) async {
      expect(vault.isInitialized, isTrue);
    });

    testWidgets('store and retrieve simple string', (
      WidgetTester tester,
    ) async {
      const testKey = 'test_key_simple';
      const testValue = 'test_value_simple';

      // Store
      await vault.store(testKey, testValue);

      // Retrieve
      final retrieved = await vault.retrieve(testKey);
      expect(retrieved, equals(testValue));

      // Cleanup
      await vault.remove(testKey);
    });

    testWidgets('store and retrieve unicode string', (
      WidgetTester tester,
    ) async {
      const testKey = 'test_key_unicode';
      const testValue = '你好世界 🔐🛡️ مرحبا Привет';

      await vault.store(testKey, testValue);
      final retrieved = await vault.retrieve(testKey);
      expect(retrieved, equals(testValue));

      await vault.remove(testKey);
    });

    testWidgets('store and retrieve special characters', (
      WidgetTester tester,
    ) async {
      const testKey = 'test_key_special';
      const testValue = '!@#\$%^&*()_+-=[]{}|;:\'",.<>?/\\`~';

      await vault.store(testKey, testValue);
      final retrieved = await vault.retrieve(testKey);
      expect(retrieved, equals(testValue));

      await vault.remove(testKey);
    });

    testWidgets('store and retrieve JSON string', (WidgetTester tester) async {
      const testKey = 'test_key_json';
      const testValue =
          '{"token": "abc123", "user": {"id": 1, "name": "Test"}}';

      await vault.store(testKey, testValue);
      final retrieved = await vault.retrieve(testKey);
      expect(retrieved, equals(testValue));

      await vault.remove(testKey);
    });

    testWidgets('store and retrieve long string', (WidgetTester tester) async {
      const testKey = 'test_key_long';
      final testValue = 'a' * 10000;

      await vault.store(testKey, testValue);
      final retrieved = await vault.retrieve(testKey);
      expect(retrieved, equals(testValue));

      await vault.remove(testKey);
    });

    testWidgets('retrieve returns null for non-existent key', (
      WidgetTester tester,
    ) async {
      final retrieved = await vault.retrieve('non_existent_key_12345');
      expect(retrieved, isNull);
    });

    testWidgets('containsKey returns correct values', (
      WidgetTester tester,
    ) async {
      const testKey = 'test_key_contains';
      const testValue = 'test_value';

      // Should not contain initially
      expect(await vault.containsKey(testKey), isFalse);

      // Store and check
      await vault.store(testKey, testValue);
      expect(await vault.containsKey(testKey), isTrue);

      // Remove and check
      await vault.remove(testKey);
      expect(await vault.containsKey(testKey), isFalse);
    });

    testWidgets('remove deletes stored value', (WidgetTester tester) async {
      const testKey = 'test_key_remove';
      const testValue = 'test_value';

      await vault.store(testKey, testValue);
      expect(await vault.retrieve(testKey), equals(testValue));

      await vault.remove(testKey);
      expect(await vault.retrieve(testKey), isNull);
    });

    testWidgets('clear removes all stored values', (WidgetTester tester) async {
      // Store multiple values
      await vault.store('clear_test_1', 'value1');
      await vault.store('clear_test_2', 'value2');
      await vault.store('clear_test_3', 'value3');

      // Verify they exist
      expect(await vault.containsKey('clear_test_1'), isTrue);
      expect(await vault.containsKey('clear_test_2'), isTrue);
      expect(await vault.containsKey('clear_test_3'), isTrue);

      // Clear all
      await vault.clear();

      // Verify they're gone
      expect(await vault.retrieve('clear_test_1'), isNull);
      expect(await vault.retrieve('clear_test_2'), isNull);
      expect(await vault.retrieve('clear_test_3'), isNull);
    });

    testWidgets('overwrite existing value', (WidgetTester tester) async {
      const testKey = 'test_key_overwrite';
      const originalValue = 'original_value';
      const newValue = 'new_value';

      await vault.store(testKey, originalValue);
      expect(await vault.retrieve(testKey), equals(originalValue));

      await vault.store(testKey, newValue);
      expect(await vault.retrieve(testKey), equals(newValue));

      await vault.remove(testKey);
    });

    testWidgets('throws on empty key', (WidgetTester tester) async {
      expect(
        () => vault.store('', 'value'),
        throwsA(
          isA<PlatformException>().having((e) => e.code, 'code', 'INVALID_KEY'),
        ),
      );
    });

    testWidgets('throws on empty value', (WidgetTester tester) async {
      expect(
        () => vault.store('key', ''),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'INVALID_VALUE',
          ),
        ),
      );
    });

    testWidgets('encryption produces unique outputs', (
      WidgetTester tester,
    ) async {
      const testKey1 = 'unique_test_1';
      const testKey2 = 'unique_test_2';
      const sameValue = 'same_value_for_both';

      // Store the same value under two different keys
      await vault.store(testKey1, sameValue);
      await vault.store(testKey2, sameValue);

      // Both should decrypt to the same value
      expect(await vault.retrieve(testKey1), equals(sameValue));
      expect(await vault.retrieve(testKey2), equals(sameValue));

      // Cleanup
      await vault.remove(testKey1);
      await vault.remove(testKey2);
    });

    testWidgets('multiple sequential operations work correctly', (
      WidgetTester tester,
    ) async {
      // Perform many operations in sequence
      for (int i = 0; i < 10; i++) {
        final key = 'sequential_test_$i';
        final value = 'value_$i';

        await vault.store(key, value);
        final retrieved = await vault.retrieve(key);
        expect(retrieved, equals(value));
        await vault.remove(key);
      }
    });
  });
}
