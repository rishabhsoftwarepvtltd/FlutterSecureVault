/// RSPL Secure Vault - Secure-by-default storage for Flutter apps.
///
/// This library provides secure, encrypted storage for sensitive data using
/// platform-specific hardware-backed key management:
/// - **iOS**: Secure Enclave and Keychain
/// - **Android**: Android Keystore with StrongBox support
///
/// ## Getting Started
///
/// ```dart
/// import 'package:rspl_secure_vault/rspl_secure_vault.dart';
///
/// // Create and initialize the vault
/// final vault = RsplSecureVault();
/// await vault.initialize(bundleId: 'com.example.myapp');
///
/// // Store sensitive data (automatically encrypted)
/// await vault.store('api_token', 'secret-value');
///
/// // Retrieve data (automatically decrypted)
/// final token = await vault.retrieve('api_token');
///
/// // Remove data
/// await vault.remove('api_token');
///
/// // Clear all data
/// await vault.clear();
/// ```
///
/// ## Security Features
///
/// - **Automatic Encryption**: All data is encrypted before storage
/// - **Envelope Encryption**: Uses AES-GCM with unique Data Encryption Keys (DEK)
/// - **Key Agreement**: ECDH (P-256) for secure key exchange
/// - **Key Derivation**: HKDF-SHA256 for deriving encryption keys
/// - **Hardware-backed Storage**: Keys are stored in secure hardware when available
/// - **Tamper Detection**: GCM authentication tags prevent data modification
///
/// ## Design Philosophy
///
/// This library is designed to be **secure by default**:
/// - No encryption configuration needed
/// - No storage type selection
/// - Simple API that's hard to misuse
/// - All security decisions are made internally
library;

export 'src/rspl_secure_vault.dart' show RsplSecureVault;
