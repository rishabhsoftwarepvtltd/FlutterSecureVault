# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3]

### Changed
- Converted LICENSE file from markdown to plain text format for better compatibility

---

## [0.0.2]

### Changed
- Shortened package description for better pub.dev search optimization
- Updated license to Rishabh Software Source Available License (Non-Commercial) v1.0

### Added
- Test coverage badge (100%) in README
- Platform declaration in pubspec.yaml

---

## [0.0.1]

### Added
- Initial release of RSPL Secure Vault
- Envelope encryption with unique DEK (Data Encryption Key) per operation
- Hardware-backed key storage:
  - iOS: Secure Enclave + Keychain
  - Android: Android Keystore with StrongBox support (when available)
- AES-256-GCM encryption for all stored data
- ECDH P-256 key agreement for secure key derivation
- HKDF-SHA256 for key derivation function
- Simple, secure-by-default API:
  - `store(key, value)` - Encrypt and store data
  - `retrieve(key)` - Retrieve and decrypt data
  - `remove(key)` - Remove specific key-value pair
  - `clear()` - Remove all stored data
  - `containsKey(key)` - Check if key exists
- Internal security audit (62/62 checks passed)
- 100% Dart test coverage

### Security
- Cryptographically secure random number generators for all encryption
- Per-operation unique nonces prevent nonce reuse attacks
- GCM authentication tags (128-bit) ensure data integrity
- Master keys never leave hardware security module
- Debug logging gated behind `kDebugMode` (Dart) and `#if DEBUG` (native)
- No sensitive data in error messages or logs

### Documentation
- Comprehensive README with quick start guide
- Common use cases (auth tokens, API keys)
- Error handling guide
- FAQ section
- Security Audit report (SECURITY_AUDIT.md)
- Architecture diagrams
