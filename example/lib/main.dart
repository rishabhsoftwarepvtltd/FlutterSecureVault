import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:rspl_secure_vault/rspl_secure_vault.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RSPL Secure Vault',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1E3A5F),
          brightness: Brightness.light,
        ),
        useMaterial3: true,
        fontFamily: 'SF Pro Display',
      ),
      home: const SecureVaultDemo(),
    );
  }
}

class SecureVaultDemo extends StatefulWidget {
  const SecureVaultDemo({super.key});

  @override
  State<SecureVaultDemo> createState() => _SecureVaultDemoState();
}

class _SecureVaultDemoState extends State<SecureVaultDemo> {
  final _vault = RsplSecureVault();
  final _keyController = TextEditingController();
  final _valueController = TextEditingController();

  String _status = 'Initializing...';
  bool _isInitialized = false;
  String? _retrievedValue;
  final List<String> _logs = [];

  @override
  void initState() {
    super.initState();
    _initializeVault();
  }

  void _log(String message) {
    debugPrint(message);
    setState(() {
      _logs.insert(
        0,
        '${DateTime.now().toString().substring(11, 19)} - $message',
      );
      if (_logs.length > 10) _logs.removeLast();
    });
  }

  Future<void> _initializeVault() async {
    try {
      await _vault.initialize(bundleId: 'com.rspl.securevault.rsplSecureVaultExample');

      if (mounted) {
        setState(() {
          _status = 'Vault initialized successfully!';
          _isInitialized = true;
        });
        _log('Vault initialized');
      }
    } on PlatformException catch (e) {
      if (mounted) {
        setState(() {
          _status = 'Failed to initialize: ${e.message}';
        });
        _log('Init error: ${e.message}');
      }
    }
  }

  Future<void> _storeValue() async {
    final key = _keyController.text.trim();
    final value = _valueController.text.trim();
    
    if (key.isEmpty || value.isEmpty) {
      _showSnackBar('Please enter both key and value');
      return;
    }

    try {
      await _vault.store(key, value);
      _log('Stored: $key');
      _showSnackBar('Value stored securely!');
    } on PlatformException catch (e) {
      _log('Store error: ${e.message}');
      _showSnackBar('Error: ${e.message}');
    }
  }

  Future<void> _retrieveValue() async {
    final key = _keyController.text.trim();
    
    if (key.isEmpty) {
      _showSnackBar('Please enter a key');
      return;
    }

    try {
      final value = await _vault.retrieve(key);
      setState(() {
        _retrievedValue = value;
      });

      if (value != null) {
        _log('Retrieved: $key');
        _showSnackBar('Value retrieved!');
      } else {
        _log('Key not found: $key');
        _showSnackBar('No value found for this key');
      }
    } on PlatformException catch (e) {
      _log('Retrieve error: ${e.message}');
      _showSnackBar('Error: ${e.message}');
    }
  }

  Future<void> _removeValue() async {
    final key = _keyController.text.trim();
    
    if (key.isEmpty) {
      _showSnackBar('Please enter a key');
      return;
    }

    try {
      await _vault.remove(key);
      setState(() {
        _retrievedValue = null;
      });
      _log('Removed: $key');
      _showSnackBar('Value removed!');
    } on PlatformException catch (e) {
      _log('Remove error: ${e.message}');
      _showSnackBar('Error: ${e.message}');
    }
  }

  Future<void> _clearAll() async {
    try {
      await _vault.clear();
      setState(() {
        _retrievedValue = null;
      });
      _log('Cleared all values');
      _showSnackBar('All values cleared!');
    } on PlatformException catch (e) {
      _log('Clear error: ${e.message}');
      _showSnackBar('Error: ${e.message}');
    }
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        behavior: SnackBarBehavior.floating,
        duration: const Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'RSPL Secure Vault',
          style: TextStyle(fontWeight: FontWeight.w600),
        ),
        centerTitle: true,
        elevation: 0,
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Status Card
              _buildStatusCard(),
              const SizedBox(height: 16),

              // Input Section
              if (_isInitialized) ...[
                _buildInputCard(),
                const SizedBox(height: 16),

                // Actions Section
                _buildActionsCard(),
                const SizedBox(height: 16),

                // Retrieved Value Section
                if (_retrievedValue != null) _buildResultCard(),
                if (_retrievedValue != null) const SizedBox(height: 16),

                // Activity Log
                _buildLogCard(),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStatusCard() {
    final isError = _status.contains('Failed') || _status.contains('error');
    final isSuccess = _status.contains('successfully');

    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: isSuccess
              ? Colors.green.shade200
              : isError
              ? Colors.red.shade200
              : Colors.orange.shade200,
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(
              isSuccess
                  ? Icons.check_circle
                  : isError
                  ? Icons.error
                  : Icons.hourglass_top,
              color: isSuccess
                  ? Colors.green.shade600
                  : isError
                  ? Colors.red.shade600
                  : Colors.orange.shade600,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                _status,
                style: TextStyle(
                  color: isSuccess
                      ? Colors.green.shade700
                      : isError
                      ? Colors.red.shade700
                      : Colors.orange.shade700,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInputCard() {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: Colors.grey.shade300),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Secure Storage',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _keyController,
              decoration: InputDecoration(
                labelText: 'Key',
                hintText: 'e.g., api_token, user_secret',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                prefixIcon: const Icon(Icons.key),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _valueController,
              decoration: InputDecoration(
                labelText: 'Value',
                hintText: 'The secret value to store',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                prefixIcon: const Icon(Icons.lock),
              ),
              obscureText: true,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildActionsCard() {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: Colors.grey.shade300),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Actions',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: FilledButton.icon(
                    onPressed: _storeValue,
                    icon: const Icon(Icons.save),
                    label: const Text('Store'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.tonalIcon(
                    onPressed: _retrieveValue,
                    icon: const Icon(Icons.search),
                    label: const Text('Retrieve'),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _removeValue,
                    icon: const Icon(Icons.delete_outline),
                    label: const Text('Remove'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _clearAll,
                    icon: const Icon(Icons.clear_all),
                    label: const Text('Clear All'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Colors.red.shade600,
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildResultCard() {
    return Card(
      elevation: 0,
      color: Theme.of(
        context,
      ).colorScheme.primaryContainer.withValues(alpha: 0.3),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.visibility,
                  size: 20,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 8),
                const Text(
                  'Retrieved Value',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.grey.shade300),
              ),
              child: SelectableText(
                _retrievedValue ?? '',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 14),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildLogCard() {
    if (_logs.isEmpty) return const SizedBox.shrink();

    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: Colors.grey.shade300),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.history, size: 20, color: Colors.grey.shade600),
                const SizedBox(width: 8),
                const Text(
                  'Activity Log',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
                ),
              ],
            ),
            const SizedBox(height: 12),
            ...List.generate(
              _logs.length,
              (index) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: Text(
                  _logs[index],
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Colors.grey.shade700,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _keyController.dispose();
    _valueController.dispose();
    super.dispose();
  }
}
