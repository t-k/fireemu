import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:fireemu_sdk_smoke_flutter/config.dart';

Map<String, String> validEnvironment() => {
  'GCLOUD_PROJECT': 'demo-app',
  'FIRESTORE_EMULATOR_HOST': '127.0.0.1:8080',
  'FIREBASE_AUTH_EMULATOR_HOST': '127.0.0.1:9099',
  'FIREBASE_STORAGE_EMULATOR_HOST': '127.0.0.1:9199',
  'FIREBASE_DATABASE_EMULATOR_HOST': '127.0.0.1:9000',
};

void main() {
  test('rejects a public endpoint before SDK initialization', () {
    final values = validEnvironment();
    values['FIRESTORE_EMULATOR_HOST'] = 'example.invalid:8080';
    expect(() => SmokeConfig.fromEnvironment(values), throwsFormatException);
  });
  test('accepts explicit loopback endpoints and demo project', () {
    final config = SmokeConfig.fromEnvironment(validEnvironment());
    expect(config.project, 'demo-app');
    expect(config.firestore.host, '127.0.0.1');
    expect(config.firestore.port, 8080);
  });
  for (final key in validEnvironment().keys) {
    test('rejects missing $key', () {
      final values = validEnvironment()..remove(key);
      expect(() => SmokeConfig.fromEnvironment(values), throwsFormatException);
    });
  }
  for (final endpoint in [
    'localhost.evil:8080', '127.0.0.1.evil:8080',
    '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:-1',
    '127.0.0.1:80/path', 'http://127.0.0.1:80',
    'user@127.0.0.1:80', '127.0.0.1', ' 127.0.0.1:80',
  ]) {
    test('rejects malformed or unsafe endpoint $endpoint', () {
      final values = validEnvironment()..['FIRESTORE_EMULATOR_HOST'] = endpoint;
      expect(() => SmokeConfig.fromEnvironment(values), throwsFormatException);
    });
  }
  for (final project in ['real-project', 'demo-', '', 'demo-app/path']) {
    test('rejects invalid project $project', () {
      final values = validEnvironment()..['GCLOUD_PROJECT'] = project;
      expect(() => SmokeConfig.fromEnvironment(values), throwsFormatException);
    });
  }
  test('accepts every valid port boundary', () {
    for (final port in [1, 80, 1024, 65535]) {
      final values = validEnvironment()
        ..['FIRESTORE_EMULATOR_HOST'] = '127.0.0.1:$port';
      expect(SmokeConfig.fromEnvironment(values).firestore.port, port);
    }
  });
  final tablePath = Platform.environment['FLUTTER_SMOKE_PICT'];
  if (tablePath != null) {
    final rows = File(tablePath).readAsLinesSync();
    for (var i = 1; i < rows.length; i++) {
      final cells = rows[i].split('\t');
      test('PICT row $i ${rows[i]}', () {
        final values = validEnvironment();
        final host = {'loopback': '127.0.0.1', 'deceptive': 'localhost.evil',
          'public': 'example.invalid'}[cells[0]]!;
        final port = {'valid': '8080', 'zero': '0', 'large': '65536'}[cells[1]]!;
        values['FIRESTORE_EMULATOR_HOST'] = '$host:$port';
        values['GCLOUD_PROJECT'] = cells[2] == 'demo' ? 'demo-app' : 'real-project';
        if (cells[0] == 'loopback' && cells[1] == 'valid' && cells[2] == 'demo') {
          expect(SmokeConfig.fromEnvironment(values).firestore.port, 8080);
        } else {
          expect(() => SmokeConfig.fromEnvironment(values), throwsFormatException);
        }
      });
    }
  }
}
