class SmokeConfig {
  SmokeConfig.fromEnvironment(Map<String, String> values)
    : project = _project(values['GCLOUD_PROJECT']),
      firestore = _endpoint(values['FIRESTORE_EMULATOR_HOST']),
      auth = _endpoint(values['FIREBASE_AUTH_EMULATOR_HOST']),
      storage = _endpoint(values['FIREBASE_STORAGE_EMULATOR_HOST']),
      database = _endpoint(values['FIREBASE_DATABASE_EMULATOR_HOST']);

  final String project;
  final Uri firestore;
  final Uri auth;
  final Uri storage;
  final Uri database;

  static String _project(String? value) {
    if (value == null || !RegExp(r'^demo-[a-z0-9][a-z0-9-]*$').hasMatch(value)) {
      throw const FormatException('An explicit demo project is required.');
    }
    return value;
  }

  static Uri _endpoint(String? value) {
    final match = value == null
        ? null
        : RegExp(r'^(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})$').firstMatch(value);
    if (match == null) {
      throw const FormatException('An explicit loopback host and port are required.');
    }
    final port = int.parse(match.group(2)!);
    if (port < 1 || port > 65535) {
      throw const FormatException('The emulator port is out of range.');
    }
    return Uri.parse('http://$value');
  }
}
