enum CaseStatus { passed, failed, blocked }

class SmokeReport {
  SmokeReport(List<String> requiredCases) : _required = Set.of(requiredCases) {
    if (_required.isEmpty || _required.length != requiredCases.length) {
      throw ArgumentError('Required case IDs must be nonempty and unique.');
    }
  }

  final Set<String> _required;
  final Map<String, Map<String, String>> _records = {};
  static const classifications = {
    'ok', 'assertion', 'sdk-error', 'timeout',
    'macos-keychain-provisioning', 'prerequisite',
  };

  bool get allPassed => _records.length == _required.length &&
      _records.values.every((result) => result['status'] == 'passed');

  List<Map<String, String>> get records =>
      _records.values.map((result) => Map<String, String>.unmodifiable(result)).toList();

  void record(String id, CaseStatus status, String classification) {
    if (!_required.contains(id) || _records.containsKey(id)) {
      throw StateError('Unknown or duplicate case ID.');
    }
    if (!classifications.contains(classification)) {
      throw ArgumentError('Only fixed sanitized classifications are allowed.');
    }
    _records[id] = {'case': id, 'status': status.name, 'classification': classification};
  }
}
