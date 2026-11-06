import 'package:flutter_test/flutter_test.dart';
import 'package:fireemu_sdk_smoke_flutter/report.dart';

void main() {
  test('missing required result cannot pass', () {
    final report = SmokeReport(['first', 'second']);
    report.record('first', CaseStatus.passed, 'ok');
    expect(report.allPassed, isFalse);
  });
  test('blocked required case cannot pass', () {
    final report = SmokeReport(['first']);
    report.record('first', CaseStatus.blocked, 'macos-keychain-provisioning');
    expect(report.allPassed, isFalse);
  });
  test('all required results pass exactly once', () {
    final report = SmokeReport(['first', 'second']);
    report.record('first', CaseStatus.passed, 'ok');
    report.record('second', CaseStatus.passed, 'ok');
    expect(report.allPassed, isTrue);
    expect(() => report.record('first', CaseStatus.passed, 'ok'), throwsStateError);
    expect(() => report.record('unknown', CaseStatus.passed, 'ok'), throwsStateError);
  });
  test('unsafe classifications cannot enter public report', () {
    final report = SmokeReport(['first']);
    expect(() => report.record('first', CaseStatus.failed, 'raw exception /path'),
      throwsArgumentError);
  });
}
