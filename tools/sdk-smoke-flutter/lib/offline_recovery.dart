import 'dart:async';

/// Owns the offline case's pending observation and restores its shared client.
class OfflineRecovery {
  OfflineRecovery(this.restore);
  final Future<void> Function() restore;
  bool _unusable = false;
  bool blocks(String caseId) =>
      _unusable &&
      (caseId.startsWith('firestore.') ||
          const {
            'flutter.timestamp-roundtrip',
            'flutter.fieldvalue-roundtrip',
            'flutter.firestore-stream-error',
          }.contains(caseId));
  final _cancelled = Completer<void>();
  final _writes = <Future<void>>[];
  Future<void>? _disabled;
  Future<void>? _closing;
  bool _closed = false;

  Future<void> start(Future<void> Function() disable) {
    if (_closed) throw StateError('Offline case already closed.');
    _disabled = disable();
    return wait(_disabled!);
  }

  Future<T> wait<T>(Future<T> operation) async {
    if (_closed) throw StateError('Offline case already closed.');
    final result = await Future.any<T>([
      operation,
      _cancelled.future.then<T>(
        (_) => throw StateError('Offline case cancelled.'),
      ),
    ]);
    if (_closed) throw StateError('Offline case cancelled.');
    return result;
  }

  void track(Future<void> operation) {
    if (_closed) throw StateError('Offline case already closed.');
    _writes.add(operation.then<void>((_) {}, onError: (Object _) {}));
  }

  Future<void> close() {
    if (_closing != null) return _closing!;
    _closed = true;
    _cancelled.complete();
    return _closing = _restore()
        .timeout(const Duration(milliseconds: 1500))
        .catchError((Object error, StackTrace stack) {
          _unusable = true;
          Error.throwWithStackTrace(error, stack);
        });
  }

  Future<void> _restore() async {
    await _disabled;
    await restore();
    await Future.wait(_writes);
  }
}
