import 'dart:async';
import 'package:fireemu_sdk_smoke_flutter/offline_recovery.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('failed restoration blocks only Firestore-dependent cases', () async {
    final recovery = OfflineRecovery(() async {
      throw StateError('restore failed');
    });
    await recovery.start(() async {});
    await expectLater(recovery.close(), throwsStateError);
    for (final id in [
      'firestore.batch-delete',
      'flutter.timestamp-roundtrip',
      'flutter.fieldvalue-roundtrip',
      'flutter.firestore-stream-error',
    ]) {
      expect(recovery.blocks(id), isTrue);
    }
    for (final id in [
      'auth.signup',
      'storage.upload-download',
      'database.set-read',
      'flutter.database-stream-error',
    ]) {
      expect(recovery.blocks(id), isFalse);
    }
  });

  test(
    'timeout cleanup restores the client before the next operation',
    () async {
      var online = true;
      final pending = Completer<void>();
      final recovery = OfflineRecovery(() async {
        online = true;
      });
      await recovery.start(() async {
        online = false;
      });
      final body = recovery
          .wait(pending.future)
          .then((_) => 'late', onError: (_) => 'cancelled');
      await recovery.close();
      expect(
        online,
        isTrue,
        reason: 'The next independent server operation needs networking',
      );
      pending.complete();
      expect(await body, 'cancelled');
    },
  );

  test(
    'cleanup waits for disable and pending writes and rejects late continuation',
    () async {
      final disabled = Completer<void>();
      final write = Completer<void>();
      final pending = Completer<void>();
      var restored = false;
      var continued = false;
      var closed = false;
      final recovery = OfflineRecovery(() async {
        restored = true;
      });
      final starting = recovery.start(() => disabled.future).catchError((_) {});
      recovery.track(write.future);
      final body = recovery.wait(pending.future).then((_) {
        continued = true;
      }, onError: (_) {});
      final closing = recovery.close().then((_) {
        closed = true;
      });
      await Future<void>.delayed(Duration.zero);
      expect(closed, isFalse);
      disabled.complete();
      await starting;
      await Future<void>.delayed(Duration.zero);
      expect(restored, isTrue);
      expect(closed, isFalse);
      write.complete();
      await closing;
      pending.complete();
      await body;
      expect(continued, isFalse);
    },
  );
}
