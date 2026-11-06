import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_database/firebase_database.dart' as rtdb;
import 'package:firebase_storage/firebase_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:fireemu_sdk_smoke_flutter/config.dart';
import 'package:fireemu_sdk_smoke_flutter/report.dart';

const caseIds = [
  'firestore.write-read',
  'firestore.transforms',
  'firestore.query',
  'firestore.listener',
  'firestore.transaction',
  'firestore.offline-resume',
  'firestore.batch-delete',
  'firestore.rules-anonymous-denied',
  'firestore.rules-owner',
  'firestore.rules-signout',
  'auth.signup',
  'auth.signin',
  'auth.refresh',
  'storage.upload-download',
  'storage.metadata',
  'storage.resumable',
  'storage.download-url',
  'storage.list-delete',
  'storage.rules-denied',
  'database.set-read',
  'database.listener',
  'database.transaction',
  'database.on-disconnect',
  'flutter.timestamp-roundtrip',
  'flutter.fieldvalue-roundtrip',
  'flutter.firestore-stream-error',
  'flutter.database-stream-error',
];

class Prerequisite implements Exception {
  Prerequisite(this.classification);
  final String classification;
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets(
    'all native FlutterFire client cases',
    (tester) async {
      final report = SmokeReport(caseIds);
      final config = SmokeConfig.fromEnvironment(const {
        'GCLOUD_PROJECT': String.fromEnvironment('GCLOUD_PROJECT'),
        'FIRESTORE_EMULATOR_HOST': String.fromEnvironment(
          'FIRESTORE_EMULATOR_HOST',
        ),
        'FIREBASE_AUTH_EMULATOR_HOST': String.fromEnvironment(
          'FIREBASE_AUTH_EMULATOR_HOST',
        ),
        'FIREBASE_STORAGE_EMULATOR_HOST': String.fromEnvironment(
          'FIREBASE_STORAGE_EMULATOR_HOST',
        ),
        'FIREBASE_DATABASE_EMULATOR_HOST': String.fromEnvironment(
          'FIREBASE_DATABASE_EMULATOR_HOST',
        ),
      });
      final app = await Firebase.initializeApp(
        name: '[DEFAULT]',
        options: config.firebaseOptions,
      );
      final observerApp = await Firebase.initializeApp(
        name: 'observer',
        options: config.firebaseOptions,
      );
      expect(app.options.storageBucket, '${config.project}.appspot.com');
      expect(
        observerApp.options.storageBucket,
        '${config.project}.appspot.com',
      );
      final firestore = FirebaseFirestore.instanceFor(app: app);
      final observer = FirebaseFirestore.instanceFor(app: observerApp);
      for (final client in [firestore, observer]) {
        client.useFirestoreEmulator(
          config.firestore.host,
          config.firestore.port,
        );
        client.settings = const Settings(persistenceEnabled: false);
      }
      final auth = FirebaseAuth.instanceFor(app: app);
      await auth.useAuthEmulator(config.auth.host, config.auth.port);
      final storage = FirebaseStorage.instanceFor(
        app: app,
        bucket: '${config.project}.appspot.com',
      );
      await storage.useStorageEmulator(
        config.storage.host,
        config.storage.port,
      );
      final anonymousStorage = FirebaseStorage.instanceFor(
        app: observerApp,
        bucket: '${config.project}.appspot.com',
      );
      await anonymousStorage.useStorageEmulator(
        config.storage.host,
        config.storage.port,
      );
      final databaseUrl =
          'https://${config.project}-default-rtdb.firebaseio.com';
      final database = rtdb.FirebaseDatabase.instanceFor(
        app: app,
        databaseURL: databaseUrl,
      );
      final databaseObserver = rtdb.FirebaseDatabase.instanceFor(
        app: observerApp,
        databaseURL: databaseUrl,
      );
      for (final client in [database, databaseObserver]) {
        client.useDatabaseEmulator(config.database.host, config.database.port);
        client.setPersistenceEnabled(false);
      }
      const server = GetOptions(source: Source.server);
      String? identity;
      String authBlock = 'prerequisite';
      final suffix = DateTime.now().microsecondsSinceEpoch.toRadixString(36);
      final address =
          'fixture-$suffix@'
          'example.invalid';
      final password = 'local-smoke-' + suffix;
      final smallBytes = Uint8List.fromList([0, 1, 127, 128, 255]);
      final smallObject = storage.ref('public/bytes-é.bin');
      final cleanup = <Future<void> Function()>[];

      void requireAuth() {
        if (identity == null) throw Prerequisite(authBlock);
      }

      Future<void> runCase(String id, Future<void> Function() body) async {
        final cleanupStart = cleanup.length;
        var status = CaseStatus.passed;
        var classification = 'ok';
        try {
          await body().timeout(const Duration(seconds: 30));
        } on Prerequisite catch (error) {
          status = CaseStatus.blocked;
          classification = error.classification;
        } on TimeoutException {
          status = CaseStatus.failed;
          classification = 'timeout';
        } on FirebaseAuthException catch (error) {
          if (RegExp(r'^[a-z0-9_-]{1,80}$').hasMatch(error.code)) {
            print('FIREEMU_DIAGNOSTIC $id SDK code ${error.code}');
          }
          final message = error.message ?? '';
          print(
            'FIREEMU_DIAGNOSTIC $id native17999=${message.contains('17999')} http404=${message.contains('404')} legacyRoute=${message.contains('relyingparty')}',
          );
          final keychain =
              error.code == 'keychain-error' ||
              message.contains('-34018') ||
              message.contains('17995');
          status = keychain ? CaseStatus.blocked : CaseStatus.failed;
          classification = keychain
              ? 'macos-keychain-provisioning'
              : 'sdk-error';
          if (keychain) authBlock = classification;
        } on FirebaseException {
          status = CaseStatus.failed;
          classification = 'sdk-error';
        } catch (_, stack) {
          final location = RegExp(
            r'smoke_test\.dart:(\d+):(\d+)',
          ).firstMatch(stack.toString());
          if (location != null)
            print('FIREEMU_DIAGNOSTIC $id assertion-line ${location.group(1)}');
          status = CaseStatus.failed;
          classification = 'assertion';
        }
        for (final cancel in cleanup.sublist(cleanupStart)) {
          try {
            await cancel().timeout(const Duration(seconds: 2));
          } catch (_) {
            status = CaseStatus.failed;
            classification = 'timeout';
          }
        }
        cleanup.removeRange(cleanupStart, cleanup.length);
        report.record(id, status, classification);
        print('FIREEMU_CASE ${jsonEncode(report.records.last)}');
      }

      Future<void> denied(Future<Object?> operation, Set<String> codes) async {
        try {
          await operation;
          fail('The protected operation unexpectedly succeeded.');
        } on FirebaseException catch (error) {
          expect(codes, contains(error.code));
        }
      }

      try {
        await runCase('firestore.write-read', () async {
          final ref = firestore.doc('public/roundtrip');
          await ref.set({
            'number': 7,
            'text': 'hello',
            'nested': {'flag': true},
          });
          expect((await ref.get(server)).data(), {
            'number': 7,
            'text': 'hello',
            'nested': {'flag': true},
          });
        });
        await runCase('firestore.transforms', () async {
          final ref = firestore.doc('public/transforms');
          await ref.set({
            'count': 2,
            'items': ['a'],
          });
          await ref.update({
            'count': FieldValue.increment(3),
            'items': FieldValue.arrayUnion(['a', 'b']),
            'time': FieldValue.serverTimestamp(),
          });
          final data = (await ref.get(server)).data()!;
          expect(data['count'], 5);
          expect(data['items'], ['a', 'b']);
          expect(data['time'], isA<Timestamp>());
        });
        await runCase('firestore.query', () async {
          final collection = firestore.collection('public/query/rows');
          for (var i = 0; i < 3; i++) {
            await collection.doc('row-$i').set({'rank': i});
          }
          final result = await collection
              .where('rank', isGreaterThanOrEqualTo: 1)
              .orderBy('rank', descending: true)
              .limit(1)
              .get(server);
          expect(result.docs.map((doc) => doc.id), ['row-2']);
          expect(result.docs.single.data(), {'rank': 2});
        });
        await runCase('firestore.listener', () async {
          final ref = firestore.doc('public/listener');
          await ref.set({'value': 1});
          final initial = Completer<void>();
          final updated = Completer<void>();
          final sub = ref
              .snapshots(includeMetadataChanges: true)
              .listen(
                (snapshot) {
                  if (snapshot.metadata.isFromCache ||
                      snapshot.metadata.hasPendingWrites)
                    return;
                  if (snapshot.data()?['value'] == 1 && !initial.isCompleted)
                    initial.complete();
                  if (snapshot.data()?['value'] == 2 && !updated.isCompleted)
                    updated.complete();
                },
                onError: (Object error) {
                  if (!initial.isCompleted) initial.completeError(error);
                  if (!updated.isCompleted) updated.completeError(error);
                },
              );
          cleanup.add(sub.cancel);
          try {
            await initial.future;
            await observer.doc(ref.path).update({'value': 2});
            await updated.future;
          } finally {
            await sub.cancel();
          }
        });
        await runCase('firestore.transaction', () async {
          final ref = firestore.doc('public/transaction');
          await ref.set({'count': 1});
          await firestore.runTransaction((transaction) async {
            final snapshot = await transaction.get(ref);
            transaction.update(ref, {
              'count': (snapshot.data()!['count'] as num) + 1,
            });
          });
          expect(
            (await observer.doc(ref.path).get(server)).data()?['count'],
            2,
          );
        });
        await runCase('firestore.offline-resume', () async {
          final ref = firestore.doc('public/offline');
          await ref.set({'value': 0});
          await firestore.disableNetwork();
          final pending = Completer<void>();
          final sub = ref.snapshots(includeMetadataChanges: true).listen((
            event,
          ) {
            if (event.metadata.hasPendingWrites &&
                event.data()?['value'] == 1 &&
                !pending.isCompleted)
              pending.complete();
          });
          cleanup.add(sub.cancel);
          try {
            final write = ref.update({'value': 1});
            await pending.future;
            await firestore.enableNetwork();
            await write;
            expect(
              (await observer.doc(ref.path).get(server)).data()?['value'],
              1,
            );
          } finally {
            await firestore.enableNetwork();
            await sub.cancel();
          }
        });
        await runCase('firestore.batch-delete', () async {
          final old = firestore.doc('public/batch-old');
          final fresh = firestore.doc('public/batch-new');
          await old.set({'old': true});
          final batch = firestore.batch();
          batch.delete(old);
          batch.set(fresh, {'new': true});
          await batch.commit();
          expect((await old.get(server)).exists, isFalse);
          expect((await fresh.get(server)).data(), {'new': true});
        });
        await runCase('firestore.rules-anonymous-denied', () async {
          await denied(observer.doc('profiles/protected').get(server), {
            'permission-denied',
          });
          expect(
            (await observer.collection('public').limit(1).get(server)).docs,
            isNotEmpty,
          );
        });
        await runCase('auth.signup', () async {
          final credential = await auth.createUserWithEmailAndPassword(
            email: address,
            password: password,
          );
          identity = credential.user?.uid;
          expect(identity, isNotEmpty);
        });
        await runCase('auth.signin', () async {
          requireAuth();
          await auth.signOut();
          final credential = await auth.signInWithEmailAndPassword(
            email: address,
            password: password,
          );
          expect(credential.user?.uid, identity);
        });
        await runCase('auth.refresh', () async {
          requireAuth();
          final token = await auth.currentUser!.getIdTokenResult(true);
          expect(token.claims?['sub'], identity);
        });
        await runCase('firestore.rules-owner', () async {
          requireAuth();
          await firestore.doc('profiles/$identity').set({'value': 'owned'});
          await denied(
            firestore.doc('profiles/other-owner').set({'value': 'forbidden'}),
            {'permission-denied'},
          );
          await firestore.doc('notes/owned').set({
            'owner': identity,
            'value': 7,
          });
          final result = await firestore
              .collection('notes')
              .where('owner', isEqualTo: identity)
              .get(server);
          expect(result.docs.map((doc) => doc.id), ['owned']);
          expect(result.docs.single.data()['value'], 7);
        });
        await runCase('storage.upload-download', () async {
          await smallObject.putData(smallBytes);
          expect(await smallObject.getData(), smallBytes);
        });
        await runCase('storage.metadata', () async {
          await smallObject.putData(
            smallBytes,
            SettableMetadata(
              contentType: 'application/octet-stream',
              customMetadata: {'stage': 'one'},
            ),
          );
          final first = await smallObject.getMetadata();
          expect(first.size, smallBytes.length);
          expect(first.contentType, 'application/octet-stream');
          expect(first.customMetadata, {'stage': 'one'});
          await smallObject.updateMetadata(
            SettableMetadata(customMetadata: {'stage': 'two'}),
          );
          expect((await smallObject.getMetadata()).customMetadata, {
            'stage': 'two',
          });
        });
        await runCase('storage.resumable', () async {
          final bytes = Uint8List.fromList(
            List.generate(600000, (i) => i % 251),
          );
          final ref = storage.ref('public/resumable.bin');
          final task = ref.putData(bytes);
          var progressSeen = false;
          final sub = task.snapshotEvents.listen((event) {
            if (event.bytesTransferred > 0) progressSeen = true;
          });
          cleanup.add(sub.cancel);
          try {
            final result = await task;
            print(
              'FIREEMU_DIAGNOSTIC storage.resumable transferred=${result.bytesTransferred} expected=${bytes.length} progressSeen=$progressSeen',
            );
            // Native progress includes multipart framing; verify stored bytes separately.
            expect(result.bytesTransferred, result.totalBytes);
            expect(result.totalBytes, greaterThanOrEqualTo(bytes.length));
            expect((await ref.getMetadata()).size, bytes.length);
            expect(progressSeen, isTrue);
            expect(await ref.getData(600001), bytes);
          } finally {
            await sub.cancel();
          }
        });
        await runCase('storage.download-url', () async {
          final url = Uri.parse(await smallObject.getDownloadURL());
          expect(url.scheme, 'http');
          expect(['127.0.0.1', 'localhost', '::1'], contains(url.host));
          expect(url.port, config.storage.port);
          final client = HttpClient();
          try {
            final response = await (await client.getUrl(url)).close();
            expect(response.statusCode, 200);
            final bytes = await response.fold<List<int>>(
              [],
              (all, chunk) => all..addAll(chunk),
            );
            expect(bytes, smallBytes);
          } finally {
            client.close(force: true);
          }
        });
        await runCase('storage.list-delete', () async {
          final listing = await storage.ref('public').listAll();
          expect(
            listing.items.map((item) => item.name),
            contains('bytes-é.bin'),
          );
          await smallObject.delete();
          await denied(smallObject.getMetadata(), {'object-not-found'});
        });
        await runCase('storage.rules-denied', () async {
          await denied(
            anonymousStorage.ref('owners/protected/item').putData(smallBytes),
            {'unauthorized'},
          );
          requireAuth();
          await denied(storage.ref('owners/other-owner/item').getData(), {
            'unauthorized',
          });
        });
        await runCase('firestore.rules-signout', () async {
          requireAuth();
          await auth.signOut();
          await denied(firestore.doc('profiles/$identity').get(server), {
            'permission-denied',
          });
        });
        await runCase('database.set-read', () async {
          final ref = database.ref('public/roundtrip');
          await ref.set({'value': 7, 'text': 'hello'});
          expect((await databaseObserver.ref(ref.path).get()).value, {
            'value': 7,
            'text': 'hello',
          });
        });
        await runCase('database.listener', () async {
          final ref = database.ref('public/listener');
          await ref.set(1);
          final first = Completer<void>();
          final next = Completer<void>();
          final sub = ref.onValue.listen((event) {
            if (event.snapshot.value == 1 && !first.isCompleted)
              first.complete();
            if (event.snapshot.value == 2 && !next.isCompleted) next.complete();
          });
          cleanup.add(sub.cancel);
          try {
            await first.future;
            await databaseObserver.ref(ref.path).set(2);
            await next.future;
          } finally {
            await sub.cancel();
          }
        });
        await runCase('database.transaction', () async {
          final ref = database.ref('public/transaction');
          await ref.set(1);
          final result = await ref.runTransaction(
            (value) => rtdb.Transaction.success((value as num? ?? 0) + 1),
          );
          expect(result.committed, isTrue);
          expect((await databaseObserver.ref(ref.path).get()).value, 2);
        });
        await runCase('database.on-disconnect', () async {
          final ref = database.ref('public/disconnect');
          await database
              .ref('.info/connected')
              .onValue
              .firstWhere((event) => event.snapshot.value == true);
          await ref.set('connected');
          final ready = Completer<void>();
          final observed = Completer<Object?>();
          final sub = databaseObserver.ref(ref.path).onValue.listen((event) {
            final value = event.snapshot.value;
            if (value == 'connected' && !ready.isCompleted) ready.complete();
            if (ready.isCompleted &&
                value != 'connected' &&
                !observed.isCompleted)
              observed.complete(value);
          });
          cleanup.add(sub.cancel);
          try {
            await ready.future;
            await ref.onDisconnect().set('gone');
            await database.goOffline();
            expect(await observed.future, 'gone');
            expect((await databaseObserver.ref(ref.path).get()).value, 'gone');
          } finally {
            await database.goOnline();
            await sub.cancel();
          }
        });
        await runCase('flutter.timestamp-roundtrip', () async {
          final ref = firestore.doc('public/timestamp');
          final value = Timestamp(-1, 123456000);
          await ref.set({'value': value});
          final result = (await ref.get(server)).data()!['value'] as Timestamp;
          expect(result.seconds, value.seconds);
          expect(result.nanoseconds, value.nanoseconds);
        });
        await runCase('flutter.fieldvalue-roundtrip', () async {
          final ref = firestore.doc('public/fieldvalue');
          await ref.set({
            'remove': true,
            'count': 5,
            'items': ['a', 'b'],
          });
          await ref.update({
            'remove': FieldValue.delete(),
            'count': FieldValue.increment(-2),
            'items': FieldValue.arrayRemove(['a']),
            'time': FieldValue.serverTimestamp(),
          });
          final result = (await ref.get(server)).data()!;
          expect(result.containsKey('remove'), isFalse);
          expect(result['count'], 3);
          expect(result['items'], ['b']);
          expect(result['time'], isA<Timestamp>());
        });
        await runCase('flutter.firestore-stream-error', () async {
          final error = Completer<Object>();
          final sub = observer
              .doc('profiles/protected')
              .snapshots()
              .listen(
                (_) {},
                onError: (Object value) {
                  if (!error.isCompleted) error.complete(value);
                },
              );
          cleanup.add(sub.cancel);
          try {
            final delivered = await error.future;
            expect(delivered, isA<FirebaseException>());
            expect((delivered as FirebaseException).code, 'permission-denied');
          } finally {
            await sub.cancel();
          }
        });
        await runCase('flutter.database-stream-error', () async {
          final error = Completer<Object>();
          final sub = databaseObserver
              .ref('protected')
              .onValue
              .listen(
                (_) {},
                onError: (Object value) {
                  if (!error.isCompleted) error.complete(value);
                },
              );
          cleanup.add(sub.cancel);
          try {
            final delivered = await error.future;
            expect(delivered, isA<FirebaseException>());
            expect((delivered as FirebaseException).code, 'permission-denied');
          } finally {
            await sub.cancel();
          }
        });
      } finally {
        for (final cancel in cleanup) {
          await cancel().timeout(const Duration(seconds: 2));
        }
        await database.goOffline();
        await databaseObserver.goOffline();
        await firestore.terminate();
        await observer.terminate();
        await observerApp.delete();
        await app.delete();
      }
      expect(report.records.length, caseIds.length);
      expect(
        report.allPassed,
        isTrue,
        reason: 'Required failed or blocked cases remain.',
      );
    },
    timeout: const Timeout(Duration(minutes: 15)),
  );
}
