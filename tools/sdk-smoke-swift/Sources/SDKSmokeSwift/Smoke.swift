import Foundation
import FirebaseCore
import FirebaseAuth
import FirebaseFirestore
import FirebaseStorage
import FirebaseDatabase
import SmokeSupport

struct SmokeFailure: Error { let reason: String }
func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
    guard condition() else { throw SmokeFailure(reason: reason) }
}
func completion(_ operation: (@escaping (Error?) -> Void) -> Void) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        operation { error in
            if let error { continuation.resume(throwing: error) }
            else { continuation.resume() }
        }
    }
}
func eventually(_ condition: () async throws -> Bool) async throws {
    for _ in 0..<100 {
        if try await condition() { return }
        try await Task.sleep(nanoseconds: 100_000_000)
    }
    throw SmokeFailure(reason: "observation-deadline")
}
final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var values: Set<Int> = []
    func insert(_ value: Int) { lock.lock(); defer { lock.unlock() }; values.insert(value) }
    func contains(_ value: Int) -> Bool { lock.lock(); defer { lock.unlock() }; return values.contains(value) }
}
func denied(_ operation: () async throws -> Void, domain: String, codes: Set<Int>) async throws {
    do { try await operation() }
    catch {
        let error = error as NSError
        try require(error.domain == domain && codes.contains(error.code), "wrong-denial-class")
        return
    }
    throw SmokeFailure(reason: "expected-denial")
}

final class Smoke {
    let project: String
    let fsEndpoint: Endpoint
    let authEndpoint: Endpoint
    let storageEndpoint: Endpoint
    let databaseEndpoint: Endpoint
    let app: FirebaseApp
    let secondApp: FirebaseApp
    let suffix = UUID().uuidString.lowercased()
    init() throws {
        let env = ProcessInfo.processInfo.environment
        project = try validateProject(env["GCLOUD_PROJECT"] ?? env["GOOGLE_CLOUD_PROJECT"])
        fsEndpoint = try Endpoint(env["FIRESTORE_EMULATOR_HOST"])
        authEndpoint = try Endpoint(env["FIREBASE_AUTH_EMULATOR_HOST"])
        storageEndpoint = try Endpoint(env["FIREBASE_STORAGE_EMULATOR_HOST"])
        databaseEndpoint = try Endpoint(env["FIREBASE_DATABASE_EMULATOR_HOST"])
        let options = FirebaseOptions(googleAppID: "1:0:ios:0", gcmSenderID: "0")
        options.projectID = project
        options.apiKey = "fake-api-key"
        options.storageBucket = "\(project).appspot.com"
        options.databaseURL = "http://\(databaseEndpoint.host):\(databaseEndpoint.port)?ns=\(project)-default-rtdb"
        FirebaseConfiguration.shared.setLoggerLevel(.error)
        FirebaseApp.configure(name: "smoke", options: options)
        FirebaseApp.configure(name: "observer", options: options)
        app = FirebaseApp.app(name: "smoke")!
        secondApp = FirebaseApp.app(name: "observer")!
    }
    func auth(_ app: FirebaseApp) -> Auth {
        let auth = Auth.auth(app: app)
        auth.useEmulator(withHost: authEndpoint.host, port: authEndpoint.port)
        return auth
    }
    func firestore(_ app: FirebaseApp) -> Firestore {
        let db = Firestore.firestore(app: app)
        db.useEmulator(withHost: fsEndpoint.host, port: fsEndpoint.port)
        let settings = db.settings
        settings.cacheSettings = MemoryCacheSettings()
        db.settings = settings
        return db
    }
    func storage(_ app: FirebaseApp) -> Storage {
        let storage = Storage.storage(app: app)
        storage.useEmulator(withHost: storageEndpoint.host, port: storageEndpoint.port)
        storage.maxUploadRetryTime = 5
        storage.maxDownloadRetryTime = 5
        storage.maxOperationRetryTime = 5
        return storage
    }
    func database(_ app: FirebaseApp) -> Database {
        let db = Database.database(app: app)
        db.useEmulator(withHost: databaseEndpoint.host, port: databaseEndpoint.port)
        return db
    }
    func signup(_ auth: Auth) async throws -> User {
        // Generated demo-only identity; never print it or its tokens.
        let address = suffix + "@" + "example.invalid"
        return try await auth.createUser(withEmail: address, password: "local-password-123").user
    }
    func runAuth(_ name: String) async throws {
        let auth = auth(app)
        let user = try await signup(auth)
        defer { try? auth.signOut() }
        try require(!user.uid.isEmpty, "empty-identity")
        if name == "auth.signin" {
            let identity = user.uid
            let address = user.email!
            try auth.signOut()
            let signedIn = try await auth.signIn(withEmail: address, password: "local-password-123")
            try require(signedIn.user.uid == identity, "signin-identity")
        }
        if name == "auth.refresh" {
            let result = try await user.getIDTokenResult(forcingRefresh: true)
            try require(result.claims["user_id"] as? String == user.uid, "refresh-identity")
            try require(result.expirationDate > result.issuedAtDate, "refresh-expiry")
        }
    }
    func runFirestore(_ name: String) async throws {
        let db = firestore(app)
        let other = firestore(secondApp)
        let root = db.collection("smoke-" + suffix)
        let ref = root.document("first")
        if name.hasPrefix("firestore.rules-") {
            let auth = auth(app)
            defer { try? auth.signOut() }
            if name == "firestore.rules-anonymous-denied" {
                try await denied({ _ = try await db.document("profiles/missing").getDocument(source: .server) }, domain: FirestoreErrorDomain, codes: [7])
                _ = try await db.collection("public").getDocuments(source: .server)
            } else {
                let user = try await signup(auth)
                let profile = db.document("profiles/" + user.uid)
                try await profile.setData(["value": 1])
                let profileValue = try await profile.getDocument(source: .server).data()?["value"] as? Int
                try require(profileValue == 1, "profile-value")
                if name == "firestore.rules-signout" {
                    try auth.signOut()
                    try await denied({ _ = try await profile.getDocument(source: .server) }, domain: FirestoreErrorDomain, codes: [7])
                } else {
                    try await denied({ try await db.document("profiles/other").setData(["value": 1]) }, domain: FirestoreErrorDomain, codes: [7])
                    try await db.collection("notes").document(suffix).setData(["owner": user.uid, "value": 1])
                    let snapshot = try await db.collection("notes").whereField("owner", isEqualTo: user.uid).getDocuments(source: .server)
                    try require(snapshot.documents.map(\.documentID) == [suffix], "owner-query")
                }
            }
            return
        }
        try await ref.setData(["value": 1, "tags": ["a"]])
        switch name {
        case "firestore.write-read":
            let data = try await ref.getDocument(source: .server).data()
            try require(data?["value"] as? Int == 1 && data?["tags"] as? [String] == ["a"], "write-read-value")
        case "firestore.transforms":
            try await ref.updateData(["value": FieldValue.increment(Int64(2)), "tags": FieldValue.arrayUnion(["b"]), "time": FieldValue.serverTimestamp()])
            let data = try await ref.getDocument(source: .server).data()
            try require(data?["value"] as? Int == 3 && data?["tags"] as? [String] == ["a", "b"] && data?["time"] is Timestamp, "transform-value")
        case "firestore.query":
            try await root.document("second").setData(["value": 2])
            try await root.document("third").setData(["value": 3])
            let result = try await root.whereField("value", isGreaterThan: 1).order(by: "value", descending: true).limit(to: 2).getDocuments(source: .server)
            try require(result.documents.map(\.documentID) == ["third", "second"], "query-ids")
            try require(result.documents.compactMap { $0.data()["value"] as? Int } == [3, 2], "query-values")
        case "firestore.listener":
            let events = Events()
            let listener = ref.addSnapshotListener(includeMetadataChanges: true) { snapshot, _ in
                if let snapshot, !snapshot.metadata.isFromCache, !snapshot.metadata.hasPendingWrites,
                   let value = snapshot.data()?["value"] as? Int { events.insert(value) }
            }
            defer { listener.remove() }
            try await eventually { events.contains(1) }
            try await other.document(ref.path).updateData(["value": 2])
            try await eventually { events.contains(2) }
        case "firestore.transaction":
            _ = try await db.runTransaction { transaction, errorPointer in
                do {
                    let value = try transaction.getDocument(ref).data()?["value"] as? Int ?? -100
                    transaction.updateData(["value": value + 1], forDocument: ref)
                } catch { errorPointer?.pointee = error as NSError }
                return nil
            }
            let value = try await other.document(ref.path).getDocument(source: .server).data()?["value"] as? Int
            try require(value == 2, "transaction-value")
        case "firestore.offline-resume":
            let events = Events()
            let listener = ref.addSnapshotListener(includeMetadataChanges: true) { snapshot, _ in
                if let snapshot, snapshot.metadata.hasPendingWrites, snapshot.data()?["value"] as? Int == 2 { events.insert(2) }
            }
            defer { listener.remove() }
            try await db.disableNetwork()
            let write = Task { try await ref.updateData(["value": 2]) }
            try await eventually { events.contains(2) }
            try await db.enableNetwork()
            try await write.value
            let value = try await other.document(ref.path).getDocument(source: .server).data()?["value"] as? Int
            try require(value == 2, "offline-resume-value")
        case "firestore.batch-delete":
            let batch = db.batch()
            batch.deleteDocument(ref)
            batch.setData(["value": 2], forDocument: root.document("second"))
            try await batch.commit()
            let deleted = try await ref.getDocument(source: .server)
            let created = try await root.document("second").getDocument(source: .server)
            try require(!deleted.exists && created.data()?["value"] as? Int == 2, "batch-value")
        default: throw SmokeFailure(reason: "unknown-case")
        }
        try await db.terminate()
        try await other.terminate()
    }
    func runStorage(_ name: String) async throws {
        let storage = storage(app)
        let root = storage.reference().child("public/" + suffix)
        let ref = root.child("日本語.txt")
        let bytes = Data("hello swift".utf8)
        if name == "storage.rules-denied" {
            try await denied({ _ = try await storage.reference().child("users/missing/file").putDataAsync(bytes) }, domain: StorageErrorDomain, codes: [StorageErrorCode.unauthorized.rawValue, StorageErrorCode.unauthenticated.rawValue])
            let auth = auth(app)
            _ = try await signup(auth)
            defer { try? auth.signOut() }
            try await denied({ _ = try await storage.reference().child("users/other/file").data(maxSize: 1024) }, domain: StorageErrorDomain, codes: [StorageErrorCode.unauthorized.rawValue, StorageErrorCode.unauthenticated.rawValue])
            return
        }
        let metadata = StorageMetadata()
        metadata.contentType = "text/plain"
        metadata.customMetadata = ["mood": "good"]
        _ = try await ref.putDataAsync(bytes, metadata: metadata)
        switch name {
        case "storage.upload-download":
            let received = try await ref.data(maxSize: 1024)
            try require(received == bytes, "download-bytes")
        case "storage.metadata":
            let current = try await ref.getMetadata()
            try require(current.size == bytes.count && current.contentType == "text/plain" && current.customMetadata?["mood"] == "good", "initial-metadata")
            let update = StorageMetadata()
            update.customMetadata = ["mood": "great"]
            update.cacheControl = "private"
            _ = try await ref.updateMetadata(update)
            let changed = try await ref.getMetadata()
            try require(changed.customMetadata?["mood"] == "great" && changed.cacheControl == "private", "updated-metadata")
        case "storage.resumable":
            let payload = Data(repeating: 7, count: 600_000)
            let progress = Events()
            let big = root.child("big.bin")
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let task = big.putData(payload) { metadata, error in
                    if let error { continuation.resume(throwing: error) }
                    else if metadata?.size == Int64(payload.count) { continuation.resume() }
                    else { continuation.resume(throwing: SmokeFailure(reason: "upload-size")) }
                }
                task.observe(.progress) { snapshot in
                    if snapshot.progress?.completedUnitCount == Int64(payload.count) { progress.insert(1) }
                }
            }
            try await eventually { progress.contains(1) }
            let received = try await big.data(maxSize: 600_001)
            try require(received == payload, "resumable-bytes")
        case "storage.download-url":
            let url = try await ref.downloadURL()
            try validateDownloadURL(url, endpoint: storageEndpoint)
            // Redirects are refused so a local response cannot route the harness elsewhere.
            let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
            defer { session.invalidateAndCancel() }
            let (received, response) = try await session.data(from: url)
            try require((response as? HTTPURLResponse)?.statusCode == 200 && received == bytes, "download-url-bytes")
        case "storage.list-delete":
            let listing = try await root.listAll()
            try require(listing.items.map(\.name) == ["日本語.txt"], "list-object")
            try await ref.delete()
            try await denied({ _ = try await ref.getMetadata() }, domain: StorageErrorDomain, codes: [StorageErrorCode.objectNotFound.rawValue])
        default: throw SmokeFailure(reason: "unknown-case")
        }
    }
    func runDatabase(_ name: String) async throws {
        let db = database(app)
        let observer = database(secondApp)
        defer { db.goOffline(); observer.goOffline() }
        let ref = db.reference().child("smoke/" + suffix)
        let other = observer.reference().child("smoke/" + suffix)
        try await completion { callback in ref.setValue(1) { error, _ in callback(error) } }
        switch name {
        case "database.set-read":
            let snapshot = try await other.getData()
            try require(snapshot.value as? Int == 1, "database-value")
        case "database.listener":
            let events = Events()
            let handle = ref.observe(.value) { snapshot in if let value = snapshot.value as? Int { events.insert(value) } }
            defer { ref.removeObserver(withHandle: handle) }
            try await eventually { events.contains(1) }
            try await completion { callback in other.setValue(2) { error, _ in callback(error) } }
            try await eventually { events.contains(2) }
        case "database.transaction":
            let committed: Bool = try await withCheckedThrowingContinuation { continuation in
                ref.runTransactionBlock({ data in
                    data.value = (data.value as? Int ?? 0) + 1
                    return TransactionResult.success(withValue: data)
                }, andCompletionBlock: { error, committed, _ in
                    if let error { continuation.resume(throwing: error) }
                    else { continuation.resume(returning: committed) }
                })
            }
            let value = try await other.getData().value as? Int
            try require(committed && value == 2, "database-transaction")
        case "database.on-disconnect":
            let events = Events()
            let handle = other.observe(.value) { snapshot in if let value = snapshot.value as? Int { events.insert(value) } }
            defer { other.removeObserver(withHandle: handle) }
            try await eventually { events.contains(1) }
            try await completion { callback in ref.onDisconnectSetValue(2) { error, _ in callback(error) } }
            db.goOffline()
            try await eventually { events.contains(2) }
        default: throw SmokeFailure(reason: "unknown-case")
        }
    }
}
final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
@main struct Main {
    static func main() async {
        let name = CommandLine.arguments.dropFirst().first ?? "missing"
        let start = Date()
        var result: [String: Any] = ["case": name]
        do {
            let smoke = try Smoke()
            if name.hasPrefix("firestore.") { try await smoke.runFirestore(name) }
            else if name.hasPrefix("auth.") { try await smoke.runAuth(name) }
            else if name.hasPrefix("storage.") { try await smoke.runStorage(name) }
            else if name.hasPrefix("database.") { try await smoke.runDatabase(name) }
            else { throw SmokeFailure(reason: "unknown-case") }
            result["status"] = "passed"
        } catch {
            result["status"] = "failed"
            result["reason"] = (error as? SmokeFailure)?.reason ?? "sdk-error"
            result["errorDomain"] = (error as NSError).domain
            result["errorCode"] = (error as NSError).code
        }
        result["seconds"] = Date().timeIntervalSince(start)
        let data = try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
        print(String(data: data, encoding: .utf8)!)
        exit(result["status"] as? String == "passed" ? 0 : 1)
    }
}
