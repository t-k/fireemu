package dev.fireemu.smoke;

import com.google.api.core.ApiFuture;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.StatusCode;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.NoCredentials;
import com.google.cloud.firestore.CollectionReference;
import com.google.cloud.firestore.DocumentChange;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.FirestoreException;
import com.google.cloud.firestore.ListenerRegistration;
import com.google.cloud.firestore.Query;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.cloud.firestore.QuerySnapshot;
import com.google.cloud.firestore.SetOptions;
import com.google.cloud.firestore.WriteBatch;
import com.google.cloud.firestore.WriteResult;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.google.firebase.ErrorCode;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.AuthErrorCode;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.cloud.FirestoreClient;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Drives a running fireemu with the Java Admin SDK: Firestore through google-cloud-firestore,
 * Auth through firebase-admin, Storage through google-cloud-storage. Run it under
 * {@code fireemu exec --project demo-app}; {@link EmulatorGuard} refuses any other environment
 * before a single SDK class is used.
 */
public final class JavaAdminSmoke {

  private static final long TIMEOUT_SECONDS = 30;

  /**
   * Steps that fail because fireemu and the Java SDK disagree, with the text the failure must
   * contain. Each is a finding to be decided on the fireemu side; this suite fixes nothing. A
   * listed step that fails differently fails the run, and so does one that passes, so an entry
   * is removed as soon as the mismatch is gone. The steps after each one cover the rest of the
   * flow on a path that avoids the mismatch.
   */
  static final Map<String, String> KNOWN_MISMATCHES =
      Map.of(
          // firebase-admin's EmulatorCryptoSigner mints alg RS256 with an empty signature;
          // fireemu's unsigned exception (auth.allowUnsignedCustomTokens) accepts alg none only.
          "auth custom token exchange",
          "signInWithCustomToken: HTTP 400 {\"error\":{\"code\":400,\"errors\":[{\"domain\":"
              + "\"global\",\"message\":\"INVALID_CUSTOM_TOKEN\"",
          // google-api-client gzips request bodies by default (Content-Encoding: gzip);
          // fireemu reads the compressed bytes as the multipart body.
          "storage upload with the SDK defaults",
          "Payload size invalid. Expected 2-3 payloads. Actual size: 0",
          // NetHttpTransport cannot send PATCH, so google-api-client sends POST with
          // X-HTTP-Method-Override: PATCH; fireemu's JSON API object route answers 501.
          "storage metadata update",
          "501 Not Implemented\nPOST http://");

  private JavaAdminSmoke() {}

  /** Exit status: 0 when every step passed, 1 when a step failed, 2 when the guard refused. */
  public static void main(String[] args) {
    int status;
    try {
      status = run(System.getenv()) == 0 ? 0 : 1;
    } catch (EmulatorGuard.UnsafeEnvironmentException e) {
      System.err.println(e.getMessage());
      status = 2;
    } catch (Exception e) {
      e.printStackTrace();
      status = 1;
    }
    // gRPC and the Admin SDK keep non-daemon threads alive; leave explicitly.
    System.exit(status);
  }

  /** Returns the number of failed steps. */
  static int run(Map<String, String> env) throws Exception {
    Map<String, String> hosts = EmulatorGuard.check(env);
    String project = env.get("GOOGLE_CLOUD_PROJECT");
    if (project == null || project.isEmpty()) {
      throw new IllegalStateException("GOOGLE_CLOUD_PROJECT is not set; run under fireemu exec");
    }
    String run = UUID.randomUUID().toString().substring(0, 8);

    // Not a credential: firebase-admin requires one, and while FIREBASE_AUTH_EMULATOR_HOST is
    // set it substitutes EmulatorCredentials for Auth and Firestore anyway
    // (ImplFirebaseTrampolines.getCredentials).
    FirebaseOptions options =
        FirebaseOptions.builder()
            .setProjectId(project)
            .setCredentials(GoogleCredentials.create(new AccessToken("owner", null)))
            .build();
    FirebaseApp app = FirebaseApp.initializeApp(options, "java-admin-smoke-" + run);
    Storage storage =
        StorageOptions.newBuilder()
            .setHost("http://" + hosts.get("FIREBASE_STORAGE_EMULATOR_HOST"))
            .setProjectId(project)
            .setCredentials(NoCredentials.getInstance())
            .build()
            .getService();

    List<String> failures = new ArrayList<>();
    try {
      Firestore db = FirestoreClient.getFirestore(app);
      FirebaseAuth auth = FirebaseAuth.getInstance(app);
      String prefix = "java-smoke-" + run;
      step(failures, "firestore crud", () -> firestoreCrud(db, prefix));
      step(failures, "firestore where+orderBy+limit", () -> firestoreQuery(db, prefix));
      step(failures, "firestore transaction", () -> firestoreTransaction(db, prefix));
      step(failures, "firestore batch", () -> firestoreBatch(db, prefix));
      step(failures, "firestore snapshot listener", () -> firestoreListener(db, prefix));
      String authHost = hosts.get("FIREBASE_AUTH_EMULATOR_HOST");
      AuthFixture user = new AuthFixture("java-smoke-" + run + "@example.com");
      step(failures, "auth create/get/claims", () -> authCreateGetClaims(auth, user));
      step(failures, "auth custom token exchange", () -> authCustomToken(auth, authHost, user));
      step(failures, "auth verify ID token", () -> authVerifyIdToken(auth, authHost, user));
      step(failures, "auth delete", () -> authDelete(auth, user));
      step(
          failures,
          "storage upload with the SDK defaults",
          () -> storageDefaultUpload(storage, project, run));
      step(
          failures,
          "storage upload/download/metadata/delete",
          () -> storageLifecycle(storage, project, run));
      step(
          failures,
          "storage metadata update",
          () -> storageMetadataUpdate(storage, project, run));
    } finally {
      app.delete();
      storage.close();
    }
    for (String name : KNOWN_MISMATCHES.keySet()) {
      if (!STEPS_RUN.contains(name)) {
        failures.add(name);
        System.out.println("FAIL  " + name + ": a known mismatch names no step of this suite");
      }
    }
    System.out.println(
        failures.isEmpty()
            ? "java admin smoke: all steps passed, "
                + KNOWN_MISMATCHES.size()
                + " of them as known mismatches"
            : "java admin smoke: " + failures.size() + " step(s) failed: " + failures);
    return failures.size();
  }

  @FunctionalInterface
  private interface Step {
    void run() throws Exception;
  }

  private static final java.util.Set<String> STEPS_RUN = new java.util.HashSet<>();

  private static void step(List<String> failures, String name, Step body) {
    STEPS_RUN.add(name);
    String expected = KNOWN_MISMATCHES.get(name);
    Throwable thrown = null;
    try {
      body.run();
    } catch (Throwable t) {
      thrown = t;
    }
    if (expected == null && thrown == null) {
      System.out.println("ok    " + name);
    } else if (expected == null) {
      failures.add(name);
      System.out.println("FAIL  " + name + ": " + thrown);
      thrown.printStackTrace(System.out);
    } else if (thrown == null) {
      failures.add(name);
      System.out.println(
          "FAIL  " + name + ": passed, but it is a known mismatch; remove it from KNOWN_MISMATCHES");
    } else if (String.valueOf(thrown.getMessage()).contains(expected)) {
      System.out.println("known " + name + ": " + thrown.getMessage());
    } else {
      failures.add(name);
      System.out.println("FAIL  " + name + ": a known mismatch failed differently: " + thrown);
      thrown.printStackTrace(System.out);
    }
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }

  private static <T> T await(ApiFuture<T> future) throws Exception {
    return future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
  }

  // Firestore

  private static void firestoreCrud(Firestore db, String prefix) throws Exception {
    DocumentReference doc = db.collection(prefix + "-crud").document("doc");
    await(doc.create(Map.of("name", "alpha", "n", 1L)));

    ExecutionException duplicate = null;
    try {
      await(doc.create(Map.of("name", "again")));
    } catch (ExecutionException e) {
      duplicate = e;
    }
    require(
        duplicate != null
            && duplicate.getCause() instanceof ApiException
            && ((ApiException) duplicate.getCause()).getStatusCode().getCode()
                == StatusCode.Code.ALREADY_EXISTS,
        "create on an existing document must fail with ALREADY_EXISTS, got " + duplicate);

    DocumentSnapshot read = await(doc.get());
    require(read.exists(), "created document must exist");
    require("alpha".equals(read.getString("name")), "name after create: " + read.getData());
    require(Long.valueOf(1L).equals(read.getLong("n")), "n after create: " + read.getData());

    await(doc.update("n", 2L));
    await(doc.set(Map.of("extra", true), SetOptions.merge()));
    read = await(doc.get());
    require(
        Map.of("name", "alpha", "n", 2L, "extra", true).equals(read.getData()),
        "after update and merge: " + read.getData());

    await(doc.delete());
    require(!await(doc.get()).exists(), "deleted document must not exist");
  }

  private static void firestoreQuery(Firestore db, String prefix) throws Exception {
    CollectionReference cities = db.collection(prefix + "-cities");
    Map<String, Long> population = Map.of("a", 50L, "b", 150L, "c", 300L, "d", 1000L);
    for (Map.Entry<String, Long> e : population.entrySet()) {
      await(cities.document(e.getKey()).set(Map.of("population", e.getValue())));
    }
    // An inequality and an order on the same field: production serves it from the automatic
    // single-field index, so the strict profile needs no composite index.
    QuerySnapshot snapshot =
        await(
            cities
                .whereGreaterThan("population", 100L)
                .orderBy("population", Query.Direction.DESCENDING)
                .limit(2)
                .get());
    List<String> ids = new ArrayList<>();
    for (QueryDocumentSnapshot d : snapshot.getDocuments()) {
      ids.add(d.getId());
    }
    require(List.of("d", "c").equals(ids), "query result order: " + ids);
  }

  private static void firestoreTransaction(Firestore db, String prefix) throws Exception {
    DocumentReference counter = db.collection(prefix + "-txn").document("counter");
    DocumentReference audit = db.collection(prefix + "-txn").document("audit");
    await(counter.set(Map.of("count", 41L)));
    Long result =
        await(
            db.runTransaction(
                tx -> {
                  DocumentSnapshot snap = tx.get(counter).get();
                  DocumentSnapshot missing = tx.get(audit).get();
                  if (missing.exists()) {
                    throw new IllegalStateException("audit must not exist yet");
                  }
                  long next = snap.getLong("count") + 1;
                  tx.update(counter, "count", next);
                  tx.create(audit, Map.of("from", snap.getLong("count")));
                  return next;
                }));
    require(Long.valueOf(42L).equals(result), "transaction result: " + result);
    require(
        Long.valueOf(42L).equals(await(counter.get()).getLong("count")),
        "count after transaction");
    require(
        Long.valueOf(41L).equals(await(audit.get()).getLong("from")),
        "audit after transaction");
  }

  private static void firestoreBatch(Firestore db, String prefix) throws Exception {
    CollectionReference col = db.collection(prefix + "-batch");
    DocumentReference kept = col.document("kept");
    DocumentReference gone = col.document("gone");
    await(kept.set(Map.of("n", 0L)));
    await(gone.set(Map.of("n", 0L)));

    WriteBatch batch = db.batch();
    batch.set(col.document("one"), Map.of("n", 1L));
    batch.set(col.document("two"), Map.of("n", 2L));
    batch.update(kept, "n", 3L);
    batch.delete(gone);
    List<WriteResult> results = await(batch.commit());
    require(results.size() == 4, "batch write results: " + results.size());

    require(Long.valueOf(1L).equals(await(col.document("one").get()).getLong("n")), "one");
    require(Long.valueOf(2L).equals(await(col.document("two").get()).getLong("n")), "two");
    require(Long.valueOf(3L).equals(await(kept.get()).getLong("n")), "kept");
    require(!await(gone.get()).exists(), "gone must be deleted");
  }

  private static void firestoreListener(Firestore db, String prefix) throws Exception {
    CollectionReference col = db.collection(prefix + "-listen");
    BlockingQueue<Object> events = new LinkedBlockingQueue<>();
    ListenerRegistration registration =
        col.addSnapshotListener(
            (snapshot, error) -> events.add(error != null ? error : snapshot));
    try {
      QuerySnapshot initial = nextSnapshot(events);
      require(
          initial.isEmpty() && initial.getDocumentChanges().isEmpty(),
          "initial snapshot of an empty collection: " + initial.size());

      await(col.document("first").set(Map.of("v", 1L)));
      QuerySnapshot changed = nextSnapshot(events);
      List<DocumentChange> changes = changed.getDocumentChanges();
      require(changes.size() == 1, "changes in the second snapshot: " + changes.size());
      DocumentChange change = changes.get(0);
      require(change.getType() == DocumentChange.Type.ADDED, "change type: " + change.getType());
      require("first".equals(change.getDocument().getId()), "changed document");
      require(
          Long.valueOf(1L).equals(change.getDocument().getLong("v")), "changed document data");
    } finally {
      registration.remove();
    }
  }

  private static QuerySnapshot nextSnapshot(BlockingQueue<Object> events) throws Exception {
    Object event = events.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    if (event == null) {
      throw new AssertionError("no snapshot within " + TIMEOUT_SECONDS + "s");
    }
    if (event instanceof FirestoreException) {
      throw (FirestoreException) event;
    }
    return (QuerySnapshot) event;
  }

  // Auth

  /** The user the Auth steps share, created by the first one. */
  private static final class AuthFixture {
    final String email;
    final String password = "correct horse battery staple";
    String uid;

    AuthFixture(String email) {
      this.email = email;
    }

    String uid() {
      require(uid != null, "no user: auth create/get/claims did not create one");
      return uid;
    }
  }

  private static void authCreateGetClaims(FirebaseAuth auth, AuthFixture user) throws Exception {
    UserRecord created =
        auth.createUser(
            new UserRecord.CreateRequest()
                .setEmail(user.email)
                .setPassword(user.password)
                .setDisplayName("Java Smoke"));
    user.uid = created.getUid();
    require(user.email.equals(created.getEmail()), "created email: " + created.getEmail());

    UserRecord fetched = auth.getUser(user.uid);
    require(user.email.equals(fetched.getEmail()), "getUser email");
    require("Java Smoke".equals(fetched.getDisplayName()), "getUser displayName");
    require(user.uid.equals(auth.getUserByEmail(user.email).getUid()), "getUserByEmail uid");

    auth.setCustomUserClaims(user.uid, Map.of("role", "admin"));
    Map<String, Object> claims = auth.getUser(user.uid).getCustomClaims();
    require(Map.of("role", "admin").equals(claims), "claims after setCustomUserClaims: " + claims);
  }

  private static void authCustomToken(FirebaseAuth auth, String authHost, AuthFixture user)
      throws Exception {
    String uid = user.uid();
    String customToken = auth.createCustomToken(uid, Map.of("tier", "gold"));
    String idToken =
        signIn(authHost, "accounts:signInWithCustomToken", Map.of("token", customToken));
    FirebaseToken decoded = auth.verifyIdToken(idToken);
    require(uid.equals(decoded.getUid()), "verified uid: " + decoded.getUid());
    require("admin".equals(decoded.getClaims().get("role")), "role claim: " + decoded.getClaims());
    require("gold".equals(decoded.getClaims().get("tier")), "tier claim: " + decoded.getClaims());
  }

  private static void authVerifyIdToken(FirebaseAuth auth, String authHost, AuthFixture user)
      throws Exception {
    String uid = user.uid();
    String idToken =
        signIn(
            authHost,
            "accounts:signInWithPassword",
            Map.of("email", user.email, "password", user.password));
    FirebaseToken decoded = auth.verifyIdToken(idToken);
    require(uid.equals(decoded.getUid()), "verified uid: " + decoded.getUid());
    require(user.email.equals(decoded.getEmail()), "verified email: " + decoded.getEmail());
    require("admin".equals(decoded.getClaims().get("role")), "role claim: " + decoded.getClaims());
    require(uid.equals(auth.verifyIdToken(idToken, true).getUid()), "checkRevoked verify");
  }

  private static void authDelete(FirebaseAuth auth, AuthFixture user) throws Exception {
    String uid = user.uid();
    auth.deleteUser(uid);
    FirebaseAuthException missing = null;
    try {
      auth.getUser(uid);
    } catch (FirebaseAuthException e) {
      missing = e;
    }
    require(
        missing != null
            && missing.getAuthErrorCode() == AuthErrorCode.USER_NOT_FOUND
            && missing.getErrorCode() == ErrorCode.NOT_FOUND,
        "getUser after deleteUser must fail with USER_NOT_FOUND, got " + missing);
  }

  /**
   * A client SDK's sign-in call; the Admin SDK has no API for it. The API key is a
   * placeholder: the emulator endpoint does not check it.
   */
  private static String signIn(String authHost, String method, Map<String, String> fields)
      throws Exception {
    JsonObject body = new JsonObject();
    fields.forEach(body::addProperty);
    body.addProperty("returnSecureToken", true);
    HttpClient client =
        HttpClient.newBuilder()
            .proxy(HttpClient.Builder.NO_PROXY)
            .connectTimeout(Duration.ofSeconds(TIMEOUT_SECONDS))
            .build();
    HttpRequest request =
        HttpRequest.newBuilder(
                URI.create(
                    "http://"
                        + authHost
                        + "/identitytoolkit.googleapis.com/v1/"
                        + method
                        + "?key=fake-api-key"))
            .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    String name = method.substring(method.indexOf(':') + 1);
    require(
        response.statusCode() == 200,
        name + ": HTTP " + response.statusCode() + " " + response.body());
    JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
    require(json.has("idToken"), name + " response: " + response.body());
    return json.get("idToken").getAsString();
  }

  // Storage

  /** The default bucket of a project created with Firebase, as tools/sdk-smoke uses it. */
  private static String bucket(String project) {
    return project + ".appspot.com";
  }

  /** {@code storage.create} with nothing but the object: the call a Java user writes first. */
  private static void storageDefaultUpload(Storage storage, String project, String run)
      throws Exception {
    BlobId id = BlobId.of(bucket(project), "java-smoke/" + run + "/default.txt");
    byte[] content = "uploaded with the SDK defaults".getBytes(StandardCharsets.UTF_8);
    Blob uploaded =
        storage.create(BlobInfo.newBuilder(id).setContentType("text/plain").build(), content);
    require(uploaded.getSize() == content.length, "uploaded size: " + uploaded.getSize());
    require(
        java.util.Arrays.equals(content, storage.readAllBytes(id)), "downloaded bytes differ");
    require(storage.delete(id), "delete must report the object existed");
  }

  /** The base64 MD5 of {@code content}, as the JSON API reports {@code md5Hash}. */
  private static String md5Base64(byte[] content) throws java.security.NoSuchAlgorithmException {
    return java.util.Base64.getEncoder()
        .encodeToString(java.security.MessageDigest.getInstance("MD5").digest(content));
  }

  /** The base64 of the big-endian CRC32C of {@code content}, as the JSON API reports it. */
  private static String crc32cBase64(byte[] content) {
    java.util.zip.CRC32C crc = new java.util.zip.CRC32C();
    crc.update(content, 0, content.length);
    int value = (int) crc.getValue();
    return java.util.Base64.getEncoder()
        .encodeToString(
            new byte[] {
              (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
            });
  }

  /**
   * The object lifecycle with gzip request bodies turned off ({@code disableGzipContent}), so
   * the rest of the flow is covered while the default upload is a known mismatch.
   */
  private static void storageLifecycle(Storage storage, String project, String run)
      throws Exception {
    BlobId id = BlobId.of(bucket(project), "java-smoke/" + run + "/hello.txt");
    byte[] content = ("hello from the Java Admin SDK " + run).getBytes(StandardCharsets.UTF_8);

    Blob uploaded =
        storage.create(
            BlobInfo.newBuilder(id)
                .setContentType("text/plain")
                .setMetadata(Map.of("origin", "java-smoke"))
                .build(),
            content,
            Storage.BlobTargetOption.disableGzipContent());
    require(uploaded.getSize() == content.length, "uploaded size: " + uploaded.getSize());

    byte[] downloaded = storage.readAllBytes(id);
    require(
        java.util.Arrays.equals(content, downloaded),
        "downloaded bytes: " + new String(downloaded, StandardCharsets.UTF_8));

    Blob meta = storage.get(id);
    require(meta != null, "metadata of the uploaded object");
    require("text/plain".equals(meta.getContentType()), "contentType: " + meta.getContentType());
    require(meta.getSize() == content.length, "size: " + meta.getSize());
    require(
        Map.of("origin", "java-smoke").equals(meta.getMetadata()),
        "custom metadata: " + meta.getMetadata());
    require(md5Base64(content).equals(meta.getMd5()), "md5: " + meta.getMd5());
    require(crc32cBase64(content).equals(meta.getCrc32c()), "crc32c: " + meta.getCrc32c());

    require(storage.delete(id), "delete must report the object existed");
    require(storage.get(id) == null, "deleted object must be gone");
    require(!storage.delete(id), "a second delete must report the object was gone");
  }

  /**
   * {@code storage.update}: a JSON API PATCH, which the default transport ({@code
   * NetHttpTransport}) cannot send, so google-api-client sends it as a POST carrying {@code
   * X-HTTP-Method-Override: PATCH}.
   */
  private static void storageMetadataUpdate(Storage storage, String project, String run)
      throws Exception {
    BlobId id = BlobId.of(bucket(project), "java-smoke/" + run + "/update.txt");
    storage.create(
        BlobInfo.newBuilder(id)
            .setContentType("text/plain")
            .setMetadata(Map.of("origin", "java-smoke"))
            .build(),
        "metadata update".getBytes(StandardCharsets.UTF_8),
        Storage.BlobTargetOption.disableGzipContent());
    try {
      Blob updated =
          storage.update(
              BlobInfo.newBuilder(id)
                  .setContentType("text/markdown")
                  .setMetadata(Map.of("origin", "java-smoke", "step", "update"))
                  .build());
      require(
          "text/markdown".equals(updated.getContentType()),
          "contentType after update: " + updated.getContentType());
      Map<String, String> metadata = storage.get(id).getMetadata();
      require(
          Map.of("origin", "java-smoke", "step", "update").equals(metadata),
          "metadata after update: " + metadata);
    } finally {
      storage.delete(id);
    }
  }
}
