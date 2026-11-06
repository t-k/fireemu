package dev.fireemu.smoke

import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.Tasks
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.*
import com.google.firebase.storage.*
import com.google.firebase.database.*
import java.net.HttpURLConnection
import java.net.URI
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicLong

class SmokeCases(private val context: android.content.Context, private val emit: (String) -> Unit = ::println, private val selectedCase: String? = null) {
    private fun <T> Task<T>.await(): T = Tasks.await(this, 10, TimeUnit.SECONDS)
    private val results = linkedMapOf<String, String>()
    private fun runCase(id: String, requires: List<String> = emptyList(), body: () -> Unit) {
        if (selectedCase != null && selectedCase != id) {
            results[id] = "blocked"
            emit("CASE $id blocked diagnostic_filter 0")
            return
        }
        if (requires.any { results[it] != "passed" }) {
            results[id] = "blocked"
            emit("CASE $id blocked prerequisite 0")
            return
        }
        val start = System.nanoTime()
        val worker = Executors.newSingleThreadExecutor()
        val task = worker.submit { body() }
        try {
            task.get(30, TimeUnit.SECONDS)
            results[id] = "passed"
            emit("CASE $id passed none ${(System.nanoTime()-start)/1000000}")
        } catch (error: Throwable) {
            results[id] = "failed"
            var cause = error
            while (cause.cause != null) cause = cause.cause!!
            if (selectedCase != null) emit("PRIVATE_DETAIL $id ${cause.javaClass.name}: ${cause.message}")
            val classification = when (cause) {
                is FirebaseFirestoreException -> "firestore_${cause.code.name}"
                is StorageException -> "storage_${cause.errorCode}_${cause.httpResultCode}"
                is com.google.firebase.auth.FirebaseAuthException -> "auth_${cause.errorCode}"
                is TimeoutException -> "timeout"
                is AssertionError, is IllegalStateException -> "assertion_or_platform"
                else -> cause.javaClass.simpleName
            }
            emit("CASE $id failed $classification ${(System.nanoTime()-start)/1000000}")
        } finally { task.cancel(true); worker.shutdownNow() }
    }
    private fun expectDenied(body: () -> Unit) {
        try { body(); error("expected permission denial") }
        catch (error: ExecutionException) {
            val cause = error.cause
            check((cause is FirebaseFirestoreException && cause.code == FirebaseFirestoreException.Code.PERMISSION_DENIED) ||
                (cause is StorageException && cause.errorCode == StorageException.ERROR_NOT_AUTHORIZED))
        }
    }
    private fun snapshot(queue: BlockingQueue<DocumentSnapshot>, accept: (DocumentSnapshot) -> Boolean): DocumentSnapshot {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            val value = queue.poll(100, TimeUnit.MILLISECONDS) ?: continue
            if (accept(value)) return value
        }
        throw TimeoutException("snapshot")
    }
    private fun observe(ref: DatabaseReference, predicate: (DataSnapshot) -> Boolean): CompletableFuture<DataSnapshot> {
        val result = CompletableFuture<DataSnapshot>()
        val listener = object : ValueEventListener {
            override fun onDataChange(value: DataSnapshot) { if (predicate(value)) result.complete(value) }
            override fun onCancelled(error: DatabaseError) { result.completeExceptionally(error.toException()) }
        }
        ref.addValueEventListener(listener)
        result.whenComplete { _, _ -> ref.removeEventListener(listener) }
        return result
    }
    private fun <T> CompletableFuture<T>.value(): T = try { get(10, TimeUnit.SECONDS) } finally { cancel(true) }

    fun exercise(endpoints: Map<String, Pair<String, Int>>) {
        fun app(name: String) = FirebaseApp.initializeApp(context, FirebaseOptions.Builder()
            .setApplicationId("android-smoke-$name").setApiKey("fake-api-key-$name").setProjectId("demo-app")
            .setStorageBucket("demo-app.appspot.com").setDatabaseUrl("https://demo-app-default-rtdb.firebaseio.com").build(),name)
        val app = app("primary")
        val peerApp = app("peer")
        val auth = FirebaseAuth.getInstance(app)
        val firestore = FirebaseFirestore.getInstance(app)
        val peer = FirebaseFirestore.getInstance(peerApp)
        val storage = FirebaseStorage.getInstance(app)
        val database = FirebaseDatabase.getInstance(app)
        val peerDatabase = FirebaseDatabase.getInstance(peerApp)
        val email = "android-smoke@example.test"
        val password = "local-smoke-password"
        var identity = ""
        try {
            endpoints.getValue("FIREBASE_AUTH_EMULATOR_HOST").let { auth.useEmulator(it.first,it.second); FirebaseAuth.getInstance(peerApp).useEmulator(it.first,it.second) }
            endpoints.getValue("FIRESTORE_EMULATOR_HOST").let { firestore.useEmulator(it.first,it.second); peer.useEmulator(it.first,it.second) }
            endpoints.getValue("FIREBASE_STORAGE_EMULATOR_HOST").let { storage.useEmulator(it.first,it.second) }
            endpoints.getValue("FIREBASE_DATABASE_EMULATOR_HOST").let { database.useEmulator(it.first,it.second); peerDatabase.useEmulator(it.first,it.second) }
            storage.maxUploadRetryTimeMillis = 5000
            storage.maxDownloadRetryTimeMillis = 5000
            storage.maxOperationRetryTimeMillis = 5000
            runCase("auth.signup") { identity=auth.createUserWithEmailAndPassword(email,password).await().user!!.uid; check(identity.isNotEmpty()) }
            runCase("auth.signin",listOf("auth.signup")) { auth.signOut(); check(auth.signInWithEmailAndPassword(email,password).await().user!!.uid==identity) }
            runCase("auth.refresh",listOf("auth.signin")) { val token=auth.currentUser!!.getIdToken(true).await(); check(token.claims["user_id"]==identity || token.claims["sub"]==identity) }
            val doc=firestore.document("public/basic")
            runCase("firestore.write-read") { doc.set(mapOf("value" to 7L)).await(); check(doc.get(Source.SERVER).await().data==mapOf("value" to 7L)) }
            runCase("firestore.transforms") {
                val ref=firestore.document("public/transforms")
                ref.set(mapOf("count" to 1L,"tags" to listOf("a"))).await()
                ref.update(mapOf("count" to FieldValue.increment(2),"tags" to FieldValue.arrayUnion("a","b"),"time" to FieldValue.serverTimestamp())).await()
                val value=ref.get(Source.SERVER).await(); check(value.getLong("count")==3L && value.get("tags")==listOf("a","b") && value.getTimestamp("time")!=null)
            }
            runCase("firestore.query") {
                val collection=firestore.collection("public/query/items")
                for (n in 1..3) collection.document("item$n").set(mapOf("rank" to n)).await()
                val values=collection.whereGreaterThan("rank",1).orderBy("rank",com.google.firebase.firestore.Query.Direction.DESCENDING).limit(1).get(Source.SERVER).await()
                check(values.documents.map { it.id }==listOf("item3") && values.documents.single().getLong("rank")==3L)
            }
            runCase("firestore.listener") {
                val ref=firestore.document("public/listener"); ref.set(mapOf("value" to 1L)).await()
                val queue=LinkedBlockingQueue<DocumentSnapshot>()
                val listener=ref.addSnapshotListener(MetadataChanges.INCLUDE) { value,error -> if(error==null && value!=null) queue.offer(value) }
                try { snapshot(queue) { !it.metadata.isFromCache && it.getLong("value")==1L }; peer.document(ref.path).update("value",2L).await(); snapshot(queue) { !it.metadata.isFromCache && it.getLong("value")==2L } }
                finally { listener.remove() }
            }
            runCase("firestore.transaction") {
                val ref=firestore.document("public/transaction"); ref.set(mapOf("count" to 1L)).await()
                check(firestore.runTransaction { tx -> val next=tx.get(ref).getLong("count")!!+1; tx.update(ref,"count",next); next }.await()==2L)
                check(peer.document(ref.path).get(Source.SERVER).await().getLong("count")==2L)
            }
            runCase("firestore.offline-resume") {
                val ref=firestore.document("public/offline"); val queue=LinkedBlockingQueue<DocumentSnapshot>()
                val listener=ref.addSnapshotListener(MetadataChanges.INCLUDE) { value,error -> if(error==null && value!=null) queue.offer(value) }
                try {
                    firestore.disableNetwork().await(); val pending=ref.set(mapOf("value" to 9L))
                    snapshot(queue) { it.metadata.hasPendingWrites() && it.getLong("value")==9L }
                    firestore.enableNetwork().await(); pending.await(); check(peer.document(ref.path).get(Source.SERVER).await().getLong("value")==9L)
                } finally { listener.remove(); firestore.enableNetwork().await() }
            }
            runCase("firestore.batch-delete") {
                val deleted=firestore.document("public/deleted"); val kept=firestore.document("public/kept")
                deleted.set(mapOf("value" to 1L)).await(); firestore.batch().set(kept,mapOf("value" to 2L)).delete(deleted).commit().await()
                check(!deleted.get(Source.SERVER).await().exists() && kept.get(Source.SERVER).await().getLong("value")==2L)
            }
            runCase("firestore.rules-anonymous-denied") { auth.signOut(); expectDenied { firestore.document("profiles/anonymous").get(Source.SERVER).await() }; check(firestore.collection("public").limit(1).get(Source.SERVER).await().size()>0) }
            runCase("firestore.rules-owner",listOf("auth.signup")) {
                auth.signInWithEmailAndPassword(email,password).await()
                firestore.document("profiles/$identity").set(mapOf("value" to 1L)).await()
                expectDenied { firestore.document("profiles/another").set(mapOf("value" to 2L)).await() }
                firestore.document("notes/owned").set(mapOf("owner" to identity,"value" to 3L)).await()
                val notes=firestore.collection("notes").whereEqualTo("owner",identity).get(Source.SERVER).await()
                check(notes.documents.map { it.id }==listOf("owned") && notes.documents.single().getLong("value")==3L)
            }
            runCase("firestore.rules-signout",listOf("firestore.rules-owner")) { auth.signOut(); expectDenied { firestore.document("profiles/$identity").get(Source.SERVER).await() } }
            val objectRef=storage.reference.child("public/日本語.txt")
            val bytes="Android byte round trip".toByteArray()
            runCase("storage.upload-download") { objectRef.putBytes(bytes).await(); check(objectRef.getBytes(1024).await().contentEquals(bytes)) }
            runCase("storage.metadata",listOf("storage.upload-download")) {
                val metadata=StorageMetadata.Builder().setContentType("text/plain").setCustomMetadata("stage","first").build()
                objectRef.updateMetadata(metadata).await(); val initial=objectRef.metadata.await()
                check(initial.sizeBytes==bytes.size.toLong() && initial.contentType=="text/plain" && initial.getCustomMetadata("stage")=="first")
                objectRef.updateMetadata(StorageMetadata.Builder().setCustomMetadata("stage","second").build()).await()
                check(objectRef.metadata.await().getCustomMetadata("stage")=="second")
            }
            runCase("storage.resumable") {
                val data=ByteArray(600000) { (it%251).toByte() }; val ref=storage.reference.child("public/large")
                val progress=AtomicLong(); val task=ref.putBytes(data)
                task.addOnProgressListener(Executor { it.run() }) { progress.set(it.bytesTransferred) }
                check(task.await().bytesTransferred==data.size.toLong()); check(progress.get()==data.size.toLong()); check(ref.getBytes(600001).await().contentEquals(data))
            }
            runCase("storage.download-url",listOf("storage.upload-download")) {
                val uri=URI(objectRef.downloadUrl.await().toString()); val endpoint=endpoints.getValue("FIREBASE_STORAGE_EMULATOR_HOST")
                check(uri.scheme=="http" && uri.host==endpoint.first && uri.port==endpoint.second && uri.userInfo==null)
                val connection=uri.toURL().openConnection() as HttpURLConnection
                connection.instanceFollowRedirects=false; connection.connectTimeout=5000; connection.readTimeout=5000
                try { check(connection.responseCode==200); check(connection.inputStream.use { it.readNBytes(1025) }.contentEquals(bytes)) } finally { connection.disconnect() }
            }
            runCase("storage.list-delete") {
                val ref=storage.reference.child("public/list/item"); ref.putBytes(bytes).await()
                check(storage.reference.child("public/list").listAll().await().items.map { it.name }==listOf("item"))
                ref.delete().await()
                try { ref.metadata.await(); error("deleted object still exists") } catch(error:ExecutionException) { check((error.cause as? StorageException)?.errorCode==StorageException.ERROR_OBJECT_NOT_FOUND) }
            }
            runCase("storage.rules-denied",listOf("auth.signup")) {
                auth.signOut(); expectDenied { storage.reference.child("protected/anonymous/item").putBytes(bytes).await() }
                auth.signInWithEmailAndPassword(email,password).await(); expectDenied { storage.reference.child("protected/another/item").getBytes(1024).await() }
            }
            runCase("database.set-read") { database.getReference("basic").setValue(7L).await(); check(peerDatabase.getReference("basic").get().await().getValue(Long::class.java)==7L) }
            runCase("database.listener") {
                val ref=database.getReference("listener"); ref.setValue(1L).await()
                observe(ref) { it.getValue(Long::class.java)==1L }.value()
                val updated=observe(ref) { it.getValue(Long::class.java)==2L }
                peerDatabase.getReference("listener").setValue(2L).await(); updated.value()
            }
            runCase("database.transaction") {
                val ref=database.getReference("transaction"); ref.setValue(1L).await(); val committed=CompletableFuture<Boolean>()
                ref.runTransaction(object : com.google.firebase.database.Transaction.Handler {
                    override fun doTransaction(value:MutableData):com.google.firebase.database.Transaction.Result { value.value=(value.getValue(Long::class.java)?:0L)+1; return com.google.firebase.database.Transaction.success(value) }
                    override fun onComplete(error:DatabaseError?,success:Boolean,value:DataSnapshot?) { if(error!=null) committed.completeExceptionally(error.toException()) else committed.complete(success) }
                })
                check(committed.value()); check(peerDatabase.getReference("transaction").get().await().getValue(Long::class.java)==2L)
            }
            runCase("database.on-disconnect") {
                observe(database.getReference(".info/connected")) { it.getValue(Boolean::class.java)==true }.value()
                val ref=database.getReference("disconnect"); ref.setValue("connected").await()
                val changed=observe(peerDatabase.getReference("disconnect")) { it.getValue(String::class.java)=="gone" }
                ref.onDisconnect().setValue("gone").await(); database.goOffline(); changed.value()
            }
        } finally {
            database.goOffline(); peerDatabase.goOffline()
            firestore.terminate().await(); peer.terminate().await()
            auth.signOut(); app.delete(); peerApp.delete()
        }
        check(CaseReport.successful(results)) { "required Android SDK cases failed or blocked" }
    }
}
