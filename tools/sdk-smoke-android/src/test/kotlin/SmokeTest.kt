package dev.fireemu.smoke

import android.os.Looper
import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.Tasks
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.database.FirebaseDatabase
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.Source
import com.google.firebase.storage.FirebaseStorage
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SmokeTest {
    private fun <T> Task<T>.await(): T = Tasks.await(this, 30, TimeUnit.SECONDS)

    @Test fun realSdkPrototype() {
        val endpoints = listOf("FIRESTORE_EMULATOR_HOST", "FIREBASE_AUTH_EMULATOR_HOST", "FIREBASE_STORAGE_EMULATOR_HOST", "FIREBASE_DATABASE_EMULATOR_HOST")
            .associateWith { EndpointGuard.validate(System.getenv(it)) }
        val executor = Executors.newSingleThreadExecutor()
        val run = executor.submit {
            var failures = 0
            for (product in listOf("firestore", "auth", "storage", "database")) {
                val app = FirebaseApp.initializeApp(RuntimeEnvironment.getApplication(), FirebaseOptions.Builder()
                    .setApplicationId("android-smoke").setApiKey("fake-api-key").setProjectId("demo-app")
                    .setStorageBucket("demo-app.appspot.com").setDatabaseUrl("https://demo-app-default-rtdb.firebaseio.com").build(), product)
                var cleanup: () -> Unit = {}
                try {
                    when (product) {
                        "firestore" -> {
                            val client = FirebaseFirestore.getInstance(app)
                            val endpoint = endpoints.getValue("FIRESTORE_EMULATOR_HOST")
                            client.useEmulator(endpoint.first, endpoint.second)
                            cleanup = { client.terminate().await() }
                            val doc = client.document("public/prototype")
                            doc.set(mapOf("value" to 7L)).await()
                            check(doc.get(Source.SERVER).await().getLong("value") == 7L)
                        }
                        "auth" -> {
                            val client = FirebaseAuth.getInstance(app)
                            val endpoint = endpoints.getValue("FIREBASE_AUTH_EMULATOR_HOST")
                            client.useEmulator(endpoint.first, endpoint.second)
                            val id = client.createUserWithEmailAndPassword("prototype@example.test", "local-password").await().user!!.uid
                            client.signOut()
                            check(client.signInWithEmailAndPassword("prototype@example.test", "local-password").await().user!!.uid == id)
                        }
                        "storage" -> {
                            val client = FirebaseStorage.getInstance(app)
                            val endpoint = endpoints.getValue("FIREBASE_STORAGE_EMULATOR_HOST")
                            client.useEmulator(endpoint.first, endpoint.second)
                            val ref = client.reference.child("public/prototype")
                            val bytes = byteArrayOf(1, 2, 3)
                            ref.putBytes(bytes).await()
                            check(ref.getBytes(10).await().contentEquals(bytes))
                        }
                        "database" -> {
                            val client = FirebaseDatabase.getInstance(app)
                            val endpoint = endpoints.getValue("FIREBASE_DATABASE_EMULATOR_HOST")
                            client.useEmulator(endpoint.first, endpoint.second)
                            cleanup = { client.goOffline() }
                            val ref = client.getReference("prototype")
                            ref.setValue(7L).await()
                            check(ref.get().await().getValue(Long::class.java) == 7L)
                        }
                    }
                    println("PROTOTYPE $product passed")
                } catch (error: Throwable) {
                    failures++
                    println("PROTOTYPE $product failed ${error.javaClass.simpleName} cause=${error.cause?.javaClass?.simpleName}")
                    // Private Gradle diagnostics establish platform failures; do not publish this output.
                    error.printStackTrace()
                } finally {
                    cleanup()
                    app.delete()
                }
            }
            check(failures == 0) { "prototype failures=$failures" }
        }
        try {
            val deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(5)
            while (!run.isDone && System.nanoTime() < deadline) {
                shadowOf(Looper.getMainLooper()).idle()
                Thread.sleep(10)
            }
            run.get(1, TimeUnit.SECONDS)
        } finally { run.cancel(true); executor.shutdownNow() }
    }
}
