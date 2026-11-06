package dev.fireemu.smoke

import android.os.Looper
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Diagnostic only: host-JDK HTTP header semantics differ from Android. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SmokeTest {
    @Test fun diagnosticJvmCases() {
        assumeTrue("Android instrumentation is the required network smoke", System.getenv("ANDROID_ROBOLECTRIC_DIAGNOSTIC") == "1")
        val names = listOf("FIRESTORE_EMULATOR_HOST", "FIREBASE_AUTH_EMULATOR_HOST", "FIREBASE_STORAGE_EMULATOR_HOST", "FIREBASE_DATABASE_EMULATOR_HOST")
        val endpoints = names.associateWith { EndpointGuard.validate(System.getenv(it)) }
        val worker = Executors.newSingleThreadExecutor()
        val future = worker.submit { SmokeCases(RuntimeEnvironment.getApplication()).exercise(endpoints) }
        try {
            val deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(10)
            while (!future.isDone && System.nanoTime() < deadline) { shadowOf(Looper.getMainLooper()).idle(); Thread.sleep(10) }
            future.get(1, TimeUnit.SECONDS)
        } finally { future.cancel(true); worker.shutdownNow() }
    }
}
