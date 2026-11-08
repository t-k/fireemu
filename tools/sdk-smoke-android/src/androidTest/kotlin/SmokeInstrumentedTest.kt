package dev.fireemu.smoke

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SmokeInstrumentedTest {
    @Test fun allRequiredCases() {
        val arguments = InstrumentationRegistry.getArguments()
        val names = listOf("FIRESTORE_EMULATOR_HOST", "FIREBASE_AUTH_EMULATOR_HOST", "FIREBASE_STORAGE_EMULATOR_HOST", "FIREBASE_DATABASE_EMULATOR_HOST")
        val endpoints = names.associateWith { EndpointGuard.validate(arguments.getString(it), device = true) }
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        SmokeCases(instrumentation.targetContext, { line ->
            instrumentation.sendStatus(0, Bundle().apply { putString("stream", "$line\n") })
        }, arguments.getString("caseFilter")).exercise(endpoints)
    }
}
