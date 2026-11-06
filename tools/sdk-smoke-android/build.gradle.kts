plugins {
    id("com.android.library") version "8.13.2"
    id("org.jetbrains.kotlin.android") version "2.3.0"
}
android {
    namespace = "dev.fireemu.smoke"
    compileSdk = 36
    buildToolsVersion = "35.0.0"
    defaultConfig { minSdk = 24 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests.isIncludeAndroidResources = true
        unitTests.all {
            it.maxHeapSize = "2g"
            it.maxParallelForks = 1
            it.jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED", "--add-opens=java.base/java.util=ALL-UNNAMED", "--add-opens=java.base/java.io=ALL-UNNAMED", "--add-opens=java.base/java.net=ALL-UNNAMED", "--add-opens=java.base/java.security=ALL-UNNAMED", "--add-opens=java.base/java.text=ALL-UNNAMED", "--add-opens=java.base/jdk.internal.access=ALL-UNNAMED")
            it.testLogging { events("passed", "failed", "skipped"); showStandardStreams = true }
        }
    }
}
kotlin { compilerOptions { jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17 } }
dependencies {
    testImplementation(platform("com.google.firebase:firebase-bom:35.1.0"))
    testImplementation("com.google.firebase:firebase-firestore")
    testImplementation("com.google.firebase:firebase-auth")
    testImplementation("com.google.firebase:firebase-storage")
    testImplementation("com.google.firebase:firebase-database")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("junit:junit:4.13.2")
}
dependencyLocking { lockAllConfigurations() }
