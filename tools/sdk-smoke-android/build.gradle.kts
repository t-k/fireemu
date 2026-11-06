plugins {
    id("com.android.library") version "8.13.2"
    id("org.jetbrains.kotlin.android") version "2.3.0"
}
val robolectricSdk by configurations.creating
val prepareRobolectric by tasks.registering(Copy::class) {
    from(robolectricSdk)
    into(layout.buildDirectory.dir("robolectric"))
}
android {
    namespace = "dev.fireemu.smoke"
    signingConfigs.getByName("debug") {
        storeFile = layout.projectDirectory.file(".gradle-home/debug.keystore").asFile
        storePassword = "android"
        keyAlias = "androiddebugkey"
        keyPassword = "android"
    }
    compileSdk = 36
    buildToolsVersion = "35.0.0"
    defaultConfig { minSdk = 24; testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        unitTests.isIncludeAndroidResources = true
        unitTests.all {
            it.dependsOn(prepareRobolectric)
            it.systemProperty("robolectric.offline", "true")
            it.systemProperty("robolectric.dependency.dir", layout.buildDirectory.dir("robolectric").get().asFile.absolutePath)
            it.maxHeapSize = "2g"
            it.doFirst { layout.projectDirectory.dir(".gradle-home/test-home").asFile.mkdirs() }
            it.systemProperty("user.home", layout.projectDirectory.dir(".gradle-home/test-home").asFile.absolutePath)
            it.systemProperty("maven.repo.local", layout.projectDirectory.dir(".gradle-home/robolectric").asFile.absolutePath)
            it.maxParallelForks = 1
            it.jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED", "--add-opens=java.base/java.util=ALL-UNNAMED", "--add-opens=java.base/java.io=ALL-UNNAMED", "--add-opens=java.base/java.net=ALL-UNNAMED", "--add-opens=java.base/java.security=ALL-UNNAMED", "--add-opens=java.base/java.text=ALL-UNNAMED", "--add-opens=java.base/jdk.internal.access=ALL-UNNAMED")
            it.testLogging { events("passed", "failed", "skipped"); showStandardStreams = true }
        }
    }
}
kotlin { compilerOptions { jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17 } }
dependencies {
    robolectricSdk("org.robolectric:android-all-instrumented:15-robolectric-13954326-i7") { isTransitive = false }
    implementation(platform("com.google.firebase:firebase-bom:35.1.0"))
    implementation("com.google.firebase:firebase-firestore")
    implementation("com.google.firebase:firebase-auth")
    implementation("com.google.firebase:firebase-storage")
    implementation("com.google.firebase:firebase-database")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
dependencyLocking { lockAllConfigurations() }
