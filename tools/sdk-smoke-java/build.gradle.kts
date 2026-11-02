// The Java Admin SDK smoke: see README.md. Every resolved artifact is hash-checked against
// gradle/verification-metadata.xml, and the wrapper checks the distribution against
// distributionSha256Sum in gradle/wrapper/gradle-wrapper.properties.
plugins {
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.google.firebase:firebase-admin:9.11.0")
}

testing {
    suites {
        named<JvmTestSuite>("test") {
            useJUnitJupiter("6.1.3")
            dependencies {
                implementation("org.junit.jupiter:junit-jupiter-params")
            }
        }
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 17
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

application {
    mainClass = "dev.fireemu.smoke.JavaAdminSmoke"
}
