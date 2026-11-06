package dev.fireemu.smoke

/** The fixed client contract prevents missing or blocked cases from passing. */
object CaseReport {
    val required = setOf(
        "firestore.write-read", "firestore.transforms", "firestore.query", "firestore.listener",
        "firestore.transaction", "firestore.offline-resume", "firestore.batch-delete",
        "firestore.rules-anonymous-denied", "firestore.rules-owner", "firestore.rules-signout",
        "auth.signup", "auth.signin", "auth.refresh", "storage.upload-download", "storage.metadata",
        "storage.resumable", "storage.download-url", "storage.list-delete", "storage.rules-denied",
        "database.set-read", "database.listener", "database.transaction", "database.on-disconnect"
    )
    fun successful(results: Map<String, String>): Boolean =
        results.keys == required && results.values.all { it == "passed" }
}
