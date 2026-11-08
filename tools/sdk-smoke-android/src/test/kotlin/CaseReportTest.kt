package dev.fireemu.smoke

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaseReportTest {
    @Test fun missingCasesCannotPass() { assertFalse(CaseReport.successful(emptyMap())) }
    @Test fun blockedCasesCannotPass() { assertFalse(CaseReport.successful(allPassed() + ("auth.signup" to "blocked"))) }
    @Test fun failedCasesCannotPass() { assertFalse(CaseReport.successful(allPassed() + ("auth.signup" to "failed"))) }
    @Test fun unknownCaseCannotReplaceRequiredCase() {
        assertFalse(CaseReport.successful(allPassed() - "database.on-disconnect" + ("database.fake" to "passed")))
    }
    @Test fun completePassingContractSucceeds() { assertTrue(CaseReport.successful(allPassed())) }
    private fun allPassed() = CaseReport.required.associateWith { "passed" }
}
