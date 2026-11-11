package dev.fireemu.smoke

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File

class GuardTest {
    @Test fun deviceAliasRequiresExplicitMode() {
        assertEquals("10.0.2.2" to 8080, EndpointGuard.validate("10.0.2.2:8080", device = true))
        assertThrows(IllegalArgumentException::class.java) { EndpointGuard.validate("10.0.2.2:8080") }
        assertThrows(IllegalArgumentException::class.java) { EndpointGuard.validate("10.0.2.2.example.com:8080", device = true) }
    }
    @Test fun rejectsPublicHost() {
        assertThrows(IllegalArgumentException::class.java) { EndpointGuard.validate("example.com:8080") }
    }
    @Test fun rejectsMissingAndMalformedEndpoints() {
        for (endpoint in listOf(null, "", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:-1", "localhost:80", "127.0.0.1.example.com:80", "http://127.0.0.1:80", "127.0.0.1:80/path", "user@127.0.0.1:80", "10.0.2.2:80")) {
            assertThrows(IllegalArgumentException::class.java) { EndpointGuard.validate(endpoint) }
        }
    }
    @Test fun acceptsLiteralLoopbackBoundaries() {
        assertEquals("127.0.0.1" to 1, EndpointGuard.validate("127.0.0.1:1"))
        assertEquals("::1" to 65535, EndpointGuard.validate("[::1]:65535"))
    }
    @Test fun generatedCombinations() {
        val generated = System.getenv("ANDROID_PICT_CASES")
        val rows = if (generated != null) File(generated).readLines().drop(1).map { it.trim().split('\t') }
            else listOf("loopback", "public", "deceptive", "alias").flatMap { host -> listOf("valid", "zero", "overflow").flatMap { port -> listOf("present", "absent").flatMap { presence -> listOf("jvm", "device").map { listOf(host, port, presence, it) } } } }
        require(rows.isNotEmpty())
        for ((host, port, presence, mode) in rows) {
            val address = when (host) { "loopback" -> "127.0.0.1"; "public" -> "example.com"; "deceptive" -> "127.0.0.1.example.com"; "alias" -> "10.0.2.2"; else -> error("unknown host factor") }
            val number = when (port) { "valid" -> "8080"; "zero" -> "0"; "overflow" -> "65536"; else -> error("unknown port factor") }
            require(presence in listOf("present", "absent"))
            val input = if (presence == "absent") null else "$address:$number"
            require(mode in listOf("jvm", "device"))
            if ((host == "loopback" || host == "alias" && mode == "device") && port == "valid" && presence == "present") assertEquals(address to 8080, EndpointGuard.validate(input, device = mode == "device"))
            else assertThrows(IllegalArgumentException::class.java) { EndpointGuard.validate(input, device = mode == "device") }
        }
        println("guard combinations=${rows.size}")
    }
}
