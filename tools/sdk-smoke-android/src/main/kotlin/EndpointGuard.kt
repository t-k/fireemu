package dev.fireemu.smoke

/** Validates all routing before any Firebase client is initialized. */
object EndpointGuard {
    fun validate(value: String?): Pair<String, Int> {
        require(value != null) { "missing emulator endpoint" }
        val match = Regex("(127\\.0\\.0\\.1|\\[::1\\]):([0-9]{1,5})").matchEntire(value)
        require(match != null) { "emulator endpoint must be literal loopback with a port" }
        val port = match.groupValues[2].toInt()
        require(port in 1..65535) { "invalid emulator port" }
        return match.groupValues[1].removeSurrounding("[", "]") to port
    }
}
