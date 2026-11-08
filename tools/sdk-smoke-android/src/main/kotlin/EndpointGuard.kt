package dev.fireemu.smoke

/** Validates all routing before any Firebase client is initialized. */
object EndpointGuard {
    fun validate(value: String?, device: Boolean = false): Pair<String, Int> {
        require(value != null) { "missing emulator endpoint" }
        val host = if (device) "(127\\.0\\.0\\.1|\\[::1\\]|10\\.0\\.2\\.2)" else "(127\\.0\\.0\\.1|\\[::1\\])"
        val match = Regex("$host:([0-9]{1,5})").matchEntire(value)
        require(match != null) { "emulator endpoint must be literal loopback with a port" }
        val port = match.groupValues[2].toInt()
        require(port in 1..65535) { "invalid emulator port" }
        return match.groupValues[1].removeSurrounding("[", "]") to port
    }
}
