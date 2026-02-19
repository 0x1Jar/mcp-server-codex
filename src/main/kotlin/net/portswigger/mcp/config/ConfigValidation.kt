package net.portswigger.mcp.config

object ConfigValidation {

    fun validateServerConfig(host: String, portText: String): String? {
        val trimmedHost = host.trim()
        val port = portText.trim().toIntOrNull()

        if (trimmedHost.isBlank()) {
            return "Host must not be empty"
        }

        // Keep host validation flexible for local/lab/mobile pentest setups:
        // allow hostname, IPv4, IPv6, and custom local names, but reject obvious invalid separators.
        if (trimmedHost.any { it.isWhitespace() } || trimmedHost.contains("/") || trimmedHost.contains("\\")) {
            return "Host contains invalid characters"
        }

        if (port == null) {
            return "Port must be a valid number"
        }

        if (port < 1024 || port > 65535) {
            return "Port is not within valid range"
        }

        return null
    }
}
