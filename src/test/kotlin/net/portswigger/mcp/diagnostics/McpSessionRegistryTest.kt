package net.portswigger.mcp.diagnostics

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class McpSessionRegistryTest {

    @BeforeEach
    fun setup() {
        McpSessionRegistry.clear()
    }

    @AfterEach
    fun tearDown() {
        McpSessionRegistry.clear()
    }

    @Test
    fun `snapshotActive should hide proxy sessions by default`() {
        val now = 1_000_000L

        McpSessionRegistry.upsert(
            sessionId = "s-proxy",
            clientType = "proxy",
            clientName = "burp-proxy",
            clientVersion = "1.0.0",
            detectedBy = "clientInfo.name",
            seenAtMs = now
        )
        McpSessionRegistry.upsert(
            sessionId = "s-codex",
            clientType = "codex",
            clientName = "codex-cli",
            clientVersion = "1.0.0",
            detectedBy = "clientInfo.name",
            seenAtMs = now
        )

        val stats = McpSessionRegistry.snapshotActive(nowMs = now)

        assertEquals(1, stats.activeSessionCount)
        assertEquals(1, stats.sessions.size)
        assertEquals("codex", stats.sessions.first().clientType)
    }

    @Test
    fun `snapshotActive should include proxy sessions when requested`() {
        val now = 2_000_000L

        McpSessionRegistry.upsert(
            sessionId = "s-proxy",
            clientType = "proxy",
            clientName = "burp-proxy",
            clientVersion = "1.0.0",
            detectedBy = "clientInfo.name",
            seenAtMs = now
        )
        McpSessionRegistry.upsert(
            sessionId = "s-codex",
            clientType = "codex",
            clientName = "codex-cli",
            clientVersion = "1.0.0",
            detectedBy = "clientInfo.name",
            seenAtMs = now
        )

        val stats = McpSessionRegistry.snapshotActive(nowMs = now, includeProxy = true)

        assertEquals(2, stats.activeSessionCount)
        assertTrue(stats.sessions.any { it.clientType == "proxy" })
        assertTrue(stats.sessions.any { it.clientType == "codex" })
    }
}
