package net.portswigger.mcp.diagnostics

import kotlinx.serialization.Serializable
import java.util.concurrent.ConcurrentHashMap

private const val ACTIVE_WINDOW_MS = 5 * 60 * 1000L

@Serializable
data class McpSessionStat(
    val sessionId: String,
    val clientType: String,
    val clientName: String,
    val clientVersion: String? = null,
    val detectedBy: String,
    val lastSeenAtMs: Long
)

@Serializable
data class McpSessionStatsResult(
    val activeSessionCount: Int,
    val sessions: List<McpSessionStat>
)

private data class McpSessionRecord(
    val sessionId: String,
    val clientType: String,
    val clientName: String,
    val clientVersion: String?,
    val detectedBy: String,
    @Volatile var lastSeenAtMs: Long
)

object McpSessionRegistry {
    private val sessions = ConcurrentHashMap<String, McpSessionRecord>()

    fun upsert(
        sessionId: String,
        clientType: String,
        clientName: String,
        clientVersion: String?,
        detectedBy: String,
        seenAtMs: Long = System.currentTimeMillis()
    ) {
        sessions.compute(sessionId) { _, existing ->
            val record = existing ?: McpSessionRecord(
                sessionId = sessionId,
                clientType = clientType,
                clientName = clientName,
                clientVersion = clientVersion,
                detectedBy = detectedBy,
                lastSeenAtMs = seenAtMs
            )

            if (existing == null) {
                record
            } else {
                existing.lastSeenAtMs = seenAtMs
                McpSessionRecord(
                    sessionId = sessionId,
                    clientType = if (existing.clientType == "unknown") clientType else existing.clientType,
                    clientName = if (existing.clientName == "unknown") clientName else existing.clientName,
                    clientVersion = existing.clientVersion ?: clientVersion,
                    detectedBy = if (existing.detectedBy == "unknown") detectedBy else existing.detectedBy,
                    lastSeenAtMs = seenAtMs
                )
            }
        }
    }

    fun touch(sessionId: String, seenAtMs: Long = System.currentTimeMillis()) {
        sessions.compute(sessionId) { _, existing ->
            if (existing == null) {
                McpSessionRecord(
                    sessionId = sessionId,
                    clientType = "unknown",
                    clientName = "unknown",
                    clientVersion = null,
                    detectedBy = "unknown",
                    lastSeenAtMs = seenAtMs
                )
            } else {
                existing.lastSeenAtMs = seenAtMs
                existing
            }
        }
    }

    fun contains(sessionId: String): Boolean = sessions.containsKey(sessionId)

    fun isUnknownClient(sessionId: String): Boolean {
        return sessions[sessionId]?.clientType == "unknown"
    }

    fun snapshotActive(
        nowMs: Long = System.currentTimeMillis(),
        includeProxy: Boolean = false
    ): McpSessionStatsResult {
        val minActiveMs = nowMs - ACTIVE_WINDOW_MS

        sessions.entries.removeIf { (_, record) -> record.lastSeenAtMs < minActiveMs }

        val active = sessions.values
            .sortedByDescending { it.lastSeenAtMs }
            .filter { includeProxy || it.clientType != "proxy" }
            .map {
                McpSessionStat(
                    sessionId = it.sessionId,
                    clientType = it.clientType,
                    clientName = it.clientName,
                    clientVersion = it.clientVersion,
                    detectedBy = it.detectedBy,
                    lastSeenAtMs = it.lastSeenAtMs
                )
            }

        return McpSessionStatsResult(
            activeSessionCount = active.size,
            sessions = active
        )
    }

    fun clear() {
        sessions.clear()
    }
}
