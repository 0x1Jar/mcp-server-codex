package net.portswigger.mcp.security

import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import javax.swing.SwingUtilities
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

enum class HistoryAccessType() {
    HTTP_HISTORY(), WEBSOCKET_HISTORY(), REPEATER();
}

interface HistoryAccessApprovalHandler {
    suspend fun requestHistoryAccess(accessType: HistoryAccessType, config: McpConfig): Boolean
}

class SwingHistoryAccessApprovalHandler : HistoryAccessApprovalHandler {
    override suspend fun requestHistoryAccess(
        accessType: HistoryAccessType, config: McpConfig
    ): Boolean {
        return suspendCoroutine { continuation ->
            SwingUtilities.invokeLater {
                val historyTypeName = when (accessType) {
                    HistoryAccessType.HTTP_HISTORY -> "HTTP history"
                    HistoryAccessType.WEBSOCKET_HISTORY -> "WebSocket history"
                    HistoryAccessType.REPEATER -> "Repeater"
                }

                val message = buildString {
                    appendLine("An MCP client is requesting access to your Burp Suite $historyTypeName data.")
                    appendLine()
                    appendLine("This may include sensitive request/response data.")
                    appendLine("Choose how you would like to respond:")
                }

                val options = arrayOf(
                    "Allow Once", "Always Allow $historyTypeName access", "Deny"
                )

                val burpFrame = findBurpFrame()

                val result = Dialogs.showOptionDialog(
                    burpFrame, message, options
                )

                when (result) {
                    0 -> {
                        continuation.resume(true)
                    }

                    1 -> {
                        when (accessType) {
                            HistoryAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory = true
                            HistoryAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory = true
                            HistoryAccessType.REPEATER -> config.alwaysAllowRepeaterAccess = true
                        }
                        continuation.resume(true)
                    }

                    else -> {
                        continuation.resume(false)
                    }
                }
            }
        }
    }
}

object HistoryAccessSecurity {

    var approvalHandler: HistoryAccessApprovalHandler = SwingHistoryAccessApprovalHandler()

    private fun isApprovalRequired(accessType: HistoryAccessType, config: McpConfig): Boolean {
        return when (accessType) {
            HistoryAccessType.REPEATER -> config.requireRepeaterAccessApproval
            HistoryAccessType.HTTP_HISTORY, HistoryAccessType.WEBSOCKET_HISTORY -> config.requireHistoryAccessApproval
        }
    }

    suspend fun checkHistoryAccessPermission(
        accessType: HistoryAccessType, config: McpConfig
    ): Boolean {
        if (!isApprovalRequired(accessType, config)) {
            return true
        }

        val isAlwaysAllowed = when (accessType) {
            HistoryAccessType.HTTP_HISTORY -> config.alwaysAllowHttpHistory
            HistoryAccessType.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory
            HistoryAccessType.REPEATER -> config.alwaysAllowRepeaterAccess
        }

        if (isAlwaysAllowed) {
            return true
        }

        return approvalHandler.requestHistoryAccess(accessType, config)
    }
}
