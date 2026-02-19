package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import java.awt.Component
import java.awt.Container
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import javax.swing.text.JTextComponent

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    auditLog(api, "category=history_access type=$accessType decision=${if (allowed) "allow" else "deny"}")
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private fun auditLog(api: MontoyaApi, event: String) {
    api.logging().logToOutput("[MCP-AUDIT] $event")
}

private val sensitiveQueryParamRegex = Regex(
    "(?i)([?&](?:token|session(?:id)?|auth(?:orization)?|api[_-]?key|access[_-]?token|refresh[_-]?token|jwt)=)([^&\\s]+)"
)
private val sensitiveFormParamRegex = Regex(
    "(?im)((?:^|&)(?:token|session(?:id)?|auth(?:orization)?|api[_-]?key|access[_-]?token|refresh[_-]?token|jwt)=)([^&\\r\\n]+)"
)
private val sensitiveJsonFieldRegex = Regex(
    "(?i)(\"(?:token|session(?:id)?|auth(?:orization)?|api[_-]?key|access[_-]?token|refresh[_-]?token|jwt|cookie)\"\\s*:\\s*\")(.*?)(\")"
)
private val sensitiveHeaderRegex = Regex(
    "(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-session-id)\\s*:\\s*(.+)$"
)
private val bearerRegex = Regex("(?i)\\bBearer\\s+[A-Za-z0-9._\\-+/=]+")

internal fun redactSensitiveData(raw: String, includeSensitive: Boolean): String {
    if (includeSensitive) return raw

    var sanitized = raw
    sanitized = sensitiveHeaderRegex.replace(sanitized) { match ->
        "${match.groupValues[1]}: <redacted>"
    }
    sanitized = bearerRegex.replace(sanitized, "Bearer <redacted>")
    sanitized = sensitiveQueryParamRegex.replace(sanitized, "$1<redacted>")
    sanitized = sensitiveFormParamRegex.replace(sanitized, "$1<redacted>")
    sanitized = sensitiveJsonFieldRegex.replace(sanitized, "$1<redacted>$3")
    return sanitized
}

private fun toolDenied(message: String, code: String): String = toolError(message = message, errorCode = code)

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {
    ToolAuditLogger.sink = { line -> api.logging().logToOutput(line) }

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        auditLog(api, "category=http_request tool=send_http1_request target=$targetHostname:$targetPort")
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            auditLog(api, "category=http_request tool=send_http1_request decision=deny target=$targetHostname:$targetPort")
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool toolDenied("Send HTTP request denied by Burp Suite", "HTTP_REQUEST_DENIED")
        }

        auditLog(api, "category=http_request tool=send_http1_request decision=allow target=$targetHostname:$targetPort")
        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        auditLog(api, "category=http_request tool=send_http2_request target=$targetHostname:$targetPort")
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            auditLog(api, "category=http_request tool=send_http2_request decision=deny target=$targetHostname:$targetPort")
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool toolDenied("Send HTTP request denied by Burp Suite", "HTTP_REQUEST_DENIED")
        }

        auditLog(api, "category=http_request tool=send_http2_request decision=allow target=$targetHostname:$targetPort")
        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
            orderedPseudoHeaderNames.forEach { name ->
                val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                if (value != null) {
                    put(name, value)
                }
            }

            pseudoHeaders.forEach { (key, value) ->
                val properKey = if (key.startsWith(":")) key else ":$key"
                if (!containsKey(properKey)) {
                    put(properKey, value)
                }
            }
        }

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current Burp project options JSON. Use this first to confirm schema before modifying project-level settings."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    mcpTool(
        "output_user_options",
        "Outputs current Burp user options JSON. Use this first to confirm schema before modifying user-level settings."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This is merged with existing config. Export first to confirm schema. Use a top-level 'project_options' object.") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolDenied(toolingDisabledMessage, "CONFIG_EDITING_DISABLED")
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This is merged with existing config. Export first to confirm schema. Use a top-level 'user_options' object.") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolDenied(toolingDisabledMessage, "CONFIG_EDITING_DISABLED")
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf(toolDenied("HTTP history access denied by Burp Suite", "HTTP_HISTORY_DENIED"))
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf(toolDenied("HTTP history access denied by Burp Suite", "HTTP_HISTORY_DENIED"))
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf(toolDenied("WebSocket history access denied by Burp Suite", "WEBSOCKET_HISTORY_DENIED"))
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf(toolDenied("WebSocket history access denied by Burp Suite", "WEBSOCKET_HISTORY_DENIED"))
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: toolDenied("No active editor", "NO_ACTIVE_EDITOR")
    }

    mcpTool(
        "get_repeater_tabs",
        "Lists visible Repeater request tabs from the Burp UI and returns structured JSON metadata."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.REPEATER, config, api, "Repeater")
        }
        if (!allowed) {
            return@mcpTool toolDenied("Repeater access denied by Burp Suite", "REPEATER_ACCESS_DENIED")
        }

        val repeaterContext = findRepeaterContext(api)
            ?: return@mcpTool toolDenied("Repeater tab not found in Burp UI", "REPEATER_TAB_NOT_FOUND")

        val tabsPane = findRepeaterRequestTabsPane(repeaterContext.repeaterContent)
            ?: return@mcpTool toolDenied("Could not detect Repeater request tabs", "REPEATER_TABS_NOT_FOUND")

        val tabs = (0 until tabsPane.tabCount).map { index ->
            RepeaterTabInfo(
                index = index,
                title = tabsPane.getTitleAt(index).ifBlank { "Tab ${index + 1}" },
                isActive = index == tabsPane.selectedIndex
            )
        }

        Json.encodeToString(
            RepeaterTabsResult(
                isRepeaterToolActive = repeaterContext.isRepeaterSelected,
                tabCount = tabs.size,
                tabs = tabs
            )
        )
    }

    mcpTool<GetActiveRepeaterRequest>(
        "Reads the raw HTTP request from the currently active Repeater request tab. Sensitive values are redacted by default unless include_sensitive=true."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.REPEATER, config, api, "Repeater")
        }
        if (!allowed) {
            return@mcpTool toolDenied("Repeater access denied by Burp Suite", "REPEATER_ACCESS_DENIED")
        }

        val repeaterContext = findRepeaterContext(api)
            ?: return@mcpTool toolDenied("Repeater tab not found in Burp UI", "REPEATER_TAB_NOT_FOUND")

        if (!repeaterContext.isRepeaterSelected) {
            return@mcpTool toolDenied("Repeater is not currently the active Burp tool tab", "REPEATER_NOT_ACTIVE")
        }

        val tabsPane = findRepeaterRequestTabsPane(repeaterContext.repeaterContent)
            ?: return@mcpTool toolDenied("Could not detect Repeater request tabs", "REPEATER_TABS_NOT_FOUND")

        val selectedTab = tabsPane.selectedComponent
            ?: return@mcpTool toolDenied("No active Repeater request tab", "REPEATER_NO_ACTIVE_TAB")

        val rawRequest = extractBestHttpRequestText(selectedTab)
            ?: return@mcpTool toolDenied("Could not read raw request from active Repeater tab", "REPEATER_REQUEST_NOT_READABLE")

        redactSensitiveData(rawRequest, includeSensitive)
    }

    mcpTool<GetActiveRepeaterResponse>(
        "Reads the raw HTTP response from the currently active Repeater request tab. Sensitive values are redacted by default unless include_sensitive=true."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.REPEATER, config, api, "Repeater")
        }
        if (!allowed) {
            return@mcpTool toolDenied("Repeater access denied by Burp Suite", "REPEATER_ACCESS_DENIED")
        }

        val repeaterContext = findRepeaterContext(api)
            ?: return@mcpTool toolDenied("Repeater tab not found in Burp UI", "REPEATER_TAB_NOT_FOUND")

        if (!repeaterContext.isRepeaterSelected) {
            return@mcpTool toolDenied("Repeater is not currently the active Burp tool tab", "REPEATER_NOT_ACTIVE")
        }

        val tabsPane = findRepeaterRequestTabsPane(repeaterContext.repeaterContent)
            ?: return@mcpTool toolDenied("Could not detect Repeater request tabs", "REPEATER_TABS_NOT_FOUND")

        val selectedTab = tabsPane.selectedComponent
            ?: return@mcpTool toolDenied("No active Repeater request tab", "REPEATER_NO_ACTIVE_TAB")

        val rawResponse = extractBestHttpResponseText(selectedTab)
            ?: return@mcpTool toolDenied("Could not read raw response from active Repeater tab", "REPEATER_RESPONSE_NOT_READABLE")

        redactSensitiveData(rawResponse, includeSensitive)
    }

    mcpTool<GetRepeaterRequestByIndex>(
        "Reads the raw HTTP request from a specific Repeater request tab index. Sensitive values are redacted by default unless include_sensitive=true."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.REPEATER, config, api, "Repeater")
        }
        if (!allowed) {
            return@mcpTool toolDenied("Repeater access denied by Burp Suite", "REPEATER_ACCESS_DENIED")
        }

        val repeaterContext = findRepeaterContext(api)
            ?: return@mcpTool toolDenied("Repeater tab not found in Burp UI", "REPEATER_TAB_NOT_FOUND")

        val tabsPane = findRepeaterRequestTabsPane(repeaterContext.repeaterContent)
            ?: return@mcpTool toolDenied("Could not detect Repeater request tabs", "REPEATER_TABS_NOT_FOUND")

        val selectedTab = getRepeaterTabComponentAtIndex(tabsPane, index)
            ?: return@mcpTool toolDenied(
                "Repeater tab index $index is out of range (0..${tabsPane.tabCount - 1})",
                "REPEATER_TAB_INDEX_OUT_OF_RANGE"
            )

        val rawRequest = extractBestHttpRequestText(selectedTab)
            ?: return@mcpTool toolDenied("Could not read raw request from Repeater tab index $index", "REPEATER_REQUEST_NOT_READABLE")

        redactSensitiveData(rawRequest, includeSensitive)
    }

    mcpTool<GetRepeaterResponseByIndex>(
        "Reads the raw HTTP response from a specific Repeater request tab index. Sensitive values are redacted by default unless include_sensitive=true."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.REPEATER, config, api, "Repeater")
        }
        if (!allowed) {
            return@mcpTool toolDenied("Repeater access denied by Burp Suite", "REPEATER_ACCESS_DENIED")
        }

        val repeaterContext = findRepeaterContext(api)
            ?: return@mcpTool toolDenied("Repeater tab not found in Burp UI", "REPEATER_TAB_NOT_FOUND")

        val tabsPane = findRepeaterRequestTabsPane(repeaterContext.repeaterContent)
            ?: return@mcpTool toolDenied("Could not detect Repeater request tabs", "REPEATER_TABS_NOT_FOUND")

        val selectedTab = getRepeaterTabComponentAtIndex(tabsPane, index)
            ?: return@mcpTool toolDenied(
                "Repeater tab index $index is out of range (0..${tabsPane.tabCount - 1})",
                "REPEATER_TAB_INDEX_OUT_OF_RANGE"
            )

        val rawResponse = extractBestHttpResponseText(selectedTab)
            ?: return@mcpTool toolDenied("Could not read raw response from Repeater tab index $index", "REPEATER_RESPONSE_NOT_READABLE")

        redactSensitiveData(rawResponse, includeSensitive)
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool toolDenied("No active editor", "NO_ACTIVE_EDITOR")

        if (!editor.isEditable) {
            return@mcpTool toolDenied("Current editor is not editable", "EDITOR_NOT_EDITABLE")
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

private val knownRepeaterEditorTabs = setOf(
    "request",
    "response",
    "raw",
    "pretty",
    "hex",
    "params",
    "inspector",
    "render"
)

data class RepeaterContext(
    val repeaterContent: Component,
    val isRepeaterSelected: Boolean
)

fun findRepeaterContext(api: MontoyaApi): RepeaterContext? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val topTabbedPanes = findDescendants(frame).filterIsInstance<JTabbedPane>().toList()

    for (tabs in topTabbedPanes) {
        for (index in 0 until tabs.tabCount) {
            val title = tabs.getTitleAt(index).trim()
            if (title.equals("Repeater", ignoreCase = true)) {
                val content = tabs.getComponentAt(index)
                return RepeaterContext(
                    repeaterContent = content,
                    isRepeaterSelected = tabs.selectedIndex == index
                )
            }
        }
    }

    return null
}

fun findRepeaterRequestTabsPane(repeaterContent: Component): JTabbedPane? {
    val panes = findDescendants(repeaterContent).filterIsInstance<JTabbedPane>().toList()
    if (panes.isEmpty()) return null

    val rootWidth = repeaterContent.width.takeIf { it > 0 } ?: repeaterContent.preferredSize.width
    val rootHeight = repeaterContent.height.takeIf { it > 0 } ?: repeaterContent.preferredSize.height
    val normalizedRootWidth = if (rootWidth > 0) rootWidth else 1600
    val normalizedRootHeight = if (rootHeight > 0) rootHeight else 900

    return panes.maxByOrNull { pane ->
        val titles = (0 until pane.tabCount).map { pane.getTitleAt(it).trim().lowercase() }
        val unknownTitles = titles.count { it.isNotBlank() && it !in knownRepeaterEditorTabs }
        val onlyKnownTitles = titles.all { it.isBlank() || it in knownRepeaterEditorTabs }
        val numericTitles = titles.count { it.matches(Regex("^\\d+$")) }

        val pointInRoot = runCatching {
            SwingUtilities.convertPoint(pane.parent, pane.x, pane.y, repeaterContent)
        }.getOrElse { java.awt.Point(pane.x, pane.y) }

        val isTopArea = pointInRoot.y <= (normalizedRootHeight * 0.25)
        val isLeftArea = pointInRoot.x <= (normalizedRootWidth * 0.4)

        var score = pane.tabCount * 10
        score += unknownTitles * 20
        if (onlyKnownTitles) score -= 15
        score += numericTitles * 60

        if (isTopArea) score += 40 else score -= 20
        if (isLeftArea) score += 40 else score -= 25

        score
    }
}

fun extractBestHttpRequestText(component: Component): String? {
    val candidates = collectTextCandidates(component)

    if (candidates.isEmpty()) return null

    return candidates.maxByOrNull { scoreHttpRequestCandidate(it) }
}

fun extractBestHttpResponseText(component: Component): String? {
    val candidates = collectTextCandidates(component)

    if (candidates.isEmpty()) return null

    return candidates.maxByOrNull { scoreHttpResponseCandidate(it) }
}

private fun collectTextCandidates(component: Component): List<String> {
    val candidates = mutableListOf<String>()

    for (child in findDescendants(component)) {
        when (child) {
            is JTextComponent -> {
                val text = child.text?.trim().orEmpty()
                if (text.isNotBlank()) candidates.add(text)
            }

            else -> {
                try {
                    val method = child.javaClass.methods.firstOrNull {
                        it.name == "getText" && it.parameterCount == 0 && it.returnType == String::class.java
                    }
                    val text = method?.invoke(child) as? String
                    if (!text.isNullOrBlank()) {
                        candidates.add(text.trim())
                    }
                } catch (_: Exception) {
                    // Best-effort UI scraping only.
                }
            }
        }
    }

    return candidates
}

private fun scoreHttpRequestCandidate(text: String): Int {
    var score = 0

    val requestLineRegex = Regex(
        "^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\\s+\\S+\\s+HTTP/\\d(?:\\.\\d)?",
        RegexOption.MULTILINE
    )
    if (requestLineRegex.containsMatchIn(text)) score += 200
    if (text.startsWith("HTTP/")) score -= 100
    if (text.contains("\nHost:", ignoreCase = true) || text.contains("\r\nHost:", ignoreCase = true)) score += 40
    if (text.contains("\r\n\r\n") || text.contains("\n\n")) score += 20

    score += minOf(text.length, 4000) / 20
    return score
}

private fun scoreHttpResponseCandidate(text: String): Int {
    var score = 0

    val responseLineRegex = Regex("^HTTP/\\d(?:\\.\\d)?\\s+\\d{3}\\b", RegexOption.MULTILINE)
    if (responseLineRegex.containsMatchIn(text)) score += 220

    val requestLineRegex = Regex(
        "^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\\s+\\S+\\s+HTTP/\\d(?:\\.\\d)?",
        RegexOption.MULTILINE
    )
    if (requestLineRegex.containsMatchIn(text)) score -= 120

    if (text.contains("\nContent-Type:", ignoreCase = true) || text.contains(
            "\r\nContent-Type:",
            ignoreCase = true
        )
    ) {
        score += 40
    }

    if (text.contains("\r\n\r\n") || text.contains("\n\n")) score += 20
    score += minOf(text.length, 4000) / 20

    return score
}

private fun findDescendants(root: Component): Sequence<Component> = sequence {
    yield(root)
    if (root is Container) {
        for (child in root.components) {
            yieldAll(findDescendants(child))
        }
    }
}

private fun JTabbedPane.getComponentAtOrNull(index: Int): Component? {
    return if (index in 0 until tabCount) getComponentAt(index) else null
}

internal fun getRepeaterTabComponentAtIndex(tabsPane: JTabbedPane, index: Int): Component? {
    return tabsPane.getComponentAtOrNull(index)
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

@Serializable
data class GetActiveRepeaterRequest(
    @SerialName("include_sensitive")
    val includeSensitive: Boolean = false
)

@Serializable
data class GetActiveRepeaterResponse(
    @SerialName("include_sensitive")
    val includeSensitive: Boolean = false
)

@Serializable
data class GetRepeaterRequestByIndex(
    val index: Int,
    @SerialName("include_sensitive")
    val includeSensitive: Boolean = false
)

@Serializable
data class GetRepeaterResponseByIndex(
    val index: Int,
    @SerialName("include_sensitive")
    val includeSensitive: Boolean = false
)

@Serializable
data class RepeaterTabInfo(
    val index: Int,
    val title: String,
    val isActive: Boolean
)

@Serializable
data class RepeaterTabsResult(
    val isRepeaterToolActive: Boolean,
    val tabCount: Int,
    val tabs: List<RepeaterTabInfo>
)
