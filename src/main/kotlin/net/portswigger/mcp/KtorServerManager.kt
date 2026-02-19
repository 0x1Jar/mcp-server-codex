package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.doublereceive.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.registerTools
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class KtorServerManager(private val api: MontoyaApi) : ServerManager {

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val sessionClients = ConcurrentHashMap<String, SessionClientInfo>()
    private val json = Json { ignoreUnknownKeys = true }

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        callback(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                val mcpServer = Server(
                    serverInfo = Implementation("burp-suite", "1.1.2"), options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )

                server = embeddedServer(Netty, port = config.port, host = config.host) {
                    install(DoubleReceive)

                    install(CORS) {
                        allowHost("localhost:${config.port}")
                        allowHost("127.0.0.1:${config.port}")

                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Post)

                        allowHeader(HttpHeaders.ContentType)
                        allowHeader(HttpHeaders.Accept)
                        allowHeader("Last-Event-ID")

                        allowCredentials = false
                        allowNonSimpleContentTypes = true
                        maxAgeInSeconds = 3600
                    }

                    intercept(ApplicationCallPipeline.Call) {
                        val origin = call.request.header("Origin")
                        val host = call.request.header("Host")
                        val referer = call.request.header("Referer")
                        val userAgent = call.request.header("User-Agent")

                        if (origin != null && !isValidOrigin(origin)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from origin: $origin")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        } else if (isBrowserRequest(userAgent)) {
                            api.logging().logToOutput("Blocked browser request without Origin header")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (host != null && !isValidHost(host, config.port)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from host: $host")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (referer != null && !isValidReferer(referer)) {
                            api.logging().logToOutput("Blocked suspicious request from referer: $referer")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        trackClientSession(call, userAgent)

                        call.response.header("X-Frame-Options", "DENY")
                        call.response.header("X-Content-Type-Options", "nosniff")
                        call.response.header("Referrer-Policy", "same-origin")
                        call.response.header("Content-Security-Policy", "default-src 'none'")
                    }

                    mcp {
                        mcpServer
                    }

                    mcpServer.registerTools(api, config)
                }.apply {
                    start(wait = false)
                }

                val baseUrl = buildBaseUrl(config.host, config.port)
                api.logging().logToOutput("Started MCP server on ${config.host}:${config.port}")
                api.logging().logToOutput("MCP ready to use | endpoint: $baseUrl/")
                api.logging().logToOutput("MCP JSON-RPC endpoint: $baseUrl/?sessionId=<id>")

                if (isLoopbackHost(config.host)) {
                    api.logging().logToOutput("MCP access scope: local-only (loopback host)")
                } else {
                    api.logging().logToOutput("MCP access scope: network/LAN (host: ${config.host})")
                }
                api.logging().logToOutput("MCP session tracking is active (auto-detect Codex/Claude/Gemini clients)")
                callback(ServerState.Running)

            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        callback(ServerState.Stopping)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                sessionClients.clear()
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        server?.stop(1000, 5000)
        server = null
        sessionClients.clear()

        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

    private suspend fun trackClientSession(call: ApplicationCall, userAgent: String?) {
        if (call.request.httpMethod != HttpMethod.Post) return

        val sessionId = call.request.queryParameters["sessionId"]?.trim().orEmpty()
        if (sessionId.isEmpty()) return
        if (sessionClients.containsKey(sessionId)) return

        val body = runCatching { call.receiveText() }.getOrNull() ?: return
        if (!body.contains("\"method\":\"initialize\"")) return

        val parsed = runCatching { json.parseToJsonElement(body).jsonObject }.getOrNull() ?: return
        val method = parsed["method"]?.jsonPrimitive?.contentOrNull ?: return
        if (method != "initialize") return

        val params = parsed["params"]?.jsonObject
        val clientInfo = params?.get("clientInfo")?.jsonObject
        val clientName = clientInfo?.get("name")?.jsonPrimitive?.contentOrNull
        val clientVersion = clientInfo?.get("version")?.jsonPrimitive?.contentOrNull

        val detection = detectClientType(clientName, userAgent)

        val previous = sessionClients.putIfAbsent(
            sessionId,
            SessionClientInfo(
                clientName = clientName ?: "unknown",
                clientVersion = clientVersion,
                userAgent = userAgent,
                clientType = detection.clientType,
                detectedBy = detection.detectedBy
            )
        )

        if (previous == null) {
            api.logging().logToOutput(
                "MCP client connected | session=$sessionId | type=${detection.clientType.label} | name=${clientName ?: "unknown"} | detectedBy=${detection.detectedBy}"
            )
        }
    }

    private fun detectClientType(clientName: String?, userAgent: String?): ClientDetection {
        val fromName = classifyClient(clientName)
        if (fromName != ClientType.UNKNOWN) {
            return ClientDetection(fromName, "clientInfo.name")
        }

        val fromUa = classifyClient(userAgent)
        if (fromUa != ClientType.UNKNOWN) {
            return ClientDetection(fromUa, "user-agent")
        }

        return ClientDetection(ClientType.UNKNOWN, "unknown")
    }

    private fun classifyClient(raw: String?): ClientType {
        val value = raw?.lowercase().orEmpty()
        if (value.isBlank()) return ClientType.UNKNOWN

        return when {
            value.contains("codex") -> ClientType.CODEX
            value.contains("claude") -> ClientType.CLAUDE
            value.contains("gemini") -> ClientType.GEMINI
            else -> ClientType.UNKNOWN
        }
    }

    private fun isValidOrigin(origin: String): Boolean {
        try {
            val url = URI(origin).toURL()
            val hostname = url.host.lowercase()

            val allowedHosts = setOf("localhost", "127.0.0.1")

            return hostname in allowedHosts
        } catch (_: Exception) {
            return false
        }
    }

    private fun isBrowserRequest(userAgent: String?): Boolean {
        if (userAgent == null) return false

        val userAgentLower = userAgent.lowercase()
        val browserIndicators = listOf(
            "mozilla/", "chrome/", "safari/", "webkit/", "gecko/", "firefox/", "edge/", "opera/", "browser"
        )

        return browserIndicators.any { userAgentLower.contains(it) }
    }

    private fun isValidHost(host: String, expectedPort: Int): Boolean {
        try {
            val parts = host.split(":")
            val hostname = parts[0].lowercase()
            val port = if (parts.size > 1) parts[1].toIntOrNull() else null

            val allowedHosts = setOf("localhost", "127.0.0.1")
            if (hostname !in allowedHosts) {
                return false
            }

            if (port != null && port != expectedPort) {
                return false
            }

            return true
        } catch (_: Exception) {
            return false
        }
    }

    private fun isValidReferer(referer: String): Boolean {
        try {
            val url = URI(referer).toURL()
            val hostname = url.host.lowercase()

            val allowedHosts = setOf("localhost", "127.0.0.1")
            return hostname in allowedHosts

        } catch (_: Exception) {
            return false
        }
    }

    private fun buildBaseUrl(host: String, port: Int): String {
        val trimmed = host.trim()
        val normalizedHost = when {
            trimmed.contains(":") && !trimmed.startsWith("[") && !trimmed.endsWith("]") -> "[$trimmed]"
            else -> trimmed
        }
        return "http://$normalizedHost:$port"
    }

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.trim().removePrefix("[").removeSuffix("]").lowercase()
        return normalized == "127.0.0.1" || normalized == "localhost" || normalized == "::1"
    }
}

private enum class ClientType(val label: String) {
    CODEX("codex"),
    CLAUDE("claude"),
    GEMINI("gemini"),
    UNKNOWN("unknown")
}

private data class ClientDetection(
    val clientType: ClientType,
    val detectedBy: String
)

private data class SessionClientInfo(
    val clientName: String,
    val clientVersion: String?,
    val userAgent: String?,
    val clientType: ClientType,
    val detectedBy: String
)
