package net.portswigger.mcp.providers

import burp.api.montoya.logging.Logging
import kotlinx.serialization.json.*
import net.portswigger.mcp.config.McpConfig
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import javax.swing.JFileChooser
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText

interface Provider {
    val name: String
    val installButtonText: String
    val confirmationText: String?
    fun install(config: McpConfig): String?
}

class ClaudeDesktopProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) : Provider {

    private val claudeConfigFileName = "claude_desktop_config.json"
    private val serverName = "burp"

    override val name = "Claude Desktop"
    override val installButtonText = "Install to $name"
    override val confirmationText =
        "Install to $name?\nThis will create an entry within $name's MCP configuration file ($claudeConfigFileName)"

    override fun install(config: McpConfig): String {
        val proxyJarFile = proxyJarManager.getProxyJar()

        val path = configFilePath() ?: error("Could not find Claude config path")
        val content = Json.parseToJsonElement(path.readText()).jsonObject.toMutableMap()

        val javaPath = javaPath()
        logging.logToOutput("Using Java from: $javaPath")

        val sseUrl = "http://${config.host}:${config.port}"
        val burpServerConfig = buildJsonObject {
            put("command", JsonPrimitive(javaPath))
            put("args", buildJsonArray {
                add(JsonPrimitive("-jar"))
                add(JsonPrimitive(proxyJarFile.toString()))
                add(JsonPrimitive("--sse-url"))
                add(JsonPrimitive(sseUrl))
            })
        }

        val mcpServers = content["mcpServers"]?.jsonObject?.toMutableMap() ?: mutableMapOf()
        mcpServers[serverName] = burpServerConfig
        content["mcpServers"] = JsonObject(mcpServers)

        val json = Json {
            prettyPrint = true
            encodeDefaults = true
        }
        path.writeText(json.encodeToString(JsonObject.serializer(), JsonObject(content)))

        logging.logToOutput("Installed Burp MCP Server to Claude Desktop config")

        return "Installation successful. Please restart $name if it is currently running."
    }

    private fun configFilePath(): Path? {
        val os = System.getProperty("os.name").lowercase()
        val home = System.getProperty("user.home")

        val basePath = when {
            os.contains("win") -> Path.of(home, "AppData", "Roaming", "Claude")
            os.contains("mac") || os.contains("darwin") -> Path.of(home, "Library", "Application Support", "Claude")
            os.contains("linux") -> Path.of(home, ".config", "Claude")
            else -> return null
        }

        if (!basePath.exists()) return null

        val configFile = basePath.resolve(claudeConfigFileName)
        if (!configFile.exists()) {
            createDefaultConfig(configFile)
        }

        return configFile
    }

    private fun createDefaultConfig(path: Path): Boolean {
        try {
            val defaultConfig = buildJsonObject {
                put("mcpServers", buildJsonObject {})
            }

            val json = Json {
                prettyPrint = true
                encodeDefaults = true
            }

            path.writeText(json.encodeToString(JsonObject.serializer(), defaultConfig))
            logging.logToOutput("Created default Claude Desktop config at $path")
            return true
        } catch (e: Exception) {
            logging.logToError("Failed to create default Claude Desktop config: ${e.message}")
            return false
        }
    }

    private fun javaPath(): String {
        val javaHome = System.getProperty("java.home")
        val os = System.getProperty("os.name").lowercase()

        return if (os.contains("win")) {
            "$javaHome\\bin\\java.exe"
        } else {
            "$javaHome/bin/java"
        }
    }
}

class CodexProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) : Provider {

    override val name = "Codex"
    override val installButtonText = "Install to $name"
    override val confirmationText =
        "Install to $name?\nThis will add/update the Burp MCP server entry in Codex config (config.toml)."

    override fun install(config: McpConfig): String {
        val proxyJarFile = proxyJarManager.getProxyJar()
        val configPath = configFilePath()

        if (!configPath.parent.exists()) {
            Files.createDirectories(configPath.parent)
        }

        if (!configPath.exists()) {
            configPath.writeText("")
        }

        val existingConfig = configPath.readText()
        val updatedConfig = upsertBurpServerConfig(existingConfig, config, proxyJarFile)

        configPath.writeText(updatedConfig)

        logging.logToOutput("Installed Burp MCP Server to Codex config: $configPath")
        return "Installation successful. Please restart Codex if it is currently running."
    }

    private fun configFilePath(): Path {
        val os = System.getProperty("os.name").lowercase()
        val home = System.getProperty("user.home")

        return when {
            os.contains("win") -> Path.of(home, ".codex", "config.toml")
            os.contains("mac") || os.contains("darwin") -> Path.of(home, ".codex", "config.toml")
            os.contains("linux") || os.contains("unix") -> Path.of(home, ".codex", "config.toml")
            else -> throw RuntimeException("Unsupported OS: $os")
        }
    }

    private fun upsertBurpServerConfig(existingConfig: String, config: McpConfig, proxyJarFile: Path): String {
        val sectionHeader = "[mcp_servers.burp]"
        val sectionBody = buildString {
            appendLine(sectionHeader)
            appendLine("command = ${toTomlString(javaPath())}")
            appendLine(
                "args = [\"-jar\", ${toTomlString(proxyJarFile.toString())}, \"--sse-url\", ${
                    toTomlString("http://${config.host}:${config.port}")
                }]"
            )
        }.trimEnd()

        if (existingConfig.isBlank()) {
            return "$sectionBody\n"
        }

        val lines = existingConfig.lines()
        val sectionStart = lines.indexOfFirst { it.trim() == sectionHeader }

        if (sectionStart == -1) {
            return existingConfig.trimEnd() + "\n\n$sectionBody\n"
        }

        var sectionEnd = lines.size
        for (i in (sectionStart + 1) until lines.size) {
            val trimmed = lines[i].trim()
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                sectionEnd = i
                break
            }
        }

        val before = lines.subList(0, sectionStart).joinToString("\n").trimEnd()
        val after = lines.subList(sectionEnd, lines.size).joinToString("\n").trimStart('\n')

        return buildString {
            if (before.isNotEmpty()) {
                append(before)
                append("\n\n")
            }
            append(sectionBody)
            if (after.isNotEmpty()) {
                append("\n\n")
                append(after)
            }
            append("\n")
        }
    }

    private fun toTomlString(value: String): String {
        val escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
        return "\"$escaped\""
    }

    private fun javaPath(): String {
        val javaHome = System.getProperty("java.home")
        val os = System.getProperty("os.name").lowercase()

        return if (os.contains("win")) {
            "$javaHome\\bin\\java.exe"
        } else {
            "$javaHome/bin/java"
        }
    }
}

class ManualProxyInstallerProvider(private val logging: Logging, private val proxyJarManager: ProxyJarManager) :
    Provider {
    override val name = "Proxy jar"
    override val installButtonText = "Extract server proxy jar"
    override val confirmationText = null

    override fun install(config: McpConfig): String? {
        val proxyJarFile = proxyJarManager.getProxyJar()

        val fileChooser = JFileChooser().apply {
            dialogTitle = "Save proxy jar"
            selectedFile = File("mcp-proxy.jar")
        }

        if (fileChooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) {
            return null
        }

        val destinationFile = fileChooser.selectedFile
        try {
            Files.copy(proxyJarFile, destinationFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
            logging.logToOutput("MCP proxy jar saved successfully to ${destinationFile.absolutePath}")
        } catch (ex: Exception) {
            logging.logToError("Failed to save installer: ${ex.message}")
            throw ex
        }

        return "Extracted proxy jar to $destinationFile"
    }
}
