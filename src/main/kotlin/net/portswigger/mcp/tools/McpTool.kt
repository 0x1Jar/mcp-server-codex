package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.PromptMessageContent
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import kotlin.experimental.ExperimentalTypeInference

object ToolAuditLogger {
    var sink: ((String) -> Unit)? = null

    fun log(event: String) {
        sink?.invoke("[MCP-AUDIT] $event")
    }
}

private val responseJson = Json {
    explicitNulls = true
    encodeDefaults = true
}

@Serializable
data class StandardToolResponse(
    val status: String,
    val message: String,
    val data: JsonElement? = null,
    @SerialName("error_code")
    val errorCode: String? = null
)

@PublishedApi
internal fun String.toJsonDataElement(): JsonElement {
    return runCatching { Json.parseToJsonElement(this) }.getOrElse { JsonPrimitive(this) }
}

@PublishedApi
internal fun isStandardToolResponse(raw: String): Boolean {
    val parsed = runCatching { Json.parseToJsonElement(raw) }.getOrNull() as? JsonObject ?: return false
    return parsed.containsKey("status") &&
        parsed.containsKey("message") &&
        parsed.containsKey("data") &&
        parsed.containsKey("error_code")
}

@PublishedApi
internal fun wrapToolSuccess(raw: String): String {
    if (isStandardToolResponse(raw)) {
        return raw
    }

    return responseJson.encodeToString(
        StandardToolResponse(
            status = "success",
            message = "ok",
            data = raw.toJsonDataElement(),
            errorCode = null
        )
    )
}

fun toolSuccess(
    message: String = "ok",
    data: JsonElement? = JsonNull,
): String {
    return responseJson.encodeToString(
        StandardToolResponse(
            status = "success",
            message = message,
            data = data,
            errorCode = null
        )
    )
}

fun toolSuccessData(data: String, message: String = "ok"): String {
    return responseJson.encodeToString(
        StandardToolResponse(
            status = "success",
            message = message,
            data = data.toJsonDataElement(),
            errorCode = null
        )
    )
}

fun toolError(message: String, errorCode: String): String {
    return responseJson.encodeToString(
        StandardToolResponse(
            status = "error",
            message = message,
            data = JsonNull,
            errorCode = errorCode
        )
    )
}

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> List<PromptMessageContent>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")

    addTool(
        name = toolName,
        description = description,
        inputSchema = I::class.asInputSchema(),
        handler = { request ->
            ToolAuditLogger.log("tool=$toolName event=request")
            try {
                val result = CallToolResult(
                    content = execute(
                        Json.decodeFromJsonElement(
                            I::class.serializer(),
                            request.arguments
                        )
                    )
                )
                ToolAuditLogger.log("tool=$toolName event=success")
                result
            } catch (e: Exception) {
                ToolAuditLogger.log("tool=$toolName event=error code=UNEXPECTED_TOOL_ERROR message=${e.message}")
                CallToolResult(
                    content = listOf(
                        TextContent(
                            toolError(
                                message = e.message ?: "Unexpected tool execution error",
                                errorCode = "UNEXPECTED_TOOL_ERROR"
                            )
                        )
                    ),
                    isError = true
                )
            }
        }
    )
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> String
) {
    mcpTool<I>(description, execute = {
        listOf(TextContent(wrapToolSuccess(execute(this))))
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolUnit")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: I.() -> Unit
) {
    mcpTool<I>(description, execute = {
        execute(this)

        listOf(
            TextContent(
                toolSuccess(message = "executed", data = JsonNull)
            )
        )
    })
}

inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedTool(
    description: String,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: I.() -> List<J>
) {
    mcpTool<I>(description, execute = {

        val items = execute(this)

        when {
            offset >= items.size -> {
                toolSuccess(message = "reached_end_of_items", data = JsonNull)
            }

            else -> {
                val upperLimit = (offset + count).coerceAtMost(items.size)

                items.subList(offset, upperLimit)
                    .joinToString(separator = "\n\n", transform = mapper)
            }
        }
    })
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: I.() -> Sequence<String>
) {
    mcpTool<I>(description, execute = {
        val seq = execute(this)
        val paginated = seq.drop(offset).take(count).toList()

        if (paginated.isEmpty()) {
            listOf(TextContent(toolSuccess(message = "reached_end_of_items", data = JsonNull)))
        } else if (paginated.size == 1 && isStandardToolResponse(paginated.first())) {
            listOf(TextContent(paginated.first()))
        } else {
            listOf(TextContent(toolSuccessData(paginated.joinToString(separator = "\n\n"))))
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> List<PromptMessageContent>
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            ToolAuditLogger.log("tool=$name event=request")
            try {
                val result = CallToolResult(
                    content = execute()
                )
                ToolAuditLogger.log("tool=$name event=success")
                result
            } catch (e: Exception) {
                ToolAuditLogger.log("tool=$name event=error code=UNEXPECTED_TOOL_ERROR message=${e.message}")
                CallToolResult(
                    content = listOf(
                        TextContent(
                            toolError(
                                message = e.message ?: "Unexpected tool execution error",
                                errorCode = "UNEXPECTED_TOOL_ERROR"
                            )
                        )
                    ),
                    isError = true
                )
            }
        }
    )
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: () -> String
) {
    addTool(
        name = name,
        description = description,
        inputSchema = Tool.Input(),
        handler = {
            ToolAuditLogger.log("tool=$name event=request")
            try {
                val output = execute()
                ToolAuditLogger.log("tool=$name event=success")
                CallToolResult(
                    content = listOf(TextContent(wrapToolSuccess(output)))
                )
            } catch (e: Exception) {
                ToolAuditLogger.log("tool=$name event=error code=UNEXPECTED_TOOL_ERROR message=${e.message}")
                CallToolResult(
                    content = listOf(
                        TextContent(
                            toolError(
                                message = e.message ?: "Unexpected tool execution error",
                                errorCode = "UNEXPECTED_TOOL_ERROR"
                            )
                        )
                    ),
                    isError = true
                )
            }
        }
    )
}

fun String.toLowerSnakeCase(): String {
    return this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int
}
