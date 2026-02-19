package net.portswigger.mcp.security

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HistoryAccessSecurityTest {

    private val originalHandler = HistoryAccessSecurity.approvalHandler

    @AfterEach
    fun tearDown() {
        HistoryAccessSecurity.approvalHandler = originalHandler
    }

    @Test
    fun `repeater approval should be independent from global history approval`() = runBlocking {
        val config = createConfig(
            mapOf(
                "requireHistoryAccessApproval" to false,
                "requireRepeaterAccessApproval" to true,
                "_alwaysAllowRepeaterAccess" to false
            )
        )

        var approvalCalls = 0
        HistoryAccessSecurity.approvalHandler = object : HistoryAccessApprovalHandler {
            override suspend fun requestHistoryAccess(accessType: HistoryAccessType, config: McpConfig): Boolean {
                approvalCalls++
                return false
            }
        }

        val httpAllowed = HistoryAccessSecurity.checkHistoryAccessPermission(HistoryAccessType.HTTP_HISTORY, config)
        val repeaterAllowed = HistoryAccessSecurity.checkHistoryAccessPermission(HistoryAccessType.REPEATER, config)

        assertTrue(httpAllowed)
        assertFalse(repeaterAllowed)
        assertEquals(1, approvalCalls)
    }

    @Test
    fun `repeater always allow should bypass approval prompt`() = runBlocking {
        val config = createConfig(
            mapOf(
                "requireHistoryAccessApproval" to true,
                "requireRepeaterAccessApproval" to true,
                "_alwaysAllowRepeaterAccess" to true
            )
        )

        var approvalCalls = 0
        HistoryAccessSecurity.approvalHandler = object : HistoryAccessApprovalHandler {
            override suspend fun requestHistoryAccess(accessType: HistoryAccessType, config: McpConfig): Boolean {
                approvalCalls++
                return false
            }
        }

        val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(HistoryAccessType.REPEATER, config)

        assertTrue(allowed)
        assertEquals(0, approvalCalls)
    }

    private fun createConfig(flags: Map<String, Boolean>): McpConfig {
        val storage = mutableMapOf<String, Any>()
        storage.putAll(flags)

        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg<String>()] as? Boolean }
            every { getString(any()) } answers { storage[firstArg<String>()] as? String }
            every { getInteger(any()) } answers { storage[firstArg<String>()] as? Int }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }

        val logging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
        }

        return McpConfig(persistedObject, logging)
    }
}
