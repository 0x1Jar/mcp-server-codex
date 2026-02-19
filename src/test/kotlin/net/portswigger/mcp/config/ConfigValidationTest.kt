package net.portswigger.mcp.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class ConfigValidationTest {

    @Test
    fun `validateServerConfig should allow mobile pentest friendly hosts`() {
        assertNull(ConfigValidation.validateServerConfig("192.168.1.10", "9876"))
        assertNull(ConfigValidation.validateServerConfig("10.10.0.55", "8080"))
        assertNull(ConfigValidation.validateServerConfig("burp-lab.local", "12345"))
        assertNull(ConfigValidation.validateServerConfig("::1", "9876"))
    }

    @Test
    fun `validateServerConfig should reject invalid host separators`() {
        assertEquals("Host contains invalid characters", ConfigValidation.validateServerConfig("bad/host", "9876"))
        assertEquals("Host contains invalid characters", ConfigValidation.validateServerConfig("bad host", "9876"))
    }
}
