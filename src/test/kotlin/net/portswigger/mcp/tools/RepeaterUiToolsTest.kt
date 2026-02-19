package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlinx.serialization.json.Json
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.JTextArea

class RepeaterUiToolsTest {

    @Test
    fun `findRepeaterRequestTabsPane should prefer user tab pane over editor subtabs`() {
        val repeaterRoot = JPanel().apply {
            layout = null
            setSize(1400, 900)
        }

        val editorSubTabs = JTabbedPane().apply {
            addTab("Raw", JPanel())
            addTab("Hex", JPanel())
            setBounds(120, 220, 420, 120)
        }

        val requestTabs = JTabbedPane().apply {
            addTab("Login Flow", JPanel())
            addTab("Search API", JPanel())
            setBounds(10, 10, 260, 44)
        }

        repeaterRoot.add(editorSubTabs)
        repeaterRoot.add(requestTabs)

        val detected = findRepeaterRequestTabsPane(repeaterRoot)

        assertSame(requestTabs, detected)
    }

    @Test
    fun `findRepeaterRequestTabsPane should prefer top-left numbered tabs over right-side tabs`() {
        val repeaterRoot = JPanel().apply {
            layout = null
            setSize(1800, 1000)
        }

        val topLeftNumberedTabs = JTabbedPane().apply {
            addTab("1", JPanel())
            addTab("2", JPanel())
            setBounds(8, 8, 220, 44)
        }

        val rightSideTabs = JTabbedPane().apply {
            addTab("Request attributes", JPanel())
            addTab("Request headers", JPanel())
            addTab("Response headers", JPanel())
            setBounds(1300, 120, 420, 300)
        }

        repeaterRoot.add(rightSideTabs)
        repeaterRoot.add(topLeftNumberedTabs)

        val detected = findRepeaterRequestTabsPane(repeaterRoot)

        assertSame(topLeftNumberedTabs, detected)
    }

    @Test
    fun `findRepeaterRequestTabsPane should stay stable with split panel and inspector tabs`() {
        val repeaterRoot = JPanel().apply {
            layout = null
            setSize(1920, 1080)
        }

        val topLeftRequestTabs = JTabbedPane().apply {
            addTab("1", JPanel())
            addTab("2", JPanel())
            addTab("3", JPanel())
            setBounds(12, 8, 260, 46)
        }

        val responseSubTabs = JTabbedPane().apply {
            addTab("Pretty", JPanel())
            addTab("Raw", JPanel())
            addTab("Hex", JPanel())
            addTab("Render", JPanel())
            setBounds(980, 210, 420, 120)
        }

        val inspectorTabs = JTabbedPane().apply {
            addTab("Request attributes", JPanel())
            addTab("Request parameters", JPanel())
            addTab("Request headers", JPanel())
            addTab("Response headers", JPanel())
            setBounds(1460, 120, 420, 420)
        }

        repeaterRoot.add(inspectorTabs)
        repeaterRoot.add(responseSubTabs)
        repeaterRoot.add(topLeftRequestTabs)

        val detected = findRepeaterRequestTabsPane(repeaterRoot)

        assertSame(topLeftRequestTabs, detected)
    }

    @Test
    fun `findRepeaterRequestTabsPane should prefer top-left user tabs when many panes exist`() {
        val repeaterRoot = JPanel().apply {
            layout = null
            setSize(1600, 900)
        }

        val requestTabs = JTabbedPane().apply {
            addTab("Login", JPanel())
            addTab("Orders", JPanel())
            addTab("Profile", JPanel())
            setBounds(8, 8, 320, 44)
        }

        val lowerPaneTabs = JTabbedPane().apply {
            addTab("Notes", JPanel())
            addTab("Logger", JPanel())
            setBounds(20, 620, 500, 220)
        }

        val rightPaneTabs = JTabbedPane().apply {
            addTab("Request", JPanel())
            addTab("Response", JPanel())
            setBounds(1160, 210, 360, 180)
        }

        repeaterRoot.add(lowerPaneTabs)
        repeaterRoot.add(rightPaneTabs)
        repeaterRoot.add(requestTabs)

        val detected = findRepeaterRequestTabsPane(repeaterRoot)

        assertSame(requestTabs, detected)
    }

    @Test
    fun `extractBestHttpRequestText should choose request-like text`() {
        val root = JPanel()
        val responseText = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
        val requestText = "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=alice"

        root.add(JTextArea(responseText))
        root.add(JTextArea(requestText))

        val extracted = extractBestHttpRequestText(root)

        assertEquals(requestText, extracted)
    }

    @Test
    fun `extractBestHttpResponseText should choose response-like text`() {
        val root = JPanel()
        val requestText = "GET /api/me HTTP/1.1\r\nHost: example.com\r\n\r\n"
        val responseText = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"unauthorized\"}"

        root.add(JTextArea(requestText))
        root.add(JTextArea(responseText))

        val extracted = extractBestHttpResponseText(root)

        assertEquals(responseText, extracted)
    }

    @Test
    fun `extractBestHttpRequestText should return null when no text found`() {
        val root = JPanel().apply {
            add(JPanel())
        }

        val extracted = extractBestHttpRequestText(root)

        assertTrue(extracted == null)
    }

    @Test
    fun `getRepeaterTabComponentAtIndex should resolve valid index and reject out of range`() {
        val tabs = JTabbedPane()
        val first = JLabel("first")
        val second = JLabel("second")
        tabs.addTab("1", first)
        tabs.addTab("2", second)

        assertSame(first, getRepeaterTabComponentAtIndex(tabs, 0))
        assertSame(second, getRepeaterTabComponentAtIndex(tabs, 1))
        assertNull(getRepeaterTabComponentAtIndex(tabs, -1))
        assertNull(getRepeaterTabComponentAtIndex(tabs, 2))
    }

    @Test
    fun `redactSensitiveData should mask common sensitive headers and params by default`() {
        val raw = """
            GET /api?token=abc123&lang=en HTTP/1.1
            Host: example.com
            Authorization: Bearer secret-token
            Cookie: sessionid=super-secret
            Content-Type: application/json
            
            {"access_token":"abc","normal":"safe"}
        """.trimIndent()

        val redacted = redactSensitiveData(raw, includeSensitive = false)

        assertTrue(redacted.contains("authorization: <redacted>", ignoreCase = true))
        assertTrue(redacted.contains("cookie: <redacted>", ignoreCase = true))
        assertTrue(redacted.contains("token=<redacted>"))
        assertTrue(redacted.contains("\"access_token\":\"<redacted>\""))
        assertFalse(redacted.contains("secret-token"))
        assertFalse(redacted.contains("super-secret"))
    }

    @Test
    fun `redactSensitiveData should preserve raw content when includeSensitive true`() {
        val raw = "Authorization: Bearer keep-this\nCookie: sessionid=keep-me"
        val output = redactSensitiveData(raw, includeSensitive = true)
        assertEquals(raw, output)
    }

    @Test
    fun `repeater tabs result should serialize as structured JSON`() {
        val result = RepeaterTabsResult(
            isRepeaterToolActive = true,
            tabCount = 2,
            tabs = listOf(
                RepeaterTabInfo(index = 0, title = "Login", isActive = true),
                RepeaterTabInfo(index = 1, title = "Search", isActive = false)
            )
        )

        val json = Json.encodeToString(RepeaterTabsResult.serializer(), result)

        assertTrue(json.contains("\"isRepeaterToolActive\":true"))
        assertTrue(json.contains("\"tabCount\":2"))
        assertTrue(json.contains("\"title\":\"Login\""))
        assertTrue(json.contains("\"isActive\":true"))
    }
}
