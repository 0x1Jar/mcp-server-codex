package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlinx.serialization.json.Json
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.JTextArea

class RepeaterUiToolsTest {

    @Test
    fun `findRepeaterRequestTabsPane should prefer user tab pane over editor subtabs`() {
        val repeaterRoot = JPanel()

        val editorSubTabs = JTabbedPane().apply {
            addTab("Raw", JPanel())
            addTab("Hex", JPanel())
        }

        val requestTabs = JTabbedPane().apply {
            addTab("Login Flow", JPanel())
            addTab("Search API", JPanel())
        }

        repeaterRoot.add(editorSubTabs)
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
