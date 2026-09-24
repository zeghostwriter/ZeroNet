package com.zeronet.mobile.service

import com.zeronet.mobile.data.ServerStore
import com.zeronet.mobile.model.ConnState
import com.zeronet.mobile.model.DiscoveryProgress
import com.zeronet.mobile.model.DiscoveryStage
import com.zeronet.mobile.model.FailReason
import com.zeronet.mobile.model.ImportResult
import com.zeronet.mobile.model.ScanResult
import com.zeronet.mobile.model.ScanState
import com.zeronet.mobile.model.Server
import com.zeronet.mobile.model.TrafficStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IpcTest {
    private val server = Server(
        key = "0123456789abcdef", link = "vless://id@example.com:443?security=reality#Node",
        name = "Node", protocol = "vless", transport = "tcp", security = "reality",
        host = "example.com", port = 443, country = "DE", source = "feed:discovered", favorite = true, delayMs = 312,
    )

    @Test
    fun `every connection state crosses the process boundary intact`() {
        val states = listOf(
            ConnState.Idle,
            ConnState.Disconnecting,
            ConnState.Searching(DiscoveryProgress(DiscoveryStage.Real, 4200, 800, 230, 60, 2)),
            ConnState.Connecting(server),
            ConnState.Connecting(null),
            ConnState.Connected(server, since = 1_700_000_000_000, delayMs = 312, pool = 4),
            ConnState.Reconnecting("all servers stopped answering"),
            ConnState.Failed(FailReason.NoWorkingServer, "DE"),
        )
        for (state in states) {
            val decoded = Ipc.stateFromJson(Ipc.stateToJson(state))
            // Server.lastTestedAt/aliveCount/failCount are not sent; compare what is.
            assertEquals(state.toString(), decoded.toString())
        }
    }

    @Test
    fun `stats, scan and import results round trip`() {
        val stats = TrafficStats(10, 2_000_000, 12345, 987654321, listOf(1, 2, 3), listOf(4, 5))
        assertEquals(stats, Ipc.statsFromJson(Ipc.statsToJson(stats)))

        val scan = ScanState(true, 500, 12, 2000, listOf(ScanResult("104.16.1.2", 443, 82)), "boom")
        assertEquals(scan, Ipc.scanFromJson(Ipc.scanToJson(scan)))
        val clean = scan.copy(error = null)
        assertEquals(clean, Ipc.scanFromJson(Ipc.scanToJson(clean)))

        val import = ImportResult(3, 1, 2, null)
        assertEquals(import, Ipc.importFromJson(Ipc.importToJson(import)))
    }

    @Test
    fun `an unknown state decodes to idle instead of crashing the UI`() {
        assertEquals(ConnState.Idle, Ipc.stateFromJson("""{"t":"from-the-future"}"""))
    }

    @Test
    fun `faster servers earn a higher history score, and every success earns at least one`() {
        val fast = ServerStore.successScore(80)
        val slow = ServerStore.successScore(2000)
        assertTrue(fast > slow)
        assertTrue(slow > 1.0)
        assertEquals(ServerStore.successScore(0), ServerStore.successScore(50), 1e-9)
    }
}
