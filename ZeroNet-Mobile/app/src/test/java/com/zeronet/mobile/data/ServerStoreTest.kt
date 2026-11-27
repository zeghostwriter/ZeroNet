package com.zeronet.mobile.data

import android.database.sqlite.SQLiteDatabase
import com.zeronet.mobile.model.Server
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ServerStoreTest {
    private val context = RuntimeEnvironment.getApplication()

    /** The store is a process singleton; each test gets a fresh database. */
    @Before
    fun freshStore() {
        ServerStore::class.java.getDeclaredField("instance").apply { isAccessible = true }.set(null, null)
        context.deleteDatabase("servers.db")
    }

    private fun server(key: String) = Server(
        key = key, link = "vless://$key@example.com:443", name = key, protocol = "vless",
        transport = "tcp", security = "reality", host = "example.com", port = 443,
        country = "DE", source = Server.SOURCE_USER,
    )

    @Test
    fun `a version 2 database upgrades with every server still included`() {
        // A servers.db as the previous release wrote it: no excluded column.
        val file = context.getDatabasePath("servers.db")
        file.parentFile?.mkdirs()
        SQLiteDatabase.openOrCreateDatabase(file, null).use { db ->
            db.execSQL(
                """CREATE TABLE servers(key TEXT PRIMARY KEY, link TEXT NOT NULL, name TEXT NOT NULL,
                   protocol TEXT NOT NULL, transport TEXT NOT NULL, security TEXT NOT NULL,
                   host TEXT NOT NULL, port INTEGER NOT NULL, country TEXT NOT NULL, source TEXT NOT NULL,
                   favorite INTEGER NOT NULL DEFAULT 0, delay_ms INTEGER NOT NULL DEFAULT -1,
                   tested_at INTEGER NOT NULL DEFAULT 0, alive_count INTEGER NOT NULL DEFAULT 0,
                   fail_count INTEGER NOT NULL DEFAULT 0, first_seen INTEGER NOT NULL, last_error TEXT)""",
            )
            db.execSQL("CREATE TABLE history(network TEXT NOT NULL, key TEXT NOT NULL, score REAL NOT NULL, last_ok INTEGER NOT NULL, PRIMARY KEY(network, key)) WITHOUT ROWID")
            db.execSQL("CREATE TABLE subscriptions(id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL DEFAULT 0, count INTEGER NOT NULL DEFAULT 0)")
            db.execSQL("INSERT INTO servers(key, link, name, protocol, transport, security, host, port, country, source, first_seen) VALUES('old', 'vless://old', 'old', 'vless', 'tcp', 'tls', 'h', 443, 'DE', 'user', 0)")
            db.version = 2
        }
        val store = ServerStore.get(context)
        val old = store.all().single { it.key == "old" }
        assertFalse("existing servers must stay available to auto-selection", old.excluded)
    }

    @Test
    fun `an excluded server is kept but left out of automatic picks`() {
        val store = ServerStore.get(context)
        store.upsert(listOf(server("a"), server("b")))
        store.recordResult("a", 100, "wifi")
        store.recordResult("b", 120, "wifi")
        assertEquals(2, store.historyLinks("wifi", 10).size)

        store.setExcluded("a", true)
        assertTrue(store.all().single { it.key == "a" }.excluded)
        assertEquals(setOf("a"), store.excludedKeys())
        assertEquals(listOf("vless://b@example.com:443"), store.historyLinks("wifi", 10))

        // A later refresh of the same link must not silently re-include it.
        store.upsert(listOf(server("a")))
        assertTrue(store.all().single { it.key == "a" }.excluded)

        store.setExcluded("a", false)
        assertEquals(2, store.historyLinks("wifi", 10).size)
    }

    private fun found(key: String) = server(key).copy(source = Server.SOURCE_FEED_PREFIX + "discovered")

    @Test
    fun `a discovered server that failed is deleted and forgotten, a working one is kept`() {
        val store = ServerStore.get(context)
        store.upsert(listOf(found("dead"), found("alive")))
        store.recordResult("dead", 100, "wifi")
        store.recordResult("alive", 120, "wifi")
        store.recordResult("dead", -1, "wifi", "timeout")
        store.forget(listOf("dead"))
        assertEquals(listOf("alive"), store.all().map { it.key })
        assertEquals(setOf("dead"), store.forgottenKeys())
        // Gone from the network history too, so it is not retried at the next connect.
        assertEquals(listOf("vless://alive@example.com:443"), store.historyLinks("wifi", 10))
    }

    @Test
    fun `the person's own, favourite and excluded servers are never forgotten`() {
        val store = ServerStore.get(context)
        store.upsert(listOf(server("mine"), found("fav"), found("ruled-out"), found("sub").copy(source = Server.SOURCE_SUB_PREFIX + "s1")))
        store.setFavorite("fav", true)
        store.setExcluded("ruled-out", true)
        store.forget(listOf("mine", "fav", "ruled-out", "sub"))
        assertEquals(setOf("mine", "fav", "ruled-out", "sub"), store.all().map { it.key }.toSet())
        assertTrue(store.forgottenKeys().isEmpty())
    }

    @Test
    fun `a forgotten server that answers again, or is imported, is forgiven`() {
        val store = ServerStore.get(context)
        store.upsert(listOf(found("a"), found("b")))
        store.forget(listOf("a", "b", "never-stored"))
        assertEquals(setOf("a", "b", "never-stored"), store.forgottenKeys())
        // A search finds "a" working again.
        store.upsert(listOf(found("a")))
        store.recordResult("a", 90, "wifi")
        assertEquals(setOf("b", "never-stored"), store.forgottenKeys())
        // The person pastes "b" themselves.
        store.upsert(listOf(server("b")))
        assertEquals(setOf("never-stored"), store.forgottenKeys())
    }

    @Test
    fun `a server is forgotten for a week and then may be tried again`() {
        val store = ServerStore.get(context)
        store.forget(listOf("old", "recent"))
        val db = store.writableDatabase
        db.execSQL("UPDATE forgotten SET at = ? WHERE key = 'old'", arrayOf<Any>(System.currentTimeMillis() - ServerStore.FORGET_MS - 1))
        assertEquals(setOf("recent"), store.forgottenKeys())
    }

    @Test
    fun `a version 4 database gains the forgotten table with its servers intact`() {
        val file = context.getDatabasePath("servers.db")
        file.parentFile?.mkdirs()
        SQLiteDatabase.openOrCreateDatabase(file, null).use { db ->
            db.execSQL(
                """CREATE TABLE servers(key TEXT PRIMARY KEY, link TEXT NOT NULL, name TEXT NOT NULL,
                   protocol TEXT NOT NULL, transport TEXT NOT NULL, security TEXT NOT NULL,
                   host TEXT NOT NULL, port INTEGER NOT NULL, country TEXT NOT NULL, source TEXT NOT NULL,
                   favorite INTEGER NOT NULL DEFAULT 0, excluded INTEGER NOT NULL DEFAULT 0,
                   delay_ms INTEGER NOT NULL DEFAULT -1, tested_at INTEGER NOT NULL DEFAULT 0,
                   alive_count INTEGER NOT NULL DEFAULT 0, fail_count INTEGER NOT NULL DEFAULT 0,
                   first_seen INTEGER NOT NULL, last_error TEXT, fingerprint TEXT NOT NULL DEFAULT '')""",
            )
            db.execSQL("CREATE TABLE history(network TEXT NOT NULL, key TEXT NOT NULL, score REAL NOT NULL, last_ok INTEGER NOT NULL, PRIMARY KEY(network, key)) WITHOUT ROWID")
            db.execSQL("CREATE TABLE subscriptions(id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL DEFAULT 0, count INTEGER NOT NULL DEFAULT 0)")
            db.execSQL("INSERT INTO servers(key, link, name, protocol, transport, security, host, port, country, source, first_seen) VALUES('k', 'vless://k', 'k', 'vless', 'tcp', 'tls', 'h', 443, 'DE', 'feed:discovered', 0)")
            db.version = 4
        }
        val store = ServerStore.get(context)
        assertEquals(listOf("k"), store.all().map { it.key })
        store.forget(listOf("k"))
        assertEquals(setOf("k"), store.forgottenKeys())
    }
}
