package com.zeronet.mobile.data

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.zeronet.mobile.model.Server

/**
 * Configs the app knows about, and what it learned about them per network.
 *
 * Plain framework SQLite: no ORM, no annotation processing, no reflection.
 * The :vpn process writes (discovery results, test results); the UI process
 * reads and toggles favourites/imports. WAL mode makes that cross-process use
 * safe, and the UI is told to re-query through the engine's IPC channel.
 *
 * Only *working* discovered configs are stored — feeds carry tens of
 * thousands of dead ones, and keeping them would cost disk, memory and list
 * performance for nothing. The user's own configs are always kept.
 */
class ServerStore private constructor(context: Context) :
    SQLiteOpenHelper(context.applicationContext, DB_NAME, null, DB_VERSION) {

    init {
        setWriteAheadLoggingEnabled(true)
    }

    override fun onConfigure(db: SQLiteDatabase) {
        db.setForeignKeyConstraintsEnabled(false)
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE servers(
                key TEXT PRIMARY KEY,
                link TEXT NOT NULL,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                transport TEXT NOT NULL,
                security TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                country TEXT NOT NULL,
                source TEXT NOT NULL,
                favorite INTEGER NOT NULL DEFAULT 0,
                delay_ms INTEGER NOT NULL DEFAULT -1,
                tested_at INTEGER NOT NULL DEFAULT 0,
                alive_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL
            )""",
        )
        db.execSQL("CREATE INDEX servers_country ON servers(country)")
        db.execSQL("CREATE INDEX servers_source ON servers(source)")
        db.execSQL(
            """CREATE TABLE history(
                network TEXT NOT NULL,
                key TEXT NOT NULL,
                score REAL NOT NULL,
                last_ok INTEGER NOT NULL,
                PRIMARY KEY(network, key)
            ) WITHOUT ROWID""",
        )
        db.execSQL("CREATE INDEX history_rank ON history(network, score DESC)")
        db.execSQL(
            """CREATE TABLE subscriptions(
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL DEFAULT 0,
                count INTEGER NOT NULL DEFAULT 0
            )""",
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Version 1 is the first schema; future migrations go here, step by step.
    }

    // ------------------------------------------------------------------ reads

    fun all(): List<Server> = query("SELECT * FROM servers ORDER BY favorite DESC, CASE WHEN delay_ms < 0 THEN 1 ELSE 0 END, delay_ms ASC")

    fun byKey(key: String): Server? =
        query("SELECT * FROM servers WHERE key = ?", arrayOf(key)).firstOrNull()

    fun byKeys(keys: Collection<String>): List<Server> {
        if (keys.isEmpty()) return emptyList()
        val placeholders = keys.joinToString(",") { "?" }
        return query("SELECT * FROM servers WHERE key IN ($placeholders)", keys.toTypedArray())
    }

    fun userServers(): List<Server> =
        query("SELECT * FROM servers WHERE source = ? OR source LIKE 'sub:%' ORDER BY favorite DESC, name", arrayOf(Server.SOURCE_USER))

    /** One subscription's configs, the ones that answered last time first. */
    fun inSubscription(id: String): List<Server> =
        query(
            "SELECT * FROM servers WHERE source = ? ORDER BY CASE WHEN delay_ms < 0 THEN 1 ELSE 0 END, delay_ms",
            arrayOf(Server.SOURCE_SUB_PREFIX + id),
        )

    fun inCountry(code: String): List<Server> =
        query("SELECT * FROM servers WHERE country = ? ORDER BY CASE WHEN delay_ms < 0 THEN 1 ELSE 0 END, delay_ms", arrayOf(code))

    /** The configs that worked best on this network, most reliable first. */
    fun historyLinks(network: String, limit: Int): List<String> {
        val out = ArrayList<String>(limit)
        readableDatabase.rawQuery(
            """SELECT s.link FROM history h JOIN servers s ON s.key = h.key
               WHERE h.network = ? ORDER BY h.score DESC, h.last_ok DESC LIMIT ?""",
            arrayOf(network, limit.toString()),
        ).use { c -> while (c.moveToNext()) out += c.getString(0) }
        return out
    }

    fun subscriptions(): List<Subscription> {
        val out = ArrayList<Subscription>()
        readableDatabase.rawQuery("SELECT id,name,url,enabled,updated_at,count FROM subscriptions ORDER BY name", null).use { c ->
            while (c.moveToNext()) {
                out += Subscription(c.getString(0), c.getString(1), c.getString(2), c.getInt(3) != 0, c.getLong(4), c.getInt(5))
            }
        }
        return out
    }

    fun count(): Int = readableDatabase.rawQuery("SELECT COUNT(*) FROM servers", null).use { c ->
        if (c.moveToFirst()) c.getInt(0) else 0
    }

    // ----------------------------------------------------------------- writes

    /** Insert or refresh descriptive fields; keeps favourite/stats of an existing row. */
    fun upsert(servers: Collection<Server>) {
        if (servers.isEmpty()) return
        val db = writableDatabase
        val now = System.currentTimeMillis()
        db.beginTransaction()
        try {
            for (s in servers) {
                val values = ContentValues(12).apply {
                    put("key", s.key); put("link", s.link); put("name", s.name)
                    put("protocol", s.protocol); put("transport", s.transport); put("security", s.security)
                    put("host", s.host); put("port", s.port); put("country", s.country); put("source", s.source)
                    put("first_seen", now)
                }
                val inserted = db.insertWithOnConflict("servers", null, values, SQLiteDatabase.CONFLICT_IGNORE)
                if (inserted == -1L) {
                    // Existing row: refresh what the link says, never downgrade a user config to a feed one.
                    values.remove("first_seen"); values.remove("key")
                    if (s.source.startsWith(Server.SOURCE_FEED_PREFIX)) values.remove("source")
                    db.update("servers", values, "key = ?", arrayOf(s.key))
                }
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    /** Record a test result, and credit/debit the per-network history. */
    fun recordResult(key: String, delayMs: Int, network: String?) {
        val db = writableDatabase
        val now = System.currentTimeMillis()
        db.beginTransaction()
        try {
            if (delayMs >= 0) {
                db.execSQL(
                    "UPDATE servers SET delay_ms = ?, tested_at = ?, alive_count = alive_count + 1 WHERE key = ?",
                    arrayOf<Any>(delayMs, now, key),
                )
                if (network != null) {
                    // Older scores decay on every new result so recent behaviour
                    // dominates; faster answers earn more. UPDATE-then-INSERT
                    // rather than UPSERT: SQLite only gained UPSERT in 3.24,
                    // which Android ships from API 30.
                    val score = successScore(delayMs)
                    val updated = db.compileStatement(
                        "UPDATE history SET score = score * 0.5 + ?, last_ok = ? WHERE network = ? AND key = ?",
                    ).apply {
                        bindDouble(1, score); bindLong(2, now); bindString(3, network); bindString(4, key)
                    }.executeUpdateDelete()
                    if (updated == 0) {
                        db.insert("history", null, ContentValues(4).apply {
                            put("network", network); put("key", key); put("score", score); put("last_ok", now)
                        })
                    }
                }
            } else {
                db.execSQL(
                    "UPDATE servers SET delay_ms = -1, tested_at = ?, fail_count = fail_count + 1 WHERE key = ?",
                    arrayOf<Any>(now, key),
                )
                if (network != null) {
                    db.execSQL("UPDATE history SET score = score * 0.25 WHERE network = ? AND key = ?", arrayOf(network, key))
                }
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun setFavorite(key: String, favorite: Boolean) {
        writableDatabase.execSQL("UPDATE servers SET favorite = ? WHERE key = ?", arrayOf<Any>(if (favorite) 1 else 0, key))
    }

    fun delete(keys: Collection<String>) {
        if (keys.isEmpty()) return
        val db = writableDatabase
        db.beginTransaction()
        try {
            for (k in keys) {
                db.delete("servers", "key = ?", arrayOf(k))
                db.delete("history", "key = ?", arrayOf(k))
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun upsertSubscription(sub: Subscription) {
        writableDatabase.insertWithOnConflict(
            "subscriptions", null,
            ContentValues().apply {
                put("id", sub.id); put("name", sub.name); put("url", sub.url)
                put("enabled", if (sub.enabled) 1 else 0); put("updated_at", sub.updatedAt); put("count", sub.count)
            },
            SQLiteDatabase.CONFLICT_REPLACE,
        )
    }

    fun deleteSubscription(id: String) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            db.delete("subscriptions", "id = ?", arrayOf(id))
            db.delete("servers", "source = ? AND favorite = 0", arrayOf(Server.SOURCE_SUB_PREFIX + id))
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    /**
     * Keep the table bounded: discovered configs beyond [maxDiscovered] are
     * evicted, least reliable first. Favourites and the user's own configs are
     * never evicted.
     */
    fun prune(maxDiscovered: Int = MAX_DISCOVERED) {
        writableDatabase.execSQL(
            """DELETE FROM servers WHERE key IN (
                 SELECT key FROM servers
                 WHERE favorite = 0 AND source LIKE 'feed:%'
                 ORDER BY alive_count - fail_count DESC, tested_at DESC
                 LIMIT -1 OFFSET ?)""",
            arrayOf(maxDiscovered),
        )
        writableDatabase.execSQL("DELETE FROM history WHERE key NOT IN (SELECT key FROM servers)")
    }

    // ---------------------------------------------------------------- helpers

    private fun query(sql: String, args: Array<String>? = null): List<Server> {
        val out = ArrayList<Server>()
        readableDatabase.rawQuery(sql, args).use { c ->
            val idx = Columns(c)
            while (c.moveToNext()) out += idx.read(c)
        }
        return out
    }

    private class Columns(c: Cursor) {
        val key = c.getColumnIndexOrThrow("key")
        val link = c.getColumnIndexOrThrow("link")
        val name = c.getColumnIndexOrThrow("name")
        val protocol = c.getColumnIndexOrThrow("protocol")
        val transport = c.getColumnIndexOrThrow("transport")
        val security = c.getColumnIndexOrThrow("security")
        val host = c.getColumnIndexOrThrow("host")
        val port = c.getColumnIndexOrThrow("port")
        val country = c.getColumnIndexOrThrow("country")
        val source = c.getColumnIndexOrThrow("source")
        val favorite = c.getColumnIndexOrThrow("favorite")
        val delay = c.getColumnIndexOrThrow("delay_ms")
        val tested = c.getColumnIndexOrThrow("tested_at")
        val alive = c.getColumnIndexOrThrow("alive_count")
        val fail = c.getColumnIndexOrThrow("fail_count")

        fun read(c: Cursor) = Server(
            key = c.getString(key), link = c.getString(link), name = c.getString(name),
            protocol = c.getString(protocol), transport = c.getString(transport), security = c.getString(security),
            host = c.getString(host), port = c.getInt(port), country = c.getString(country), source = c.getString(source),
            favorite = c.getInt(favorite) != 0, delayMs = c.getInt(delay), lastTestedAt = c.getLong(tested),
            aliveCount = c.getInt(alive), failCount = c.getInt(fail),
        )
    }

    companion object {
        private const val DB_NAME = "servers.db"
        private const val DB_VERSION = 1
        const val MAX_DISCOVERED = 2000

        /** Faster answers earn more; any success earns at least 1. */
        fun successScore(delayMs: Int): Double = 1.0 + 1000.0 / (delayMs.coerceAtLeast(50) + 250.0)

        @Volatile private var instance: ServerStore? = null
        fun get(context: Context): ServerStore =
            instance ?: synchronized(this) { instance ?: ServerStore(context).also { instance = it } }
    }
}

data class Subscription(
    val id: String,
    val name: String,
    val url: String,
    val enabled: Boolean,
    val updatedAt: Long,
    val count: Int,
)
