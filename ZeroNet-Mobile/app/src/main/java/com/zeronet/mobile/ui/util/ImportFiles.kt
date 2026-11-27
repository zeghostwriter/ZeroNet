package com.zeronet.mobile.ui.util

import android.content.Context
import android.net.Uri

/** The largest file read as a config: a subscription with thousands of nodes is a few MB. */
const val MAX_IMPORT_FILE_BYTES = 8 * 1024 * 1024

/**
 * The text of a file the user picked or another app handed over (a `content://`
 * or `file://` address), or null when it cannot be read or is not text.
 *
 * Any file is accepted whatever it is called: JSON configs arrive as
 * `application/json`, `text/plain`, `application/octet-stream` or with no type
 * at all, depending on the app that saved them. A UTF-8 byte-order mark is
 * dropped. A file past [MAX_IMPORT_FILE_BYTES] is refused rather than cut off,
 * since half a JSON document imports as nothing.
 */
fun readImportFile(context: Context, uri: Uri): String? = runCatching {
    context.contentResolver.openInputStream(uri)?.use { input ->
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            out.write(buffer, 0, read)
            if (out.size() > MAX_IMPORT_FILE_BYTES) return@runCatching null
        }
        out.toString("UTF-8").removePrefix("﻿")
    }
}.getOrNull()?.takeIf { it.isNotBlank() }
