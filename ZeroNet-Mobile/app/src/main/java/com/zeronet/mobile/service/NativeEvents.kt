package com.zeronet.mobile.service

import com.zeronet.mobile.core.NativeListener
import com.zeronet.mobile.core.ZrayNative
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.channels.awaitClose
import org.json.JSONObject

/**
 * Runs a native job and exposes its events as a cold Flow of JSON objects.
 * Collecting starts the job; cancelling the collector cancels the job.
 *
 * Batches arrive on a Rust thread; they are split and handed to the channel
 * without blocking (trySend into an unlimited buffer — batches are already
 * rate-limited to ~10/s natively).
 */
internal fun nativeJob(start: (NativeListener) -> Long): Flow<JSONObject> = callbackFlow {
    val listener = NativeListener { batch ->
        var finished = false
        for (line in batch.lineSequence()) {
            if (line.isBlank()) continue
            val event = runCatching { JSONObject(line) }.getOrNull() ?: continue
            trySend(event)
            if (event.optString("t") == "done") finished = true
        }
        if (finished) channel.close()
    }
    val handle = start(listener)
    awaitClose { if (handle > 0) ZrayNative.cancel(handle) }
}.buffer(Channel.UNLIMITED)
