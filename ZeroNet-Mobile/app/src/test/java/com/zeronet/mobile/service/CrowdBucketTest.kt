package com.zeronet.mobile.service

import org.junit.Assert.assertEquals
import org.junit.Test

class CrowdBucketTest {

    @Test
    fun `delays leave the phone rounded, with the relay's buckets`() {
        mapOf(0 to 0, 4 to 0, 34 to 30, 99 to 100, 187 to 200, 1_377 to 1_500, 1_374 to 1_250, 90_000 to 60_000, -5 to 0)
            .forEach { (ms, bucket) -> assertEquals("$ms", bucket, Crowd.bucketMs(ms)) }
    }
}
