package com.zeronet.mobile.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ConnectTargetTest {

    /** A target saved before several lists could be chosen reads back as it was. */
    @Test
    fun `one list saved the old way still reads as that list`() {
        assertEquals(ConnectTarget.Subscription("abc"), ConnectTarget.decode("sub:abc"))
        assertEquals("sub:abc", ConnectTarget.Subscription("abc").encode())
    }

    @Test
    fun `several lists save and read back in one order whatever order they were chosen in`() {
        val target = ConnectTarget.Subscription.of(listOf("b", "a", "b", " "))!!
        assertEquals(listOf("a", "b"), target.ids)
        assertEquals("sub:a,b", target.encode())
        assertEquals(target, ConnectTarget.decode("sub:b,a"))
    }

    @Test
    fun `no list left is no list target`() {
        assertNull(ConnectTarget.Subscription.of(emptyList()))
        assertEquals(ConnectTarget.Fastest, ConnectTarget.decode("sub:"))
        assertEquals(ConnectTarget.Fastest, ConnectTarget.decode("sub:,"))
    }
}
