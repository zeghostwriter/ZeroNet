package com.zeronet.mobile.data

import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Local IPv4 addresses other devices can reach this phone on: Wi-Fi, the
 * phone's own hotspot, USB/Bluetooth tethering. Loopback, the VPN's own TUN
 * and cellular interfaces are excluded — sharing over them is either
 * meaningless or unreachable.
 */
object LanAddresses {
    private val SHAREABLE = listOf("wlan", "ap", "swlan", "rndis", "usb", "bt-pan", "eth", "softap")

    fun list(): List<String> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback && !it.isVirtual && SHAREABLE.any { p -> it.name.startsWith(p) } }
            .flatMap { nic -> nic.inetAddresses.toList().filterIsInstance<Inet4Address>().map { it.hostAddress.orEmpty() } }
            .filter { it.isNotBlank() && !it.startsWith("172.19.0.") }
            .distinct()
    }.getOrDefault(emptyList())
}
