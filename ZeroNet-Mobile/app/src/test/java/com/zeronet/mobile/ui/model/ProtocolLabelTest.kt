package com.zeronet.mobile.ui.model

import org.junit.Assert.assertEquals
import org.junit.Test

class ProtocolLabelTest {
    @Test
    fun `every protocol the core can run has a proper name, not its raw spelling`() {
        val names = mapOf(
            "vless" to "VLESS", "vmess" to "VMess", "trojan" to "Trojan", "ss" to "Shadowsocks",
            "hysteria2" to "Hysteria 2", "hy2" to "Hysteria 2", "tuic" to "TUIC", "juicity" to "Juicity",
            "anytls" to "AnyTLS", "zerov1" to "ZeroV1", "masterdns" to "MasterDnsVPN", "socks" to "SOCKS5",
            "wireguard" to "WireGuard", "amnezia-wg" to "AmneziaWG", "warp" to "WARP", "tor" to "Tor",
            "freedom" to "Serverless",
        )
        names.forEach { (raw, shown) -> assertEquals(raw, shown, protocolLabel(raw)) }
        assertEquals("—", protocolLabel(""))
    }
}
