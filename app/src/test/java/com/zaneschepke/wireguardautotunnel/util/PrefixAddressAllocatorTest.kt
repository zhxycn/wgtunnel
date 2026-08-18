package com.zaneschepke.wireguardautotunnel.util

import java.math.BigInteger
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PrefixAddressAllocatorTest {
    @Test
    fun `creates host addresses from IPv4 and IPv6 prefixes`() {
        val allocated =
            PrefixAddressAllocator.apply(
                addresses = "10.0.0.2/32, 2001:db8:ffff::1/128",
                prefixes = "192.168.1.0/24, 2001:db8:1::/64",
            )!!

        val entries = allocated.split(", ")
        assertEquals(2, entries.size)
        val ipv4 = entries.first { ':' !in it }
        val ipv6 = entries.first { ':' in it }

        assertEquals(32, ipv4.substringAfter('/').toInt())
        assertEquals(128, ipv6.substringAfter('/').toInt())
        assertInPrefix(ipv4.substringBefore('/'), "192.168.1.0", 24)
        assertInPrefix(ipv6.substringBefore('/'), "2001:db8:1::", 64)
        assertFalse(ipv4.endsWith(".0/32") || ipv4.endsWith(".255/32"))
        assertNotEquals(
            BigInteger.ZERO,
            BigInteger(1, InetAddress.getByName(ipv6.substringBefore('/')).address)
                .and(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `rejects prefixes without host addresses`() {
        PrefixAddressAllocator.apply(null, "192.168.1.1/32")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `rejects non-numeric prefix lengths`() {
        PrefixAddressAllocator.validate("192.168.1.0/not-a-number")
    }

    @Test
    fun `allocation replaces a manually configured host address`() {
        val allocated =
            PrefixAddressAllocator.apply(
                addresses = "203.0.113.7/32",
                prefixes = "192.168.1.0/24",
            )!!

        assertFalse(allocated == "203.0.113.7/32")
        assertInPrefix(allocated.substringBefore('/'), "192.168.1.0", 24)
    }

    @Test
    fun `creates an address for every configured prefix`() {
        val allocated =
            PrefixAddressAllocator.apply(
                addresses = "203.0.113.7/32, 2001:db8:ffff::1/128",
                prefixes =
                    "192.168.1.0/24, 198.51.100.0/24, 2001:db8:1::/64, 2001:db8:2::/64",
            )!!

        val ipv4 = allocated.split(", ").filter { ':' !in it }
        val ipv6 = allocated.split(", ").filter { ':' in it }

        assertEquals(2, ipv4.size)
        assertEquals(2, ipv6.size)
        assertTrue(ipv4.any { assertMatchesPrefix(it, "192.168.1.0", 24) })
        assertTrue(ipv4.any { assertMatchesPrefix(it, "198.51.100.0", 24) })
        assertTrue(ipv6.any { assertMatchesPrefix(it, "2001:db8:1::", 64) })
        assertTrue(ipv6.any { assertMatchesPrefix(it, "2001:db8:2::", 64) })
    }

    private fun assertInPrefix(address: String, prefix: String, bits: Int) {
        val mask =
            BigInteger.ONE.shiftLeft(InetAddress.getByName(address).address.size * 8)
                .subtract(BigInteger.ONE)
                .shiftRight(InetAddress.getByName(address).address.size * 8 - bits)
                .shiftLeft(InetAddress.getByName(address).address.size * 8 - bits)
        assertEquals(
            BigInteger(1, InetAddress.getByName(prefix).address).and(mask),
            BigInteger(1, InetAddress.getByName(address).address).and(mask),
        )
    }

    private fun assertMatchesPrefix(address: String, prefix: String, bits: Int): Boolean {
        return runCatching { assertInPrefix(address.substringBefore('/'), prefix, bits) }.isSuccess
    }
}
