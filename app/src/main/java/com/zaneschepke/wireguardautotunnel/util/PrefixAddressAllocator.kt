package com.zaneschepke.wireguardautotunnel.util

import inet.ipaddr.IPAddressString
import java.math.BigInteger
import java.net.InetAddress
import java.security.SecureRandom
import kotlin.math.max
import kotlin.math.min

object PrefixAddressAllocator {
    private val random = SecureRandom()

    fun apply(addresses: String?, prefixes: String?): String? {
        var result = addresses.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }

        parsedPrefixes(prefixes)
            .groupBy { it.family }
            .forEach { (family, values) -> result = replaceFamilyAddresses(result, family, values) }

        return result.joinToString(", ").ifBlank { null }
    }

    fun validate(prefixes: String?) {
        parsedPrefixes(prefixes)
    }

    private fun parsedPrefixes(prefixes: String?): List<ParsedPrefix> {
        return prefixes
            .orEmpty()
            .split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { prefix -> parse(prefix, familyOf(prefix), mustHaveHostBits = true) }
    }

    private fun replaceFamilyAddresses(
        addresses: List<String>,
        family: Family,
        prefixes: List<ParsedPrefix>,
    ): List<String> {
        return addresses.filterNot { address ->
            runCatching { parse(address, family, mustHaveHostBits = false) }.isSuccess
        } + prefixes.map { it.allocate() }
    }

    private fun familyOf(value: String): Family {
        val address = IPAddressString(value.substringBefore('/').trim()).hostAddress
        require(address != null) { "Invalid IP address" }
        return if (address.isIPv4) Family.IPV4 else Family.IPV6
    }

    private fun parse(value: String, family: Family, mustHaveHostBits: Boolean): ParsedPrefix {
        val parts = value.trim().split('/', limit = 2)
        require(parts.size == 2 && parts[0].isNotBlank()) { "A CIDR prefix is required" }

        val prefixLength = requireNotNull(parts[1].trim().toIntOrNull()) { "Invalid prefix length" }
        require(prefixLength in 0..family.bits) { "Invalid prefix length" }
        if (mustHaveHostBits)
            require(prefixLength < family.bits) { "The prefix has no host addresses" }

        val addressString = IPAddressString(parts[0].trim())
        require(addressString.isValid) { "Invalid IP address" }
        val address = requireNotNull(addressString.hostAddress) { "Invalid IP address" }
        require(address.isIPv4 == (family == Family.IPV4)) { "Incorrect IP address family" }

        val bytes = InetAddress.getByName(address.toNormalizedString()).address
        return ParsedPrefix(BigInteger(1, bytes), prefixLength, family)
    }

    private data class ParsedPrefix(
        val value: BigInteger,
        val prefixLength: Int,
        val family: Family,
    ) {
        private val hostBits
            get() = family.bits - prefixLength

        private val hostMask
            get() = BigInteger.ONE.shiftLeft(hostBits).subtract(BigInteger.ONE)

        private val network
            get() = value.and(hostMask.notWithin(family.bits))

        fun allocate(): String {
            var host: BigInteger
            do {
                host = BigInteger(hostBits, PrefixAddressAllocator.random)
            } while (
                host == BigInteger.ZERO ||
                    (family == Family.IPV4 && hostBits >= 2 && host == hostMask)
            )

            return network.or(host).toAddress(family) + "/${family.bits}"
        }
    }

    private fun BigInteger.notWithin(bits: Int): BigInteger {
        val allBits = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)
        return allBits.xor(this)
    }

    private fun BigInteger.toAddress(family: Family): String {
        val source = toByteArray()
        val result = ByteArray(family.byteLength)
        val sourceStart = max(0, source.size - result.size)
        val length = min(source.size, result.size)
        source.copyInto(result, destinationOffset = result.size - length, startIndex = sourceStart)
        return checkNotNull(InetAddress.getByAddress(result).hostAddress)
    }

    private enum class Family(val bits: Int, val byteLength: Int) {
        IPV4(32, 4),
        IPV6(128, 16),
    }
}
