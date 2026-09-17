package org.microg.gms.constellation.core.verification.ts43

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** The framed, mandatory attributes of an EAP-Request/AKA-Challenge. */
internal data class EapAkaChallenge(
    val packet: ByteArray,
    val id: Byte,
    val rand: ByteArray,
    val autn: ByteArray,
    private val macValueOffset: Int
) {
    fun hasValidMac(kAut: ByteArray): Boolean {
        if (kAut.size != 16) return false
        val received = packet.copyOfRange(macValueOffset, macValueOffset + 16)
        val authenticated = packet.copyOf()
        authenticated.fill(0, macValueOffset, macValueOffset + 16)
        val expected = try {
            Mac.getInstance("HmacSHA1").apply {
                init(SecretKeySpec(kAut, "HmacSHA1"))
            }.doFinal(authenticated).copyOf(16)
        } catch (_: java.security.GeneralSecurityException) {
            return false
        }
        return MessageDigest.isEqual(received, expected)
    }

    companion object {
        fun parse(raw: ByteArray): EapAkaChallenge? {
            if (raw.size < 8) return null
            val length = ((raw[2].toInt() and 255) shl 8) or (raw[3].toInt() and 255)
            if (length < 8 || length > raw.size) return null
            // RFC 3748: octets beyond the EAP Length field are link padding.
            val packet = raw.copyOf(length)
            if (packet[0].toInt() != 1 || packet[4].toInt() != 23 || packet[5].toInt() != 1) return null
            var rand: ByteArray? = null
            var autn: ByteArray? = null
            var macOffset: Int? = null
            var offset = 8
            while (offset < length) {
                if (length - offset < 4) return null
                val type = packet[offset].toInt() and 255
                val attrLength = (packet[offset + 1].toInt() and 255) * 4
                if (attrLength < 4 || attrLength > length - offset) return null
                when (type) {
                    1 -> {
                        if (attrLength != 20 || rand != null) return null
                        rand = packet.copyOfRange(offset + 4, offset + 20)
                    }
                    2 -> {
                        if (attrLength != 20 || autn != null) return null
                        autn = packet.copyOfRange(offset + 4, offset + 20)
                    }
                    11 -> {
                        if (attrLength != 20 || macOffset != null) return null
                        macOffset = offset + 4
                    }
                    // RFC 4187 section 8.2: only unknown skippable attributes may be ignored.
                    else -> if (type < 128) return null
                }
                offset += attrLength
            }
            return EapAkaChallenge(packet, packet[1], rand ?: return null,
                autn ?: return null, macOffset ?: return null)
        }
    }
}
