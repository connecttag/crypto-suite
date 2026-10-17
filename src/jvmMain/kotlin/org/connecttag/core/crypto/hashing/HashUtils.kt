package org.connecttag.core.crypto.hashing

import java.security.MessageDigest

/**
 * Generic hashing utilities migrated from hajah and expanded.
 */
public actual object HashUtils {
    /**
     * Hashes the given [input] string using SHA-256 and returns the hex string representation.
     */
    public actual fun sha256(input: String): String {
        val hashedBytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return hashedBytes.joinToString(separator = "") { "%02x".format(it) }
    }

    /**
     * Compatibility alias for callers that hash password payloads before transport.
     */
    public actual fun hashPassword(password: String): String {
        return sha256(password)
    }

    /**
     * Hashes the given [input] string using SHA-1 and returns the hex string representation.
     */
    public actual fun sha1(input: String): String {
        val hashedBytes = MessageDigest.getInstance("SHA-1").digest(input.toByteArray(Charsets.UTF_8))
        return hashedBytes.joinToString(separator = "") { "%02x".format(it) }
    }
}
