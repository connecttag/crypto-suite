package org.connecttag.core.crypto.hashing

/**
 * Generic hashing utilities shared by supported KMP targets.
 */
public expect object HashUtils {
    /**
     * Hashes the given [input] string using SHA-256 and returns the hex string representation.
     */
    public fun sha256(input: String): String

    /**
     * Compatibility alias for callers that hash password payloads before transport.
     */
    public fun hashPassword(password: String): String

    /**
     * Hashes the given [input] string using SHA-1 and returns the hex string representation.
     */
    public fun sha1(input: String): String
}
