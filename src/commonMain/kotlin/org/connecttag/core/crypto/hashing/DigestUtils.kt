package org.connecttag.core.crypto.hashing

public expect object DigestUtils {
    public val MD5: String
    public val SHA1: String
    public val SHA256: String

    public fun digest(bytes: ByteArray): String
    public fun digest(bytes: ByteArray, algorithm: String): String
    public fun md5(bytes: ByteArray): String
    public fun sha1(bytes: ByteArray): String
    public fun sha256(bytes: ByteArray): String
}
