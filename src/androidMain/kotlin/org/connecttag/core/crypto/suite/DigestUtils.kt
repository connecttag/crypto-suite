package org.connecttag.core.crypto.suite

import java.io.File
import java.io.InputStream

@Deprecated(
    message = "Use org.connecttag.core.crypto.hashing.DigestUtils instead.",
)
public object DigestUtils {
    public const val MD5: String = "MD5"
    public const val SHA1: String = "SHA-1"
    public const val SHA256: String = "SHA-256"

    public fun digest(bytes: ByteArray, algorithm: String = SHA256): String {
        return org.connecttag.core.crypto.hashing.DigestUtils.digest(bytes, algorithm)
    }

    public fun digest(inputStream: InputStream, algorithm: String = SHA256): String {
        return org.connecttag.core.crypto.hashing.DigestUtils.digest(inputStream, algorithm)
    }

    public fun digest(file: File, algorithm: String = SHA256): String {
        return org.connecttag.core.crypto.hashing.DigestUtils.digest(file, algorithm)
    }

    public fun md5(bytes: ByteArray): String = org.connecttag.core.crypto.hashing.DigestUtils.md5(bytes)
    public fun sha1(bytes: ByteArray): String = org.connecttag.core.crypto.hashing.DigestUtils.sha1(bytes)
    public fun sha256(bytes: ByteArray): String = org.connecttag.core.crypto.hashing.DigestUtils.sha256(bytes)
    public fun md5(inputStream: InputStream): String = org.connecttag.core.crypto.hashing.DigestUtils.md5(inputStream)
    public fun sha1(inputStream: InputStream): String = org.connecttag.core.crypto.hashing.DigestUtils.sha1(inputStream)
    public fun sha256(inputStream: InputStream): String = org.connecttag.core.crypto.hashing.DigestUtils.sha256(inputStream)
    public fun md5(file: File): String = org.connecttag.core.crypto.hashing.DigestUtils.md5(file)
    public fun sha1(file: File): String = org.connecttag.core.crypto.hashing.DigestUtils.sha1(file)
    public fun sha256(file: File): String = org.connecttag.core.crypto.hashing.DigestUtils.sha256(file)
}
