package org.connecttag.core.crypto.hashing

import java.io.File
import java.io.InputStream
import java.security.MessageDigest

public actual object DigestUtils {
    public actual val MD5: String = "MD5"
    public actual val SHA1: String = "SHA-1"
    public actual val SHA256: String = "SHA-256"

    public actual fun digest(bytes: ByteArray): String = digest(bytes, SHA256)

    public actual fun digest(bytes: ByteArray, algorithm: String): String =
        MessageDigest.getInstance(algorithm).digest(bytes).toHexString()

    public fun digest(inputStream: InputStream, algorithm: String = SHA256): String {
        val messageDigest = MessageDigest.getInstance(algorithm)
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        inputStream.use { stream ->
            while (true) {
                val read = stream.read(buffer)
                if (read == -1) {
                    break
                }
                messageDigest.update(buffer, 0, read)
            }
        }
        return messageDigest.digest().toHexString()
    }

    public fun digest(file: File, algorithm: String = SHA256): String =
        file.inputStream().use { digest(it, algorithm) }

    public actual fun md5(bytes: ByteArray): String = digest(bytes, MD5)
    public actual fun sha1(bytes: ByteArray): String = digest(bytes, SHA1)
    public actual fun sha256(bytes: ByteArray): String = digest(bytes, SHA256)
    public fun md5(inputStream: InputStream): String = digest(inputStream, MD5)
    public fun sha1(inputStream: InputStream): String = digest(inputStream, SHA1)
    public fun sha256(inputStream: InputStream): String = digest(inputStream, SHA256)
    public fun md5(file: File): String = digest(file, MD5)
    public fun sha1(file: File): String = digest(file, SHA1)
    public fun sha256(file: File): String = digest(file, SHA256)

    private fun ByteArray.toHexString(): String = joinToString(separator = "") { byte -> "%02x".format(byte) }
}
