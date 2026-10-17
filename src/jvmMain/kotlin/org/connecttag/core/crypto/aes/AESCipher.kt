package org.connecttag.core.crypto.aes

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

public class AESCipher {
    public fun encrypt(plainText: String, aesKey: String): ByteArray {
        val keyBytes = aesKey.decodeHex()
        val key = SecretKeySpec(keyBytes, "AES")
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        val encryptedBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return iv + encryptedBytes
    }

    public fun decrypt(encryptedBase64Data: String, aesKey: String): String {
        val keyBytes = aesKey.decodeHex()
        val key = SecretKeySpec(keyBytes, "AES")
        val decodedBytes = Base64.getDecoder().decode(encryptedBase64Data)
        val ivBytes = decodedBytes.copyOfRange(0, 16)
        val encryptedData = decodedBytes.copyOfRange(16, decodedBytes.size)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(ivBytes))
        val decryptedBytes = cipher.doFinal(encryptedData)
        return String(decryptedBytes, Charsets.UTF_8)
    }

    private fun String.decodeHex(): ByteArray {
        check(length % 2 == 0) { "Must have an even length" }
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
