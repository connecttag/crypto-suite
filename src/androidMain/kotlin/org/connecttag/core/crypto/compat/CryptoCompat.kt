package org.connecttag.core.crypto.compat

import android.util.Base64

/**
 * Compatibility utilities for legacy Hajah cryptographic operations.
 */
public object CryptoCompat {

    /**
     * XOR decrypts [obfuscatedInput] (Base64) using [key].
     */
    public fun xorDecrypt(obfuscatedInput: String, key: String): String? {
        return try {
            val obfuscatedBytes = Base64.decode(obfuscatedInput, Base64.DEFAULT)
            val keyBytes = key.toByteArray(Charsets.UTF_8)
            val outputBytes = ByteArray(obfuscatedBytes.size)

            for (i in obfuscatedBytes.indices) {
                outputBytes[i] = (obfuscatedBytes[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }

            String(outputBytes, Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Decodes Base64 [value] if [shouldDecode] is true. Falls back to original [value] on error.
     * Replaces Hajah's `CryptUtils.getDecBasToStr`.
     */
    public fun decodeBase64WithFallback(value: String, shouldDecode: Boolean): String {
        if (!shouldDecode) return value
        return try {
            val decodedBytes = Base64.decode(value, Base64.DEFAULT)
            String(decodedBytes, Charsets.UTF_8)
        } catch (_: Exception) {
            value
        }
    }

    /**
     * Legacy client decryption used in Hajah for API keys.
     */
    public fun decryptClientLegacy(
        strToDecrypt: String,
        sessionKey: String,
        iv: String = "rA5zE3G9F5X3T3H6"
    ): String? {
        return try {
            val decodedSessionKey = decodeBase64WithFallback(sessionKey, true)
            val keySpec = javax.crypto.spec.SecretKeySpec(decodedSessionKey.toByteArray(), "AES")
            val ivSpec = javax.crypto.spec.IvParameterSpec(iv.toByteArray())
            val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec)
            val decodedData = Base64.decode(strToDecrypt, Base64.DEFAULT)
            val decryptedBytes = cipher.doFinal(decodedData)
            String(decryptedBytes, Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }
}
