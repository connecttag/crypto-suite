package org.connecttag.core.crypto.broadcast

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

public object BroadcastCryptoUtils {
    private const val HMAC_ALGO = "HmacSHA256"
    private const val AES_ALGO = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    private const val IV_SIZE = 12

    public fun generateNonce(): String = Random.nextBytes(IV_SIZE).let { Base64.getEncoder().encodeToString(it) }

    public fun hmacSign(payload: String, key: String): String {
        val mac = Mac.getInstance(HMAC_ALGO)
        val secretKey = SecretKeySpec(key.toByteArray(Charsets.UTF_8), HMAC_ALGO)
        mac.init(secretKey)
        val signature = mac.doFinal(payload.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(signature)
    }

    public fun verifyHmac(payload: String, key: String, signatureBase64: String?): Boolean {
        if (signatureBase64 == null) {
            return false
        }
        return try {
            val expected = hmacSign(payload, key)
            MessageDigest.isEqual(
                Base64.getDecoder().decode(expected),
                Base64.getDecoder().decode(signatureBase64),
            )
        } catch (_: Exception) {
            false
        }
    }

    public fun aesGcmEncrypt(plain: String, secret: String): String {
        val keyBytes = deriveAesKey(secret)
        val key = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance(AES_ALGO)
        val iv = ByteArray(IV_SIZE)
        Random.nextBytes(iv)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        val cipherBytes = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(iv.size + cipherBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(cipherBytes, 0, combined, iv.size, cipherBytes.size)
        return Base64.getEncoder().encodeToString(combined)
    }

    public fun aesGcmDecrypt(base64: String, secret: String): String? {
        return try {
            val combined = Base64.getDecoder().decode(base64)
            val iv = combined.copyOfRange(0, IV_SIZE)
            val cipherBytes = combined.copyOfRange(IV_SIZE, combined.size)
            val keyBytes = deriveAesKey(secret)
            val key = SecretKeySpec(keyBytes, "AES")
            val cipher = Cipher.getInstance(AES_ALGO)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            val plain = cipher.doFinal(cipherBytes)
            String(plain, Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private fun deriveAesKey(secret: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(secret.toByteArray(Charsets.UTF_8))
    }
}
