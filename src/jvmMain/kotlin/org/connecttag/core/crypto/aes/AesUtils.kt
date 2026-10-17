package org.connecttag.core.crypto.aes

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Generic AES utilities migrated from hajah and modernized.
 */
public object AesUtils {
    private const val AES_ALGORITHM = "AES"
    private const val DEFAULT_TRANSFORMATION = "AES/CBC/PKCS5Padding"
    private const val IV_LENGTH = 16

    /**
     * Encrypts the [data] using the provided [secretKey] and [iv].
     * If [iv] is null, a random one will be generated and prepended to the result.
     * Result is Base64 encoded.
     */
    public fun encrypt(
        data: String,
        secretKey: String,
        iv: String? = null,
        transformation: String = DEFAULT_TRANSFORMATION,
    ): String? {
        return try {
            val keySpec = generateKeySpec(secretKey)
            val ivBytes = iv?.toByteArray(Charsets.UTF_8) ?: ByteArray(IV_LENGTH).apply {
                SecureRandom().nextBytes(this)
            }
            val ivSpec = IvParameterSpec(ivBytes)

            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
            val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

            val result = if (iv == null) {
                ivBytes + encrypted
            } else {
                encrypted
            }
            Base64.getEncoder().encodeToString(result)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Decrypts the [base64Data] using the provided [secretKey].
     * If [iv] is provided, it is used directly. Otherwise, it is assumed to be prepended to the data.
     */
    public fun decrypt(
        base64Data: String,
        secretKey: String,
        iv: String? = null,
        transformation: String = DEFAULT_TRANSFORMATION,
    ): String? {
        return try {
            val keySpec = generateKeySpec(secretKey)
            val decoded = Base64.getDecoder().decode(base64Data)

            val (ivSpec, encryptedData) = if (iv != null) {
                IvParameterSpec(iv.toByteArray(Charsets.UTF_8)) to decoded
            } else {
                val ivBytes = decoded.copyOfRange(0, IV_LENGTH)
                val data = decoded.copyOfRange(IV_LENGTH, decoded.size)
                IvParameterSpec(ivBytes) to data
            }

            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            val decrypted = cipher.doFinal(encryptedData)
            String(decrypted, Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Generates a random AES key of specified [keySize].
     */
    public fun generateKey(keySize: Int = 256): String {
        val keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM)
        keyGenerator.init(keySize)
        val secretKey = keyGenerator.generateKey()
        return Base64.getEncoder().encodeToString(secretKey.encoded)
    }

    private fun generateKeySpec(secretKey: String): SecretKeySpec {
        val digest = MessageDigest.getInstance("SHA-256")
        val keyBytes = digest.digest(secretKey.toByteArray(Charsets.UTF_8))
        return SecretKeySpec(keyBytes, AES_ALGORITHM)
    }
}
