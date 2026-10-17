package org.connecttag.core.crypto.rsa

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher

/**
 * Generic RSA utilities migrated from hajah.
 */
public object RsaUtils {
    private const val ALGORITHM = "RSA"
    private const val DEFAULT_TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    private const val DEFAULT_KEY_SIZE = 2048

    /**
     * Encrypts the [data] using the provided [publicKeyString] (Base64).
     */
    public fun encrypt(
        data: String,
        publicKeyString: String,
        transformation: String = DEFAULT_TRANSFORMATION,
    ): String? {
        return try {
            val publicKey = getPublicKey(publicKeyString)
            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            val encryptedBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
            Base64.getEncoder().encodeToString(encryptedBytes)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Encrypts large data by splitting it into chunks.
     */
    public fun encryptLarge(
        data: String,
        publicKeyString: String,
        chunkSize: Int = 245,
        transformation: String = DEFAULT_TRANSFORMATION
    ): String? {
        return try {
            data.toByteArray(Charsets.UTF_8)
                .asSequence()
                .chunked(chunkSize)
                .map { it.toByteArray() }
                .map { encrypt(String(it), publicKeyString, transformation) }
                .filterNotNull()
                .joinToString(separator = ".")
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Decrypts the [base64Data] using the provided [privateKeyString] (Base64).
     */
    public fun decrypt(
        base64Data: String,
        privateKeyString: String,
        transformation: String = DEFAULT_TRANSFORMATION,
    ): String? {
        return try {
            val privateKey = getPrivateKey(privateKeyString)
            val cipher = Cipher.getInstance(transformation)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            val decodedBytes = Base64.getDecoder().decode(base64Data)
            val decryptedBytes = cipher.doFinal(decodedBytes)
            String(decryptedBytes, Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Decrypts large data that was encrypted in chunks.
     */
    public fun decryptLarge(
        encryptedData: String,
        privateKeyString: String,
        transformation: String = DEFAULT_TRANSFORMATION
    ): String? {
        return try {
            encryptedData.split(".")
                .map { decrypt(it, privateKeyString, transformation) }
                .filterNotNull()
                .joinToString("")
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Generates an RSA key pair.
     */
    public fun generateKeyPair(keySize: Int = DEFAULT_KEY_SIZE): KeyPair? {
        return try {
            val generator = KeyPairGenerator.getInstance(ALGORITHM)
            generator.initialize(keySize, SecureRandom())
            generator.generateKeyPair()
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Data class for encoded RSA key pair.
     */
    public data class EncodedRSAKeyPair(
        val publicKey: String,
        val privateKey: String
    )

    /**
     * Generates an RSA key pair and returns them Base64 encoded.
     */
    public fun generateEncodedKeyPair(keySize: Int = DEFAULT_KEY_SIZE): EncodedRSAKeyPair? {
        val keyPair = generateKeyPair(keySize) ?: return null
        val publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        val privateKey = Base64.getEncoder().encodeToString(keyPair.private.encoded)
        return EncodedRSAKeyPair(publicKey, privateKey)
    }

    private fun getPublicKey(publicKeyString: String): PublicKey {
        val keyBytes = Base64.getDecoder().decode(publicKeyString.cleanKey())
        val keySpec = X509EncodedKeySpec(keyBytes)
        return KeyFactory.getInstance(ALGORITHM).generatePublic(keySpec)
    }

    private fun getPrivateKey(privateKeyString: String): PrivateKey {
        val keyBytes = Base64.getDecoder().decode(privateKeyString.cleanKey())
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(keySpec)
    }

    private fun String.cleanKey(): String {
        return this.replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .replace("-----END RSA PUBLIC KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\n", "")
            .replace("\r", "")
            .trim()
    }
}
