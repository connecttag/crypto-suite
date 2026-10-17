package org.connecttag.core.crypto

import org.connecttag.core.crypto.aes.AESCipher
import org.connecttag.core.crypto.aes.AesUtils
import org.connecttag.core.crypto.broadcast.BroadcastCryptoUtils
import org.connecttag.core.crypto.encoding.Base64Utils
import org.connecttag.core.crypto.hashing.DigestUtils
import org.connecttag.core.crypto.hashing.HashUtils
import org.connecttag.core.crypto.rsa.RsaUtils
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CryptoSuiteJvmTest {
    @Test
    fun base64RoundTripsStringsAndBytes() {
        val text = "ConnectTag"
        val bytes = byteArrayOf(0, 1, 2, 127, -1)

        assertEquals(text, Base64Utils.decode(Base64Utils.encode(text)))
        assertContentEquals(bytes, Base64Utils.decodeToBytes(Base64Utils.encode(bytes)))
    }

    @Test
    fun digestHelpersReturnStableHex() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            HashUtils.sha256("abc"),
        )
        assertEquals(
            "a9993e364706816aba3e25717850c26c9cd0d89d",
            DigestUtils.sha1("abc".toByteArray(Charsets.UTF_8)),
        )
    }

    @Test
    fun aesUtilitiesRoundTripText() {
        val secret = "local-test-secret"
        val encrypted = AesUtils.encrypt(data = "payload", secretKey = secret)

        assertNotNull(encrypted)
        assertEquals("payload", AesUtils.decrypt(base64Data = encrypted, secretKey = secret))
    }

    @Test
    fun aesCipherRoundTripsTextWithHexKey() {
        val cipher = AESCipher()
        val hexKey = "000102030405060708090a0b0c0d0e0f"

        val encrypted = cipher.encrypt("payload", hexKey)
        val decrypted = cipher.decrypt(Base64Utils.encode(encrypted), hexKey)

        assertEquals("payload", decrypted)
    }

    @Test
    fun rsaUtilitiesRoundTripText() {
        val pair = assertNotNull(RsaUtils.generateKeyPair())
        val publicKey = Base64Utils.encode(pair.public.encoded)
        val privateKey = Base64Utils.encode(pair.private.encoded)

        val encrypted = assertNotNull(RsaUtils.encrypt("payload", publicKey))
        val decrypted = RsaUtils.decrypt(encrypted, privateKey)

        assertEquals("payload", decrypted)
    }

    @Test
    fun broadcastHelpersSignVerifyAndEncrypt() {
        val signature = BroadcastCryptoUtils.hmacSign(payload = "payload", key = "secret")

        assertTrue(BroadcastCryptoUtils.verifyHmac("payload", "secret", signature))
        assertFalse(BroadcastCryptoUtils.verifyHmac("payload", "wrong-secret", signature))

        val encrypted = BroadcastCryptoUtils.aesGcmEncrypt(plain = "payload", secret = "secret")

        assertEquals("payload", BroadcastCryptoUtils.aesGcmDecrypt(encrypted, "secret"))
    }
}
