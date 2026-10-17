package org.connecttag.core.crypto.suite

@Deprecated(
    message = "Use org.connecttag.core.crypto.aes.AESCipher instead.",
)
public class AESCipher {
    private val delegate: org.connecttag.core.crypto.aes.AESCipher = org.connecttag.core.crypto.aes.AESCipher()

    public fun encrypt(plainText: String, aesKey: String): ByteArray {
        return delegate.encrypt(plainText, aesKey)
    }

    public fun decrypt(encryptedBase64Data: String, aesKey: String): String {
        return delegate.decrypt(encryptedBase64Data, aesKey)
    }
}
