package org.connecttag.core.crypto.suite

@Deprecated(
    message = "Use org.connecttag.core.crypto.rsa.RSACipher instead.",
)
public class RSACipher {
    private val delegate: org.connecttag.core.crypto.rsa.RSACipher = org.connecttag.core.crypto.rsa.RSACipher()

    public fun setPrivateKey(key: String) {
        delegate.setPrivateKey(key)
    }

    public fun encrypt(plainText: String, publicKey: String): String? {
        return delegate.encrypt(plainText, publicKey)
    }

    public fun decrypt(encryptedBase64Data: String, privateKeyOverride: String? = null): String? {
        return delegate.decrypt(encryptedBase64Data, privateKeyOverride)
    }
}
