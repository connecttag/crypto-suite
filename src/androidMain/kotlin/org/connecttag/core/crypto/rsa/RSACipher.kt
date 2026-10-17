package org.connecttag.core.crypto.rsa

public class RSACipher {
    private var privateKey: String? = null

    public fun setPrivateKey(key: String) {
        privateKey = key
    }

    public fun encrypt(plainText: String, publicKey: String): String? {
        return RsaUtils.encrypt(plainText, publicKey)
    }

    public fun decrypt(encryptedBase64Data: String, privateKeyOverride: String? = null): String? {
        val effectivePrivateKey = privateKeyOverride ?: privateKey ?: return null
        return RsaUtils.decrypt(encryptedBase64Data, effectivePrivateKey)
    }
}
