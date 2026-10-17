package org.connecttag.core.crypto.encoding

/**
 * Common Base64 utilities for shared crypto helpers.
 */
public object Base64Utils {
    private const val ENCODE_TABLE: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    private val decodeTable: IntArray = IntArray(128) { -1 }.also { table ->
        ENCODE_TABLE.forEachIndexed { index, character -> table[character.code] = index }
    }

    /**
     * Encodes the given [input] string to Base64.
     */
    public fun encode(input: String): String {
        return runCatching {
            encode(input.toByteArray(Charsets.UTF_8))
        }.getOrDefault("")
    }

    /**
     * Decodes the given [input] Base64 string back to its original UTF-8 string.
     */
    public fun decode(input: String): String {
        return runCatching {
            String(decodeToBytes(input), Charsets.UTF_8)
        }.getOrDefault("")
    }

    /**
     * Encodes raw [bytes] to Base64.
     */
    public fun encode(bytes: ByteArray): String {
        if (bytes.isEmpty()) {
            return ""
        }

        val encoded = StringBuilder(((bytes.size + 2) / 3) * 4)
        var index = 0
        while (index < bytes.size) {
            val first = bytes[index++].toInt() and 0xFF
            val second = if (index < bytes.size) bytes[index++].toInt() and 0xFF else -1
            val third = if (index < bytes.size) bytes[index++].toInt() and 0xFF else -1

            encoded.append(ENCODE_TABLE[first shr 2])
            encoded.append(ENCODE_TABLE[((first and 0x03) shl 4) or (if (second >= 0) second shr 4 else 0)])
            encoded.append(if (second >= 0) ENCODE_TABLE[((second and 0x0F) shl 2) or (if (third >= 0) third shr 6 else 0)] else '=')
            encoded.append(if (third >= 0) ENCODE_TABLE[third and 0x3F] else '=')
        }
        return encoded.toString()
    }

    /**
     * Decodes [input] Base64 string to raw bytes.
     */
    public fun decodeToBytes(input: String): ByteArray {
        require(input.length % 4 == 0) { "Invalid Base64 length" }
        if (input.isEmpty()) {
            return ByteArray(0)
        }

        val padding = input.takeLastWhile { character -> character == '=' }.length
        require(padding <= 2) { "Invalid Base64 padding" }

        val output = ByteArray((input.length / 4) * 3 - padding)
        var inputIndex = 0
        var outputIndex = 0
        while (inputIndex < input.length) {
            val first = input.decodeValueAt(inputIndex++)
            val second = input.decodeValueAt(inputIndex++)
            val thirdChar = input[inputIndex++]
            val fourthChar = input[inputIndex++]
            val third = if (thirdChar == '=') 0 else thirdChar.decodeValue()
            val fourth = if (fourthChar == '=') 0 else fourthChar.decodeValue()

            if (outputIndex < output.size) {
                output[outputIndex++] = ((first shl 2) or (second shr 4)).toByte()
            }
            if (outputIndex < output.size) {
                output[outputIndex++] = (((second and 0x0F) shl 4) or (third shr 2)).toByte()
            }
            if (outputIndex < output.size) {
                output[outputIndex++] = (((third and 0x03) shl 6) or fourth).toByte()
            }
        }
        return output
    }

    private fun String.decodeValueAt(index: Int): Int = this[index].decodeValue()

    private fun Char.decodeValue(): Int {
        require(code < decodeTable.size) { "Invalid Base64 character" }
        val value = decodeTable[code]
        require(value >= 0) { "Invalid Base64 character" }
        return value
    }
}
