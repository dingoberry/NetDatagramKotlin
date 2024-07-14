package com.dingoberry.netdatagram



fun ByteArray.update2Bytes(offset: Int, value: Int) = (value and 0xFFFF).let {
    this[offset] = (it shr 8).toByte()
    this[offset + 1] = (it and 0xFF).toByte()
}

fun ByteArray.update4Bytes(offset: Int, value: Int) {
    this[offset] = (value shr 24 and 0xFF).toByte()
    this[offset + 1] = (value shr 16 and 0xFF).toByte()
    this[offset + 2] = (value shr 8 and 0xFF).toByte()
    this[offset + 3] = (value and 0xFF).toByte()
}

infix fun Byte.int(low: Byte) =
    ((this.toInt() and 0xFF shl 8)
            or
            (low.toInt() and 0xFF))

fun ByteArray.resolve2Bytes(offset: Int) =
    this[offset] int this[offset + 1]

fun ByteArray.resolve4Bytes(offset: Int) =
    ((this[offset].toInt() and 0xFF shl 24)
            or
            (this[offset + 1].toInt() and 0xFF shl 16)
            or
            (this[offset + 2].toInt() and 0xFF shl 8)
            or
            (this[offset + 3].toInt() and 0xFF))


