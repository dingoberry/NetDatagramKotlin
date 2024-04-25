package com.dingoberry.netdatagram

fun ByteArray.resolve2Bytes(offset: Int) =
    ((this[offset].toInt() and 0xFF shl 8)
            or
            (this[offset + 1].toInt() and 0xFF))

fun ByteArray.resolve4Bytes(offset: Int) =
    ((this[offset].toInt() and 0xFF shl 24)
            or
            (this[offset + 1].toInt() and 0xFF shl 16)
            or
            (this[offset + 2].toInt() and 0xFF shl 8)
            or
            (this[offset + 3].toInt() and 0xFF))


