package com.dingoberry.netdatagram

/**
 * 字节偏移
 */
abstract class DataOffset(private val offset: Int) {

    protected val Byte.offset
        get() = this offset this@DataOffset.offset

    companion object {
        internal infix fun Byte.offset(offset: Int) = this + offset
    }
}