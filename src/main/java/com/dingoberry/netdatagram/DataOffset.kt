package com.dingoberry.netdatagram

abstract class DataOffset(private val offset: Int) {

    protected val Byte.offset
        get() = this + this@DataOffset.offset
}