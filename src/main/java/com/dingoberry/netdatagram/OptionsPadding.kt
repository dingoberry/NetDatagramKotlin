package com.dingoberry.netdatagram

import kotlin.reflect.KProperty

/**
 * 可选项+填充
 */
internal class OptionsPadding(
    private val dataSource: ByteArray,
    private val offset: Int,
    private val headerLength: Int
) {
    @Throws(DataPacketException::class)
    operator fun getValue(thisRef: Any?, property: KProperty<*>): ByteArray =
        (headerLength - 20).takeIf { it >= 0 }?.let {
            dataSource.copyOfRange(offset, it)
        } ?: run { throw DataPacketException("invalid headerLength $headerLength!") }


    @Throws(DataPacketException::class)
    operator fun setValue(
        thisRef: Any?,
        property: KProperty<*>,
        array: ByteArray
    ) {
        val limit = headerLength - 20
        if (array.size <= limit) {
            ((array.size % 4).takeIf {
                it > 0
            }?.let {
                array.copyOf(array.size + it)
            } ?: array).apply {
                this.copyInto(dataSource, offset, 0, this.size)
            }
        } else if (limit <= 0) {
            throw DataPacketException("invalid headerLength $headerLength!")
        } else {
            throw DataPacketException("options must less than $limit bytes length!")
        }
    }
}
