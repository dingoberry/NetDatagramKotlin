package com.dingoberry.netdatagram

import kotlin.reflect.KProperty

/**
 * 计算校验合
 */
internal class CheckSum(
    private val dataSource: ByteArray,
    private val calculateEnd: Int,
    private val offset: Int,
    private val checkSumIndex: Int,
    private val pseudoHeader: ByteArray? = null
) {

    private val checksum: Int
        get() {
            var sum = 0L
            var high: Byte = 0
            var low: Byte
            var isHigh = true

            fun calculate(byte: Byte) {
                if (isHigh) {
                    high = byte
                    isHigh = false
                } else {
                    low = byte
                    sum += high int low
                    isHigh = true
                }
            }

            fun verify() {
                if (!isHigh) {
                    sum += high.toInt() and 0xFF shl 8
                }
            }

            pseudoHeader?.let {
                it.forEach { item ->
                    calculate(item)
                }
                verify()
            }

            val checkSumValue = dataSource.resolve2Bytes(checkSumIndex)
            dataSource.update2Bytes(checkSumIndex, 0)
            for (i in offset until calculateEnd) {
                calculate(dataSource[i])
            }
            dataSource.update2Bytes(checkSumIndex, checkSumValue)
            verify()

            while (sum > 0xFFFF) {
                sum = (sum and 0xFFFF) + (sum shr 16)
            }
            return (sum.inv() and 0xFFFF).toInt()
        }


    @Throws(DataPacketException::class)
    operator fun getValue(thisRef: Any?, property: KProperty<*>): String {
        val cr = dataSource.resolve2Bytes(checkSumIndex)
        val ccr = checksum
        return "${cr == ccr}(${ccr},hex:${ccr.toString(16)})"
    }

    @Throws(DataPacketException::class)
    operator fun setValue(
        thisRef: Any?,
        property: KProperty<*>,
        checksum: String
    ) {
        dataSource.update2Bytes(checkSumIndex, if (checksum.isEmpty()) this.checksum else 0)
    }
}