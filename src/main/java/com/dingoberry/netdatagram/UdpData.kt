package com.dingoberry.netdatagram

class UdpData(dataSource: ByteArray, ipHeader: IpHeader, chunkEnd: Int, offset: Int) :
    CommonData(dataSource, ipHeader, chunkEnd, offset, INDEX_CHECKSUM) {

    companion object {
        private const val INDEX_LENGTH = 4.toByte()
        private const val INDEX_CHECKSUM = 6.toByte()
    }


    /**
     * 长度（Length）: 表示UDP头部和数据总共的长度，最小值是8（仅头部，无数据）。
     */
    var length
        get() = dataSource.resolve2Bytes(INDEX_LENGTH.offset)
        set(value) {
            dataSource.update2Bytes(INDEX_LENGTH.offset, value)
        }

    /**
     * 数据（DATA）
     */
    var data
        get() = dataSource.copyOfRange(0.toByte().offset + length, chunkEnd)
        set(value) {
            val dataSize = dataSource.size - 0.toByte().offset - length
            if (value.size > dataSize) {
                throw DataPacketException("cannot update data out of valid size($dataSize)!")
            }

            (if (value.size == dataSize) {
                value
            } else {
                value.copyOf(dataSize)
            }).copyInto(dataSource, 0.toByte().offset + length)
        }

    override var headerLength: Int
        get() = 8
        set(_) {}
}