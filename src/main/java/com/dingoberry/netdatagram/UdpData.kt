package com.dingoberry.netdatagram

class UdpData(private val dataSource: ByteArray, ipHeader: IpHeader, offset: Int) :
    DataOffset(offset) {

    companion object {
        private const val INDEX_SOURCE_PORT = 0.toByte()
        private const val INDEX_DESTINATION_PORT = 2.toByte()
        private const val INDEX_LENGTH = 4.toByte()
        private const val INDEX_CHECKSUM = 8.toByte()
    }

    /**
     * 源端口号（Source Port）: 标识发送端的端口号
     */
    var sourcePort
        get() = dataSource.resolve2Bytes(INDEX_SOURCE_PORT.offset)
        set(value) {
            dataSource.update2Bytes(INDEX_SOURCE_PORT.offset, value)
        }

    /**
     * 目的端口号（Destination Port）: 标识接收端的端口号
     */
    var destinationPort
        get() = dataSource.resolve2Bytes(INDEX_DESTINATION_PORT.offset)
        set(value) {
            dataSource.update2Bytes(INDEX_DESTINATION_PORT.offset, value)
        }

    /**
     * 长度（Length）: 表示UDP头部和数据总共的长度，最小值是8（仅头部，无数据）。
     */
    var length
        get() = dataSource.resolve2Bytes(INDEX_LENGTH.offset)
        set(value) {
            dataSource.update2Bytes(INDEX_LENGTH.offset, value)
        }

    var checksum by CheckSum(
        dataSource,
        dataSource.size,
        0.toByte().offset,
        INDEX_CHECKSUM.offset,
        ipHeader.pseudoHeader
    )

    /**
     * 数据（DATA）
     */
    var data
        get() = dataSource.copyOfRange(0.toByte().offset + length, dataSource.size)
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
}