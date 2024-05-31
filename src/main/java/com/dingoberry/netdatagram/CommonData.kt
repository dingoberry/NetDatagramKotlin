package com.dingoberry.netdatagram

sealed class CommonData(
    protected val dataSource: ByteArray, ipHeader: IpHeader?, protected val chunkEnd: Int,
    offset: Int, private val checkSumIndex: Byte
) :
    DataOffset(offset) {

    companion object {
        private const val INDEX_SOURCE_PORT = 0.toByte()
        private const val INDEX_DESTINATION_PORT = 2.toByte()
    }

    /**
     * 源端口号（Source Port）: 标识发送端的端口号
     */
    open var sourcePort
        get() = dataSource.resolve2Bytes(INDEX_SOURCE_PORT.offset)
        set(value) {
            dataSource.update2Bytes(INDEX_SOURCE_PORT.offset, value)
        }

    /**
     * 目的端口号（Destination Port）: 标识接收端的端口号
     */
    open var destinationPort
        get() = dataSource.resolve2Bytes(INDEX_DESTINATION_PORT.offset)
        set(value) {
            dataSource.update2Bytes(INDEX_DESTINATION_PORT.offset, value)
        }

    /**
     * 校验和（Checksum）: 用于错误检测的校验和
     */
    var checksum by CheckSum(
        dataSource,
        chunkEnd,
        0.toByte().offset,
        checkSumIndex.offset,
        ipHeader?.pseudoHeader
    )

    val checkSumValue
        get() = dataSource.resolve2Bytes(checkSumIndex.offset)

    /**
     * 头部长度
     */
    abstract var headerLength: Int
}