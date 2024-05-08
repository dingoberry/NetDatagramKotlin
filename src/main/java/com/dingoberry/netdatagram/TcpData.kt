package com.dingoberry.netdatagram

class TcpData(dataSource: ByteArray, ipHeader: IpHeader, totalLength: Int, offset: Int) :
    CommonData(dataSource, ipHeader, totalLength, offset, INDEX_CHECKSUM) {
    companion object {
        private const val INDEX_SEQUENCE_NUMBER = 4.toByte()
        private const val INDEX_ACKNOWLEDGEMENT_NUMBER = 8.toByte()
        private const val INDEX_DATA_SET_RESERVED = 12.toByte()
        private const val INDEX_FLAGS = 13.toByte()
        private const val INDEX_WINDOW_SIZE = 14.toByte()
        private const val INDEX_CHECKSUM = 16.toByte()
        private const val INDEX_URGENT_POINTER = 18.toByte()
        private const val INDEX_OPTIONS_PADDING = 20.toByte()
    }

    /**
     *序列号（Sequence Number）: 用于数据重组的序列号、初始序列号
     */
    var sequenceNumber
        get() = dataSource.resolve4Bytes(INDEX_SEQUENCE_NUMBER.offset)
        set(value) {
            dataSource.update4Bytes(INDEX_SEQUENCE_NUMBER.offset, value)
        }

    /**
     *确认号（Acknowledgment Number）: 发送确认的数据
     */
    var acknowledgementNumber
        get() = dataSource.resolve4Bytes(INDEX_ACKNOWLEDGEMENT_NUMBER.offset)
        set(value) {
            dataSource.update4Bytes(INDEX_ACKNOWLEDGEMENT_NUMBER.offset, value)
        }

    /**
     * 数据偏移（Data Offset）: TCP头部的长度, 32位字。
     */
    var dataOffset
        get() = dataSource[INDEX_DATA_SET_RESERVED.offset].toInt() and 0xF0 shr 4
        set(value) {
            dataSource[INDEX_DATA_SET_RESERVED.offset] = (value and 0x0F shl 4
                    or dataSource[INDEX_DATA_SET_RESERVED.offset].toInt()).toByte()
        }

    /**
     * 标志位（Flags）: 控制标志
     */
    var flags
        get() = dataSource[INDEX_FLAGS.offset].toInt()
        set(value) {
            dataSource[INDEX_FLAGS.offset] =
                (dataSource[INDEX_FLAGS.offset].toInt() or value).toByte()
        }

    /**
     * Congestion Window Reduced: 拥塞窗口减小标志位
     */
    var cwr
        get() = flags and 0b10000000 != 0
        set(value) {
            flags = if (value) 0b10000000 else 0
        }

    /**
     * ECN-Echo: 拥塞通知标志位
     */
    var ece
        get() = flags and 0b1000000 != 0
        set(value) {
            flags = if (value) 0b1000000 else 0
        }

    /**
     * Urgent: 紧急标志位
     */
    var urg
        get() = flags and 0b100000 != 0
        set(value) {
            flags = if (value) 0b100000 else 0
        }

    /**
     * Acknowledgment: 确认数据段的接收
     */
    var ack
        get() = flags and 0b10000 != 0
        set(value) {
            flags = if (value) 0b10000 else 0
        }

    /**
     * Push: 推送标志位
     */
    var psh
        get() = flags and 0b1000 != 0
        set(value) {
            flags = if (value) 0b1000 else 0
        }

    /**
     * Reset: 重置标志位
     */
    var rst
        get() = flags and 0b100 != 0
        set(value) {
            flags = if (value) 0b100 else 0
        }

    /**
     * Synchronize: 建立连接
     */
    var syn
        get() = flags and 0b10 != 0
        set(value) {
            flags = if (value) 0b10 else 0
        }

    /**
     * Finish: 结束标志位
     */
    var fin
        get() = flags and 1 != 0
        set(value) {
            flags = if (value) 1 else 0
        }

    /**
     * 窗口大小（Window Size）: 用于流量控制，指示发送方可以发送的数据量
     */
    var windowSize
        get() = dataSource.resolve4Bytes(INDEX_WINDOW_SIZE.offset)
        set(value) {
            dataSource.update4Bytes(INDEX_WINDOW_SIZE.offset, value)
        }

    /**
     * 紧急指针（Urgent Pointer）: 仅当URG标志位为1时才有效，指示紧急数据的结束位置
     */
    var urgentPointer
        get() = dataSource.resolve4Bytes(INDEX_URGENT_POINTER.offset)
        set(value) {
            dataSource.update4Bytes(INDEX_URGENT_POINTER.offset, value)
        }

    /**
     * 选项（Options）:  可变长度：用于各种控制目的，如最大报文段长度（MSS）、窗口扩大因子、时间戳等。选项字段的长度可变，但总长度必须使得整个头部长度是32位的整数倍。
     * 填充（Padding）:  可变长度：确保TCP头部长度是32位的整数倍。
     */
    var optionsPadding by OptionsPadding(dataSource, INDEX_OPTIONS_PADDING.offset, dataOffset)

    /**
     * 数据（DATA）
     */
    var data
        get() = dataSource.copyOfRange(0.toByte().offset + dataOffset, dataSource.size)
        set(value) {
            val dataSize = dataSource.size - 0.toByte().offset - dataOffset
            if (value.size > dataSize) {
                throw DataPacketException("cannot update data out of valid size($dataSize)!")
            }

            (if (value.size == dataSize) {
                value
            } else {
                value.copyOf(dataSize)
            }).copyInto(dataSource, 0.toByte().offset + dataOffset)
        }
}