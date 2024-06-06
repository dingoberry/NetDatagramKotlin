package com.dingoberry.netdatagram

class IcmpData(dataSource: ByteArray, chunkEnd: Int, offset: Int) :
    CommonData(dataSource, null, chunkEnd, offset, INDEX_CHECKSUM) {

    companion object {
        private const val INDEX_TYPE = 0.toByte()
        private const val INDEX_CODE = 1.toByte()
        private const val INDEX_CHECKSUM = 2.toByte()
        private const val INDEX_IDENTIFIER = 4.toByte()
        private const val INDEX_SEQUENCE_NUMBER = 6.toByte()
    }

    override var headerLength
        get() = 16
        set(_) {
        }

    override var sourcePort
        get() = 0
        set(_) {
        }

    override var destinationPort
        get() = 0
        set(_) {
        }

    /**
     * 用于标识 ICMP 请求和应答报文之间的关联
     */
    var identification
        get() = dataSource.resolve2Bytes(INDEX_IDENTIFIER.offset).toUShort()
        set(value) = dataSource.update2Bytes(INDEX_IDENTIFIER.offset, value.toInt())

    /**
     * 用于标识 ICMP 请求和应答报文之间的顺序
     */
    var sequenceNumber
        get() = dataSource.resolve2Bytes(INDEX_SEQUENCE_NUMBER.offset)
        set(value) {
            dataSource.update2Bytes(INDEX_SEQUENCE_NUMBER.offset, value)
        }

    /**
     * 数据类型
     */
    var dataType
        get() = when (dataSource[INDEX_TYPE.offset].toInt()) {
            0 -> DataType.TYPE_ECHO_REPLY
            8 -> DataType.TYPE_ECHO_REQUEST
            3 -> DataType.TYPE_DESTINATION_UNREACHABLE
            11 -> DataType.TYPE_TIME_EXCEEDED
            else -> DataType.TYPE_NONE
        }
        set(value) {
            when (value) {
                DataType.TYPE_ECHO_REPLY -> dataSource[INDEX_TYPE.offset] = 0
                DataType.TYPE_ECHO_REQUEST -> dataSource[INDEX_TYPE.offset] = 8
                DataType.TYPE_DESTINATION_UNREACHABLE -> dataSource[INDEX_TYPE.offset] = 3
                DataType.TYPE_TIME_EXCEEDED -> dataSource[INDEX_TYPE.offset] = 11
                else -> {}
            }
        }

    /**
     * 目的不可达原因
     */
    val getDestinationUnreachableReason
        get() = if (dataType == DataType.TYPE_DESTINATION_UNREACHABLE) {
            when (dataSource[INDEX_CODE.offset].toInt()) {
                0 -> DestinationUnreachableReason.NETWORK_UNREACHABLE
                1 -> DestinationUnreachableReason.HOST_UNREACHABLE
                2 -> DestinationUnreachableReason.PROTOCOL_UNREACHABLE
                3 -> DestinationUnreachableReason.PORT_UNREACHABLE
                4 -> DestinationUnreachableReason.FRAGMENT_NEEDED_AND_DONT_FRAGMENT_WAS_SET
                5 -> DestinationUnreachableReason.SOURCE_ROUTE_FAILED
                else -> DestinationUnreachableReason.NONE
            }
        } else {
            DestinationUnreachableReason.NONE
        }

    /**
     * 超时原因
     */
    val getTimeExceededReason
        get() = if (dataType == DataType.TYPE_TIME_EXCEEDED) {
            when (dataSource[INDEX_CODE.offset].toInt()) {
                0 -> TimeExceededReason.TIME_TO_LIVE_EXCEEDED_IN_TRANSIT
                1 -> TimeExceededReason.FRAGMENT_REASSEMBLY_TIME_EXCEEDED
                else -> TimeExceededReason.NONE
            }
        } else {
            TimeExceededReason.NONE
        }

    enum class DataType(val value: String) {
        TYPE_ECHO_REQUEST("request"),
        TYPE_ECHO_REPLY("reply"),
        TYPE_DESTINATION_UNREACHABLE("dest unreachable"),
        TYPE_TIME_EXCEEDED("time exceeded"),
        TYPE_NONE("none");

        override fun toString(): String {
            return value
        }
    }

    enum class DestinationUnreachableReason(val value: String) {
        NETWORK_UNREACHABLE("network unreachable"),
        HOST_UNREACHABLE("host unreachable"),
        PROTOCOL_UNREACHABLE("protocol unreachable"),
        PORT_UNREACHABLE("port unreachable"),
        FRAGMENT_NEEDED_AND_DONT_FRAGMENT_WAS_SET("fragment needed and don't fragment was set"),
        SOURCE_ROUTE_FAILED("source route failed"),
        NONE("none");

        override fun toString(): String {
            return value
        }
    }

    enum class TimeExceededReason(val value: String) {
        TIME_TO_LIVE_EXCEEDED_IN_TRANSIT("time to live exceeded in transit"),
        FRAGMENT_REASSEMBLY_TIME_EXCEEDED("fragment reassembly time exceeded"),
        NONE("none");

        override fun toString(): String {
            return value
        }
    }
}