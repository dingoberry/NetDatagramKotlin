package com.dingoberry.netdatagram

class IcmpData(dataSource: ByteArray, ipHeader: IpHeader, chunkEnd: Int, offset: Int) :
    CommonData(dataSource, ipHeader, chunkEnd, offset, INDEX_CHECKSUM) {

    companion object {
        private const val INDEX_TYPE = 1.toByte()
        private const val INDEX_CODE = 2.toByte()
        private const val INDEX_CHECKSUM = 3.toByte()
        private const val INDEX_IDENTIFIER = 5.toByte()
        private const val INDEX_SEQUENCE_NUMBER = 7.toByte()
    }

    override var headerLength
        get() = 16
        set(_) {
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

    enum class DataType {
        TYPE_ECHO_REQUEST,
        TYPE_ECHO_REPLY,
        TYPE_DESTINATION_UNREACHABLE,
        TYPE_TIME_EXCEEDED,
        TYPE_NONE
    }

    enum class DestinationUnreachableReason {
        NETWORK_UNREACHABLE,
        HOST_UNREACHABLE,
        PROTOCOL_UNREACHABLE,
        PORT_UNREACHABLE,
        FRAGMENT_NEEDED_AND_DONT_FRAGMENT_WAS_SET,
        SOURCE_ROUTE_FAILED,
        NONE
    }

    enum class TimeExceededReason {
        TIME_TO_LIVE_EXCEEDED_IN_TRANSIT,
        FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
        NONE
    }
}