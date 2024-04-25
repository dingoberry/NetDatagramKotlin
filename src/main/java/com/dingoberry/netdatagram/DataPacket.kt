package com.dingoberry.netdatagram

class DataPacket(
    dataSource: ByteArray,
    clone: Boolean = false
) {

    private val mDataSource: ByteArray = if (clone) dataSource.clone() else dataSource

    /**
     * 传输Header协议
     */
    private val ipHeader = IpHeader.resolveHeader(mDataSource)

    /**
     * 传输流量数据
     */
    private val data: Any? = when (ipHeader.protocol) {
        IpHeader.Protocol.UDP -> UdpData(
            mDataSource,
            ipHeader, ipHeader.headerLength
        )

        IpHeader.Protocol.TCP -> TcpData(
            mDataSource,
            ipHeader, ipHeader.headerLength
        )

        else -> null
    }
}