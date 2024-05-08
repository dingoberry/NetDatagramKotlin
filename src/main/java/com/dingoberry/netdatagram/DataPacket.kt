package com.dingoberry.netdatagram

/**
 * 数据报
 *
 * @param dataSource 数据源
 * @param clone 解析数据包是否将源数据复制一遍
 * @param offset 数据偏移量
 * @param newCreationIpV6 （默认不创建，抛[DataPacketException]]）Ip头报如果解析失败， true以IpV6形式创建Header，false则为IpV4
 */
class DataPacket(
    dataSource: ByteArray,
    clone: Boolean = false,
    offset: Int = 0,
    newCreationIpV6: Boolean? = null
) {

    private val mDataSource: ByteArray = if (clone) dataSource.clone() else dataSource

    /**
     * 传输Header协议
     */
    val ipHeader = IpHeader.resolveHeader(mDataSource, offset, newCreationIpV6)

    /**
     * 传输流量数据
     */
    val data: Any? = when (ipHeader.protocol) {
        IpHeader.Protocol.UDP -> UdpData(
            mDataSource,
            ipHeader,
            ipHeader.totalLength,
            ipHeader.headerLength
        )

        IpHeader.Protocol.TCP -> TcpData(
            mDataSource,
            ipHeader,
            ipHeader.totalLength,
            ipHeader.headerLength
        )

        else -> null
    }
}