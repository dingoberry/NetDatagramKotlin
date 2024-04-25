package com.dingoberry.netdatagram

class DataPacket(
    dataSource: ByteArray,
    clone: Boolean = false
) {

    private val mDataSource: ByteArray = if (clone) dataSource.clone() else dataSource
}