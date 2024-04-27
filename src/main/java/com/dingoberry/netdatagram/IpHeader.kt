package com.dingoberry.netdatagram

import java.net.InetAddress

sealed class IpHeader(protected val dataSource: ByteArray, offset: Int) : DataOffset(offset) {

    enum class Protocol {
        TCP, UDP, UNKNOWN
    }

    /**
     * 头部长度
     */
    abstract var headerLength: Int

    /**
     * 总长度
     */
    abstract var totalLength: Int


    internal abstract var protocolData: Byte

    /**
     * 目标IP地址
     */
    abstract var destinationIp: InetAddress

    /**
     * 源IP地址
     */
    abstract var sourceIp: InetAddress

    /**
     * 伪头部，用于上层协议计算校验合
     */
    abstract val pseudoHeader: ByteArray

    /**
     * 协议，支持：UDP or TCP
     */
    var protocol: Protocol
        get() = when (protocolData.toInt() and 0xFF) {
            6 -> Protocol.TCP
            17 -> Protocol.UDP
            else -> Protocol.UNKNOWN
        }
        set(value) {
            when (value) {
                Protocol.TCP -> protocolData = 6
                Protocol.UDP -> protocolData = 17
                else -> {}
            }
        }

    class IpV4Header(dataSource: ByteArray, offset: Int) : IpHeader(dataSource, offset) {
        companion object {
            private const val INDEX_IHL = 0.toByte()
            private const val INDEX_TYPE_OF_SERVICE = 1.toByte()
            private const val INDEX_TOTAL_LENGTH = 2.toByte()
            private const val INDEX_IDENTIFICATION = 4.toByte()
            private const val INDEX_FLAGS_FRAGMENT_OFFSET = 6.toByte()
            private const val INDEX_TIME_TO_LIVE = 8.toByte()
            private const val INDEX_PROTOCOL = 9.toByte()
            private const val INDEX_HEADER_CHECKSUM = 10.toByte()
            private const val INDEX_SOURCE_IP = 12.toByte()
            private const val INDEX_DESTINATION_IP = 16.toByte()
            private const val INDEX_OPTIONS_PADDING = 20.toByte()
        }

        override var headerLength
            get() = (dataSource[INDEX_IHL.offset].toInt() and 0x0F) * 4
            set(value) {
                dataSource[INDEX_IHL.offset] =
                    ((value / 4) or (dataSource[INDEX_IHL.offset].toInt() and 0xFF)).toByte()
            }
        override var totalLength
            get() = dataSource.resolve2Bytes(INDEX_TOTAL_LENGTH.offset)
            set(value) = dataSource.update2Bytes(INDEX_TOTAL_LENGTH.offset, value)
        override var protocolData
            get() = dataSource[INDEX_PROTOCOL.offset]
            set(value) {
                dataSource[INDEX_PROTOCOL.offset] = value
            }
        override var destinationIp: InetAddress
            get() = InetAddress.getByAddress(ByteArray(4).apply {
                System.arraycopy(dataSource, INDEX_DESTINATION_IP.offset, this, 0, 4)
            })
            set(value) {
                value.address.copyInto(dataSource, INDEX_DESTINATION_IP.offset)
            }
        override var sourceIp: InetAddress
            get() = InetAddress.getByAddress(ByteArray(4).apply {
                System.arraycopy(dataSource, INDEX_SOURCE_IP.offset, this, 0, 4)
            })
            set(value) {
                value.address.copyInto(dataSource, INDEX_SOURCE_IP.offset)
            }
        override val pseudoHeader
            get() = ByteArray(12).apply {
                dataSource.copyInto(this, 0, INDEX_SOURCE_IP.offset, INDEX_SOURCE_IP.offset + 4)
                dataSource.copyInto(
                    this,
                    4,
                    INDEX_DESTINATION_IP.offset,
                    INDEX_DESTINATION_IP.offset + 4
                )
                this[9] = protocolData
                this.update2Bytes(10, totalLength - headerLength)
            }

        /**
         * 目标IP[Int]
         */
        var destinationIpInt
            get() = dataSource.resolve4Bytes(INDEX_DESTINATION_IP.offset)
            set(value) = dataSource.update4Bytes(INDEX_DESTINATION_IP.offset, value)

        /**
         * 源IP[Int]
         */
        var sourceIpInt
            get() = dataSource.resolve4Bytes(INDEX_SOURCE_IP.offset)
            set(value) = dataSource.update4Bytes(INDEX_SOURCE_IP.offset, value)

        /**
         * 选项（Options）:  可变长度：可选字段，用于网络测试、安全等目的。
         * 填充（Padding）:  可变长度：确保IP头部长度是32位字的整数倍。
         */
        var optionsPadding by OptionsPadding(dataSource, INDEX_OPTIONS_PADDING.offset, headerLength)

        private fun getTypeOfService(mask: Int) =
            (dataSource[INDEX_TYPE_OF_SERVICE.offset].toInt() and mask)

        private fun isTypeOfServiceOk(mask: Int) = 0 != getTypeOfService(mask)

        private fun setTypeOfService(mask: Int, enable: Boolean) {
            dataSource[INDEX_TYPE_OF_SERVICE.offset] =
                (dataSource[INDEX_TYPE_OF_SERVICE.offset].toInt() or if (enable) {
                    mask
                } else {
                    0
                }).toByte()
        }

        /**
         * 服务类型: 优先级
         */
        var precedence
            get() = when (getTypeOfService(0b11100000) shr 5) {
                Precedence.PRIORITY.value -> Precedence.PRIORITY
                Precedence.IMMEDIATE.value -> Precedence.IMMEDIATE
                Precedence.FLASH.value -> Precedence.FLASH
                Precedence.FLASH_OVERRIDE.value -> Precedence.FLASH_OVERRIDE
                Precedence.CRITICAL.value -> Precedence.CRITICAL
                Precedence.INTERNET_WORK_CONTROL.value -> Precedence.INTERNET_WORK_CONTROL
                Precedence.NETWORK_CONTROL.value -> Precedence.NETWORK_CONTROL
                else -> Precedence.ROUTINE
            }
            set(value) {
                dataSource[INDEX_TYPE_OF_SERVICE.offset] = (0b11100000 or value.value
                        or dataSource[INDEX_TYPE_OF_SERVICE.offset].toInt()).toByte()
            }

        /**
         * 服务类型: 低延迟
         */
        var lowDelay: Boolean
            get() = isTypeOfServiceOk(0b00010000)
            set(value) {
                setTypeOfService(0b00010000, value)
            }

        /**
         * 服务类型: 高吞吐量
         */
        var highThroughPut: Boolean
            get() = isTypeOfServiceOk(0b00001000)
            set(value) {
                setTypeOfService(0b00001000, value)
            }

        /**
         * 服务类型: 高可靠性
         */
        var highReliability: Boolean
            get() = isTypeOfServiceOk(0b00000100)
            set(value) {
                setTypeOfService(0b00000100, value)
            }

        /**
         * 服务类型: 最低成本
         */
        var minMonetaryCost: Boolean
            get() = isTypeOfServiceOk(0b00000010)
            set(value) {
                setTypeOfService(0b00000010, value)
            }

        /**
         * 标识 (Identification): 用于唯一标识主机发送的每一个数据包
         */
        var identification
            get() = dataSource.resolve2Bytes(INDEX_IDENTIFICATION.offset).toUShort()
            set(value) = dataSource.update2Bytes(INDEX_IDENTIFICATION.offset, value.toInt())

        /**
         * 标志 (Flags): 用于指示是否允许对 IP 数据报进行分片
         */
        var allowFragment
            get() = 0 == (dataSource[INDEX_FLAGS_FRAGMENT_OFFSET.offset].toInt() and 0x40)
            set(value) {
                dataSource[INDEX_FLAGS_FRAGMENT_OFFSET.offset].toInt().apply {
                    dataSource[INDEX_FLAGS_FRAGMENT_OFFSET.offset] =
                        (this or if (value) 0x40 else 0).toByte()
                }
            }

        /**
         * 标志 (Flags): 用于指示是否还有更多的分片
         */
        var moreFragment
            get() = allowFragment && 0 != (dataSource[INDEX_FLAGS_FRAGMENT_OFFSET.offset].toInt() and 0x20)
            set(value) {
                if (allowFragment) {
                    dataSource[INDEX_FLAGS_FRAGMENT_OFFSET.offset] =
                        (dataSource[INDEX_FLAGS_FRAGMENT_OFFSET.offset].toInt()
                                or if (value) 0x20 else 0).toByte()
                }
            }

        /**
         * 片偏移 (Fragment Offset): 用于分片和重组数据包
         */
        var fragmentOffset
            get() =
                if (moreFragment)
                    INDEX_FLAGS_FRAGMENT_OFFSET.offset.let {
                        (dataSource[it].toInt() shl 8) or (dataSource[it + 1].toInt() and 0xFF) and 0x1FFF
                    }
                else 0
            set(value) {
                if (moreFragment) {
                    INDEX_FLAGS_FRAGMENT_OFFSET.offset.let {
                        dataSource[it] =
                            (value and 0x1F00 shr 8 and dataSource[it].toInt()).toByte()
                        dataSource[it + 1] =
                            (value and 0xFF and dataSource[it + 1].toInt()).toByte()
                    }
                }
            }

        /**
         * 生存时间 (Time To Live, TTL): 指定数据包在网络中可以通过的最大路由器数。
         */
        var timeToLive
            get() = dataSource[INDEX_TIME_TO_LIVE.offset]
            set(value) {
                dataSource[INDEX_TIME_TO_LIVE.offset] = value
            }

        /**
         * 头部校验和，Get返回校验合是否准确，Set=true: 设置校验合， 反之清零
         */
        var checkSum by CheckSum(
            dataSource,
            headerLength,
            0.toByte().offset,
            INDEX_HEADER_CHECKSUM.offset
        )


        enum class Precedence(val value: Int) {
            /**
             * 普通优先级（Routine）
             */
            ROUTINE(0b000),

            /**
             * 优先（Priority）
             */
            PRIORITY(0b001),

            /**
             * 即时（Immediate）
             */
            IMMEDIATE(0b010),

            /**
             * 闪电（Flash）
             */
            FLASH(0b011),

            /**
             * 无线电闪电（Flash Override）
             */
            FLASH_OVERRIDE(0b100),

            /**
             * 关键（Critical）
             */
            CRITICAL(0b101),

            /**
             * 互联网控制（InterNetwork Control）
             */
            INTERNET_WORK_CONTROL(0b110),

            /**
             * 网络控制（Network Control）
             */
            NETWORK_CONTROL(0b111)
        }
    }

    class IpV6Header(dataSource: ByteArray, offset: Int) : IpHeader(dataSource, offset) {
        companion object {
            private const val INDEX_TRAFFIC_CLASS = 0.toByte()
            private const val INDEX_FLOW_LABEL = 1.toByte()
            private const val INDEX_PAYLOAD_LENGTH = 4.toByte()
            private const val INDEX_NEXT_HEADER = 6.toByte()
            private const val INDEX_HOT_LIMIT = 7.toByte()
            private const val INDEX_SOURCE_IP = 8.toByte()
            private const val INDEX_DESTINATION_IP = 24.toByte()
        }

        override var headerLength: Int
            get() = 40
            set(_) {
            }
        override var totalLength: Int
            get() = headerLength + payloadLength
            set(value) {
                payloadLength = value - headerLength
            }
        override var protocolData: Byte
            get() = dataSource[INDEX_NEXT_HEADER.offset]
            set(value) {
                dataSource[INDEX_NEXT_HEADER.offset] = value
            }
        override var destinationIp: InetAddress
            get() = InetAddress.getByAddress(ByteArray(16).apply {
                System.arraycopy(dataSource, INDEX_DESTINATION_IP.offset, this, 0, 16)
            })
            set(value) {
                value.address.copyInto(dataSource, INDEX_DESTINATION_IP.offset)
            }
        override var sourceIp: InetAddress
            get() = InetAddress.getByAddress(ByteArray(16).apply {
                System.arraycopy(dataSource, INDEX_SOURCE_IP.offset, this, 0, 16)
            })
            set(value) {
                value.address.copyInto(dataSource, INDEX_SOURCE_IP.offset)
            }
        override val pseudoHeader
            get() = ByteArray(36).apply {
                dataSource.copyInto(
                    this,
                    0,
                    INDEX_SOURCE_IP.offset,
                    INDEX_SOURCE_IP.offset + 16
                )
                dataSource.copyInto(
                    this,
                    16,
                    INDEX_DESTINATION_IP.offset,
                    INDEX_DESTINATION_IP.offset + 16
                )
                this[33] = protocolData
                this.update2Bytes(34, payloadLength)
            }

        /**
         * 有效载荷长度 (Payload Length): 指定除了标准40字节的IPv6头部之外的数据包部分的长度。
         */
        var payloadLength
            get() = dataSource.resolve2Bytes(INDEX_PAYLOAD_LENGTH.offset)
            set(value) = dataSource.update2Bytes(INDEX_PAYLOAD_LENGTH.offset, value)

        /**
         * 流量类别 (Traffic Class): 用于区分数据包的优先级和服务质量。
         */
        var trafficClass
            get() = (dataSource[INDEX_TRAFFIC_CLASS.offset].toInt() and 0x0F shl 4) or
                    (dataSource[INDEX_TRAFFIC_CLASS.offset + 1].toInt() and 0xF0 shr 4)
            set(value) {
                (value and 0xFF).let {
                    dataSource[INDEX_TRAFFIC_CLASS.offset] =
                        (it shr 4 or dataSource[INDEX_TRAFFIC_CLASS.offset].toInt()).toByte()
                    dataSource[INDEX_TRAFFIC_CLASS.offset + 1] =
                        (it shl 4 or dataSource[INDEX_TRAFFIC_CLASS.offset + 1].toInt()).toByte()
                }
            }

        /**
         *  流量类别 (Traffic Class): Differentiated Services Code Point
         */
        var dscp
            get() = when (trafficClass shr 2) {
                DSCP.CS1.value -> DSCP.CS1
                DSCP.CS2.value -> DSCP.CS2
                DSCP.CS3.value -> DSCP.CS3
                DSCP.CS4.value -> DSCP.CS4
                DSCP.EF.value -> DSCP.EF
                else -> DSCP.DEFAULT
            }
            set(value) {
                trafficClass = value.value
            }

        /**
         *  流量类别 (Traffic Class): 有保证的转发 Differentiated Services Code Point of AF
         */
        var af
            get() = when (trafficClass shr 2) {
                AF.AF11.value -> AF.AF11
                AF.AF12.value -> AF.AF12
                AF.AF13.value -> AF.AF13

                AF.AF21.value -> AF.AF21
                AF.AF22.value -> AF.AF22
                AF.AF23.value -> AF.AF23

                AF.AF31.value -> AF.AF31
                AF.AF32.value -> AF.AF32
                AF.AF33.value -> AF.AF33

                AF.AF41.value -> AF.AF41
                AF.AF42.value -> AF.AF42
                AF.AF43.value -> AF.AF43
                else -> AF.DEFAULT
            }
            set(value) {
                trafficClass = value.value
            }

        /**
         * 流量类别 (Traffic Class): 网络拥塞情况
         */
        var ecn
            get() = when (trafficClass and 0xF3) {
                ECN.ECT_0.value -> ECN.ECT_0
                ECN.ECT_1.value -> ECN.ECT_1
                ECN.CE.value -> ECN.CE
                else -> ECN.NOT_ECT
            }
            set(value) {
                trafficClass = value.value
            }

        /**
         * 流标签 (Flow Label): 用于标识来自同一源的数据包流，以便于特殊处理。
         */
        var flowLabel
            get() = dataSource[INDEX_FLOW_LABEL.offset].toInt() and 3 shl 16 or dataSource.resolve2Bytes(
                INDEX_FLOW_LABEL.offset + 1
            )
            set(value) {
                dataSource[INDEX_FLOW_LABEL.offset] = (value and 0x30000 shr 16).toByte()
                dataSource[INDEX_FLOW_LABEL.offset + 1] = (value and 0xFFFF).toByte()
            }

        /**
         * 跳限制 (Hop Limit): 与IPv4中的生存时间（TTL）字段相似，每经过一个路由器该值减一，减至0时数据包被丢弃。
         */
        var hotLimit
            get() = dataSource[INDEX_HOT_LIMIT.offset]
            set(value) {
                dataSource[INDEX_HOT_LIMIT.offset] = value
            }

        /**
         * 服务质量
         */
        enum class DSCP(val value: Int) {
            /**
             * （最佳努力）默认服务，用于普通的数据传输，没有特殊的优先级或服务质量要求。
             */
            DEFAULT(0),

            /**
             * ：CS1，最低优先级，适用于低优先级流量，如后台任务。
             */
            CS1(0b001000),

            /**
             * CS2，低优先级，适用于一般优先级流量，如邮件和文件传输。
             */
            CS2(0b010000),

            /**
             * CS3，中等优先级，适用于较高优先级流量，如视频流或VoIP信令。
             */
            CS3(0b011000),

            /**
             * CS4，高优先级，适用于高优先级流量，如实时音频和视频流。
             */
            CS4(0b100000),

            /**
             * Expedited Forwarding（EF）（加速转发），最高优先级，用于实时音频和视频流等，要求低延迟、低丢包率。
             */
            EF(0b101110)
        }

        /**
         * 有保证的转发: 服务质量
         * AFxy（其中x=1-4，y=1-3）：Assured Forwarding，提供四个类别的服务，每个类别有三个不同的丢包优先级。
         * 例如，AF11（001010）、AF12（001100）、AF13（001110）分别表示第一类别的低、中、高丢包优先级。
         */
        enum class AF(val value: Int) {
            DEFAULT(0),
            AF11(0b001010), AF12(0b001100), AF13(0b001110),
            AF21(0b010010), AF22(0b010100), AF23(0b010110),
            AF31(0b011010), AF32(0b011100), AF33(0b011110),
            AF41(0b100010), AF42(0b100100), AF43(0b100110),
        }

        /**
         *显式拥塞通知
         */
        enum class ECN(val value: Int) {
            /**
             * 不使用显式拥塞通知。
             */
            NOT_ECT(0),

            /**
             *使用显式拥塞通知，但优先级较低。
             */
            ECT_0(0b01),

            /**
             *使用显式拥塞通知，但优先级较高。
             */
            ECT_1(0b10),

            /**
             *表示拥塞已发生，需要采取措施减少拥塞。
             */
            CE(0b11)
        }
    }

    companion object {
        private const val INDEX_VERSION_IHL = 0.toByte()

        /**
         * 解析Header
         */
        @Throws(DataPacketException::class)
        fun resolveHeader(
            dataSource: ByteArray,
            offset: Int = 0,
            newCreationIpV6: Boolean?
        ): IpHeader {
            dataSource.getOrNull(INDEX_VERSION_IHL offset offset)?.run {
                return when (val type = this.toInt() shr 4) {
                    4 -> IpV4Header(dataSource, offset)
                    6 -> IpV6Header(dataSource, offset)
                    else -> {
                        newCreationIpV6?.let {
                            fun applyHeader(version: Int) {
                                dataSource[INDEX_VERSION_IHL offset offset] =
                                    (version shl 4).toByte()
                            }

                            if (it) {
                                applyHeader(6)
                                IpV6Header(dataSource, offset)
                            } else {
                                applyHeader(4)
                                IpV4Header(dataSource, offset)
                            }
                        } ?: run { throw DataPacketException("Illegal ip header type=${type}!") }
                    }
                }
            } ?: run {
                throw DataPacketException("Bad ip header from offset(${offset})!")
            }
        }
    }
}