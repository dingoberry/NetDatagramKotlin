package com.dingoberry.netdatagram

import java.net.InetAddress

sealed class IpHeader(protected val dataSource: ByteArray, offset: Int) : DataOffset(offset) {

    enum class Protocol {
        TCP, UDP, UNKNOWN
    }

    abstract val headerLength: Int

    abstract val totalLength: Int

    abstract val protocolData: Byte

    abstract val destinationIp: InetAddress

    abstract val sourceIp: InetAddress

    abstract val pseudoHeader: ByteArray

    val protocol: Protocol
        get() = when (protocolData.toInt() and 0xFF) {
            6 -> Protocol.TCP
            17 -> Protocol.UDP
            else -> Protocol.UNKNOWN
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

        override val headerLength
            get() = (dataSource[INDEX_IHL.offset].toInt() and 0x0F) * 4
        override val totalLength
            get() = dataSource.resolve2Bytes(INDEX_TOTAL_LENGTH.offset)
        override val protocolData
            get() = dataSource[INDEX_PROTOCOL.offset]
        override val destinationIp: InetAddress
            get() = InetAddress.getByAddress(ByteArray(4).apply {
                System.arraycopy(dataSource, INDEX_DESTINATION_IP.offset, this, 0, 4)
            })
        override val sourceIp: InetAddress
            get() = InetAddress.getByAddress(ByteArray(4).apply {
                System.arraycopy(dataSource, INDEX_SOURCE_IP.offset, this, 0, 4)
            })
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

        val destinationIpInt
            get() = dataSource.resolve4Bytes(INDEX_DESTINATION_IP.offset)
        val sourceIpInt
            get() = dataSource.resolve4Bytes(INDEX_SOURCE_IP.offset)

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

        var lowDelay: Boolean
            get() = isTypeOfServiceOk(0b00010000)
            set(value) {
                setTypeOfService(0b00010000, value)
            }

        var highThroughPut: Boolean
            get() = isTypeOfServiceOk(0b00001000)
            set(value) {
                setTypeOfService(0b00001000, value)
            }

        var highReliability: Boolean
            get() = isTypeOfServiceOk(0b00000100)
            set(value) {
                setTypeOfService(0b00000100, value)
            }

        var minMonetaryCost: Boolean
            get() = isTypeOfServiceOk(0b00000010)
            set(value) {
                setTypeOfService(0b00000010, value)
            }

        val identification
            get() = dataSource.resolve2Bytes(INDEX_IDENTIFICATION.offset).toUShort()

        val allowFragment
            get() = 0 == (dataSource[INDEX_FLAGS_FRAGMENT_OFFSET.offset].toInt() and 0x40)

        val moreFragment
            get() = allowFragment && 0 != (dataSource[INDEX_FLAGS_FRAGMENT_OFFSET.offset].toInt() and 0x20)

        val fragmentOffset
            get() =
                if (moreFragment)
                    INDEX_FLAGS_FRAGMENT_OFFSET.offset.let {
                        (dataSource[it].toInt() shl 8) or (dataSource[it + 1].toInt() and 0xFF) and 0x1FFF
                    }
                else 0

        val timeToLive
            get() = dataSource[INDEX_TIME_TO_LIVE.offset]

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

        override val headerLength: Int
            get() = 40
        override val totalLength: Int
            get() = headerLength + payloadLength
        override val protocolData: Byte
            get() = dataSource[INDEX_NEXT_HEADER.offset]
        override val destinationIp: InetAddress
            get() = InetAddress.getByAddress(ByteArray(16).apply {
                System.arraycopy(dataSource, INDEX_DESTINATION_IP.offset, this, 0, 16)
            })
        override val sourceIp: InetAddress
            get() = InetAddress.getByAddress(ByteArray(16).apply {
                System.arraycopy(dataSource, INDEX_SOURCE_IP.offset, this, 0, 16)
            })
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

        val hotLimit
            get() = dataSource[INDEX_HOT_LIMIT.offset]

        val payloadLength
            get() = dataSource.resolve2Bytes(INDEX_PAYLOAD_LENGTH.offset)

        var trafficClass
            get() = (dataSource[INDEX_TRAFFIC_CLASS.offset].toInt() and 0x0F shl 4) or
                    (dataSource[INDEX_FLOW_LABEL.offset].toInt() and 0xF0 shr 4)
            set(value) {
                (value and 0xFF).let {
                    dataSource[INDEX_TRAFFIC_CLASS.offset] =
                        (it shr 4 or dataSource[INDEX_TRAFFIC_CLASS.offset].toInt()).toByte()
                    dataSource[INDEX_FLOW_LABEL.offset] =
                        (it shl 4 or dataSource[INDEX_FLOW_LABEL.offset].toInt()).toByte()
                }
            }

        val dscp
            get() = when (trafficClass shr 2) {
                DSCP.CS1.value -> DSCP.CS1
                DSCP.CS2.value -> DSCP.CS2
                DSCP.CS3.value -> DSCP.CS3
                DSCP.CS4.value -> DSCP.CS4
                DSCP.EF.value -> DSCP.EF
                else -> DSCP.DEFAULT
            }

        val af
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

        val ecn
            get() = when (trafficClass and 0xF3) {
                ECN.ECT_0.value -> ECN.ECT_0
                ECN.ECT_1.value -> ECN.ECT_1
                ECN.CE.value -> ECN.CE
                else -> ECN.NOT_ECT
            }

        /**
         * 服务质量
         */
        enum class DSCP(val value: Int) {
            /**
             * 默认服务，没有特殊的优先级或服务质量要求。
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
             * Expedited Forwarding（EF），最高优先级，用于实时音频和视频流等，要求低延迟、低丢包率。
             */
            EF(0b101110)
        }

        /**
         * 服务质量
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
            NOT_ECT(0b00),

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

        @Throws(DataPacketException::class)
        fun resolveHeader(dataSource: ByteArray, offset: Int = 0): IpHeader {
            dataSource.getOrNull(INDEX_VERSION_IHL + offset)?.run {
                return when (val type = this.toInt() shr 4) {
                    4 -> IpV4Header(dataSource, offset)
                    6 -> IpV6Header(dataSource, offset)
                    else -> throw DataPacketException("Illegal ip header type=${type}!")
                }
            } ?: run {
                throw DataPacketException("Bad ip header from offset(${offset})!")
            }
        }
    }
}