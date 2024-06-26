# NetDatagramKotlin
network datagram structure written in kotlin

数据流量包基础工具类：封装流量包基础协议以及相关工具使用

一、IPHeader
1.1 IPv4头部是一个复杂的结构，它包含了多个字段，每个字段都有特定的意义。IPv4头部的数据格式如下：

    版本 (Version) - 4位：指定IP协议的版本，IPv4的版本号是4。
    
    头部长度 (IHL, Internet Header Length) - 4位：指定IPv4头部的长度，单位是32位字。最小值是5（即20字节），如果有选项字段，则长度会增加。
    
    服务类型 (Type of Service, TOS) - 8位：指定数据包的服务质量。
    
    总长度 (Total Length) - 16位：指定整个IP数据包的长度，包括头部和数据，单位是字节。
    
    标识 (Identification) - 16位：用于唯一标识主机发送的每一个数据包。
    
    标志 (Flags) - 3位：控制和标识分片。
    
    片偏移 (Fragment Offset) - 13位：用于分片和重组数据包。
    
    生存时间 (Time To Live, TTL) - 8位：指定数据包在网络中可以通过的最大路由器数。
    
    协议 (Protocol) - 8位：指定上层协议，例如TCP是6，UDP是17。
    
    头部校验和 (Header Checksum) - 16位：用于错误检测，只校验头部。
    
    源IP地址 (Source Address) - 32位：发送方的IP地址。
    
    目的IP地址 (Destination Address) - 32位：接收方的IP地址。
    
    选项 (Options) - 可变长度：可选字段，用于网络测试、安全等目的。
    
    填充 (Padding) - 可变长度：确保IP头部长度是32位字的整数倍。

    IPv4头部的结构如下所示（每行代表32位）：
    
     0               8               16              24              31
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |Version|  IHL  |    Type of Service    |        Total Length       |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |       Identification      |Flags|       Fragment Offset         |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |   Time to Live   |    Protocol   |        Header Checksum       |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                         Source Address                          |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                      Destination Address                        |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                    Options                    |    Padding    |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

1.2 IPv6头部的设计比IPv4更为简化，主要是为了提高路由效率。IPv6头部包含以下字段：

    版本 (Version) - 4位：指定IP协议的版本，IPv6的版本号是6。
    
    流量类别 (Traffic Class) - 8位：类似于IPv4中的服务类型（Type of Service），用于区分数据包的优先级和服务质量。
    
    流标签 (Flow Label) - 20位：用于标识来自同一源的数据包流，以便于特殊处理。
    
    有效载荷长度 (Payload Length) - 16位：指定除了标准40字节的IPv6头部之外的数据包部分的长度，单位是字节。
    
    下一个头部 (Next Header) - 8位：指定紧接着IPv6头部的扩展头部或上层协议的类型，类似于IPv4中的协议字段。
    
    跳限制 (Hop Limit) - 8位：与IPv4中的生存时间（TTL）字段相似，每经过一个路由器该值减一，减至0时数据包被丢弃。
    
    源地址 (Source Address) - 128位：发送方的IPv6地址。
    
    目的地址 (Destination Address) - 128位：接收方的IPv6地址。
    
    IPv6头部的结构如下所示（每行代表32位）：

     0               8               16              24              31
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |Version| Traffic Class |           Flow Label                  |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |         Payload Length        |  Next Header  |   Hop Limit   |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                                                               |
    +                                                               +
    |                                                               |
    +                         Source Address                        +
    |                                                               |
    +                                                               +
    |                                                               |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                                                               |
    +                                                               +
    |                                                               |
    +                      Destination Address                      +
    |                                                               |
    +                                                               +
    |                                                               |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

二、TcpHeader
TCP（传输控制协议）头部是TCP数据包的核心部分，它包含了控制TCP连接和数据流的各种重要信息。TCP头部的数据格式是固定和定义良好的，以下是TCP头部的结构：

    源端口号（Source Port） - 16位：标识发送端的端口号。
    目的端口号（Destination Port） - 16位：标识接收端的端口号。
    序列号（Sequence Number） - 32位：用于数据重组的序列号，如果SYN标志位为1，则这个字段的值也是初始序列号。
    确认号（Acknowledgment Number） - 32位：如果ACK标志位为1，则该字段包含发送确认的数据。
    数据偏移（Data Offset） - 4位：指示TCP头部的长度，即头部有多少个32位字。
    保留（Reserved） - 3位：保留未用。
    标志位（Flags） - 9位：包含了控制标志，如SYN、ACK、FIN、RST、PSH、URG、ECE、CWR和NS。
    窗口大小（Window Size） - 16位：用于流量控制，指示发送方可以发送的数据量。
    校验和（Checksum） - 16位：用于错误检测的校验和，覆盖整个TCP段，包括TCP头部、数据和一个伪头部。
    紧急指针（Urgent Pointer） - 16位：仅当URG标志位为1时才有效，指示紧急数据的结束位置。
    选项（Options） - 可变长度：用于各种控制目的，如最大报文段长度（MSS）、窗口扩大因子、时间戳等。选项字段的长度可变，但总长度必须使得整个头部长度是32位的整数倍。
    填充（Padding） - 可变长度：确保TCP头部长度是32位的整数倍。
    TCP头部的最小长度是20字节（不包含选项），最大长度是60字节（包含最大长度的选项）。数据偏移字段指示了头部的实际长度，以便接收方知道在哪里开始读取数据。
    
    这是一个TCP头部的字节级表示，每个数字代表一个字节：
     0                   1                   2                   3   
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

二、UdpHeader
UDP（用户数据报协议）头部相对于TCP头部来说简单得多。UDP是一个无连接的、简单的传输层协议，提供了基本的数据包发送功能，但不保证可靠性、顺序或数据完整性。UDP头部包含以下字段：

    源端口号（Source Port） - 16位：这是发送端的端口号，用于接收端识别发送源。在某些情况下，这个字段可能不被使用，然后被设置为零。
    目的端口号（Destination Port） - 16位：这是接收端的端口号，用于接收端识别目标应用程序。
    长度（Length） - 16位：表示UDP头部和数据总共的长度，最小值是8（仅头部，无数据）。
    校验和（Checksum） - 16位：用于错误检测，覆盖整个UDP数据报，包括UDP头部、数据和一个伪头部（包含源地址、目的地址、协议类型和UDP长度等信息）。这个字段在IPv4中是可选的，但在IPv6中则是必须的。
    UDP头部的长度固定为8字节。以下是UDP头部的字节级表示，每个数字代表一个字节：
     0                   1                   2                   3   
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       Source Port            |        Destination Port       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Length             |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

三、IcmpHeader
 ICMP（Internet Control Message Protocol）协议头信息结构：

    Type（8 bits）：指示 ICMP 报文的类型。
    Code（8 bits）：与 Type 字段一起用于更具体地描述 ICMP 报文的目的或错误类型。
    Checksum（16 bits）：用于检测 ICMP 报文的完整性。
    Identifier（16 bits）：用于标识 ICMP 请求和应答报文之间的关联。
    Sequence Number（16 bits）：用于标识 ICMP 请求和应答报文之间的顺序。
    Data：根据 ICMP 报文的类型和代码，可能包含不同的数据字段。在 Echo 请求和应答报文中，Data 字段通常包含发送和接收的数据。

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             Data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
