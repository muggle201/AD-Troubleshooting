TCP特性
- Connectoin-oriented<br>
  进行数据交换前，需要建立TCP连接——TCP三次握手。
- Full duplex<br>
  具有双向通道，可同时进行。
- Reliable<br>
  有序的，且有ACK；若无ACK，则进行retransmitted。
- Byte stream<br>
- Sender- and Receiver- flow control<br>
  Sender端，包逐渐加大。Receiver端，表明可接收大小。
- Segmentation of Applicateion Layer data<br>
  
- One-to-one Delivery<br>
  点对点的环形结构，不提供一对多。

# TCP Header
- Source port
- Dest port
- Seq Num
- Ack Num
- Flags
- ...


## TCP Port

## TCP Flags
- ACK
- RST
  表明收到了错误的TCP segment，立即中止连接。
- SYN
- FIN
# Connections
A TCP connection is a bidirectional, full-duplex logical circuit between two process(Application Layer protocols) in an IP network.
> TCP连接是双向且可同时传输