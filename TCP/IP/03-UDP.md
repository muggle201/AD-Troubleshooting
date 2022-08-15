UDP，RFC 768，以下特性：
- Connectionless<br>
    直接发送，不需要与对方negotiate a connection。
- Unreliable<br>
    UDP不负责datagram的sequencing或acknoledgement，因此Application Layer协议必须对该datagram进行重新排序并检查丢失。一些典型的UDP-based应用层协议会提供稳定的交流或定期重传。
- Provides identification of Application Layer protocols<br>
  发送至指定Application Layer协议或进程。
- Provides checksum of UDP message<br>
  

不包含以下：
- Buffering<br>
  不缓存任何incoming或outcomming数据，需要Application Layer提供
- Segmentation<br>
  对于data不会进行分割，需要Application Layer对包裹进行分割。
- Flow Control<br>
  

# 1. UDP Message
UDP消息由IP header中IP Protocol number 17(0x11)进行识别。
<br>

# 2. UDP Ports
53 DNS

445 SMB

Sending node决定了DEST port（指定，或从GetServByNmae获取）及Source port。然后Sending node表明source IP address, DEST IP address,source port,DEST port及消息。

接收后，接收方UDP组件确认DEST port，若有进程在监听该端口，则UDP将消息发送至该application；若无进程在监听，则返回ICMP Destination Unreachable-Port Unreachable消息，然后丢弃该UDP 消息。
