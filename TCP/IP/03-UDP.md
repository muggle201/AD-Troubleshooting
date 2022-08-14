UDP，RFC 768，以下特性：
- Connectionless<br>
    直接发送，不需要与对方negotiate a connection。
- Unreliable<br>
    UDP不负责datagram的sequencing或acknoledgement，因此Application Layer协议必须对该datagram进行重新排序并检查丢失。一些典型的UDP-based应用层协议会提供稳定的交流或定期重传。
- Provides identification of Application Layer protocols
- Provides checksum of UDP message