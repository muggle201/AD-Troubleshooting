高效的交流依赖于通用的语言。

当使用通用的语言描述通用的行为，则称之为“协议” （Protocol）

> Protocol:
>
> The official procedure or system of rules governing affairs of state or diplomatic occasions.

用于指定各种协议如何相互依赖并完成各自任务的设计，称之为“结构” （Architecture）或Reference Model。

TCP/IP是用于实现互联网结构的Protocol Suite，起源于ARPANET Reference Model（ARM）。

# Architectural Principles

TCP/IP的目的，即让所有的电脑，手机等任何终端设备上的任何程序，软件能够互相通信。



## Packets, Connections, Datagrams

直到20世纪60年代，网络的概念很大程度上仍基于电话信号。

在60年代，最重要的概念之一便是***Packet Switiching***，即通过网络传输由一些字节组成的“Chunk" (packets)。Chunks来自于不同的sources或senders，可以被混合在一起并在随后分开，这一过程称为***Multiplexing***。

> **Packet Switiching**
>
> 一种数据传输方式，将数据打碎成几个部分，分别地传送至目的地，每个数据包都将选择对自身而言最佳地路线，在全部到达目的地后再重新组装。

当交换机收到packets后，存储于*buffer memory*或*queue*中，然后遵循*first-come-first-served*(FCFS)模式，一种及其便捷地packets管理方式，也可以称为*first-in-first-out*(FIFO)。



































