

# TCP/IP 协议结构

TCP/IP协议映射了理想的4层结构--DARPA模型，即：
- Application
- Transport
- Internet
- Network

与7层OSI模型中的一个或多个对应。
![image info](../Image/protocol%20architecture.gif)

## Network Interface Layer
Network Interface Layer负责将TCP/IP包放置于网络介质及从网络介质接收包。TCP/IP被设计为独立于Network Interface Layer之上。
<br>

一般假定Network Interface Layer并非安全且可靠的，因此连接的稳定性与安全性依赖于Transport Layer--TCP/IP。
<br>

## Internet Layer
Internet Layer负责
- Addressing
- Packaging
- Routings
<br>

## Transport Layer
我们也可称该层为端对端传输层，为Application Layer提供会话及数据传输服务。该层使用TCP或UDP协议。
<br>

- TCP
<br>

一对一，以连接为基础的可靠交流。
- UDP
<br>

一对一/多，无连接的不可靠交流。适用于不希望建立TCP连接，或Application Layer可以提供可靠传递时。
<br>

## Application Layer
Application Layer使得引用获取其他层的服务并定义应用在交换数据时所使用的protocols。
<br>

用于user information交换
- HTTP
- FTP
- SMTP
<br>

用于使用并管理TCP/IP网络
- DNS
- RIP
- SNMP
<br>

# TCP/IP Application Interfaces
Network Operation System建立了APIs来供Application使用，使得application能够使用TCP/IP的一些服务。
<br>

![image info](../Image/APIs%20for%20TCPIP.gif )
<br>

## Windows Sockets Interface
Windows Sockets API允许应用bind指定的端口及IP 地址，初始化连接，收发数据并关闭连接。
- TCP
- UDP

# TCP/IP Tools

# Dignostic Tools
