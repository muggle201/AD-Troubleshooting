> 安全通道，验证Requester的同时，向Requester保证数据的confidentiality及integrity。

# 三种Secure Channel
- Client and Domain Controller
- DC of source domain and DC of a trusted domain
- DCs in the same domain

# How Secure Channel operates?
在通道建立过程中，唯一会使用的Account是发起者的Computer Account。而在AD中该Computer Account会提供machine password来进行验证。
> Machine password默认30天更新，该password在AD中不会expire，更新天数可在Group Polic中进行修改。
> 路径为Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Maximum machine account password age

负责建立该通道的Service为Netlogon，当机器启动，一旦Netlogon service可用，则立即开始建立Computer与DC间的Secure Channel，以下三个为Netlogon在此过程中使用的重要参数：
- ScavengeInterval决定Netlogon service检查密码是否过期的频率。
- MaximumPasswordAge决定System修改Computer Account Password的频率。
- DisablePasswordChange可以通过修改该值为1，使得不再更新密码。（该值默认为0）

> 如何修改这三个参数
> - ScavengeInterval
> HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters
> Computer Configuration\Administrative Templates\System\Netlogon\Scavenge Interval
> - MaximumPasswordAge
> HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters
> Computer Configuration\windows Settings\Security settings\Local Policies\Security Options\ Domain member: Maximum machine account Password age
> - DisablePasswordChange
> HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters
> Computer Configuration\windows Settings\Security settings\Local Policies\Security Options\Domain member: Disable machine account Password changes





---
REF: 
https://social.technet.microsoft.com/wiki/contents/articles/24644.detailed-concepts-secure-channel-explained.aspx