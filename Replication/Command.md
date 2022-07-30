# 快速检查复制状态

**CMD**

```powershell
repadmin /replsum 
repadmin /showrepl 
```

**PowerShell**

```powershell
# 显示指定DC最近一次成功复制时间
Get-ADReplicationPartnerMetadata <DOmainController> | FL LastReplicationSuccess
```

该命令永远是检查复制问题的起点。



# 潜在的复制问题

CMD

```powershell
dcdiag /test:replications
repadmin /showrepl /errorsonly
```

PowerShell

```powershell
Get-ADReplicationFailure "<DCName>"
```

Directory Service event log在复制及KCC问题时可能不是有价值的信息来源。



# Enable Diagnostics Logging

**CMD**

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v
"<LoggingSetting>" /t REG_DWORD /d <0-5>
```

**PowerShell**

```powershell
Set_ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\"
Diagnostics" -Name "<LoggingSetting>" -Value "<FlagValue>"
```



对于特定问题可以提升diagnostics logging level。

1. Knowledge Consistency Checker
2. Security Events
3. ExDS Interface Events
4. MAPI Interface Events
5. Replication Events
6. Garbage Collection
7. Internal Configuration
8. Directory Access
9. Internal Processing
10. Performance Counters
11. Initialization/Termination
12. Service Control
13. Name Resolution
14. Backup
15. Field Engineering
16. LDAP Interface Events
17. Setup
18. Global Catalog
19. Inter-site Messaging
20. Group Caching
21. Linked-Value Replication
22. DS RPC Client
23. DS RPC Server
24. DS Schema
25. Transformation Engine
26. Claims-Based Access Control



# 两个DC是否同步

**CMD**

```shell
repadmin /showutdved <DC1> <NamingContextDN>
repadmin /showutdvec <DC2> <NamingContextDN>
```

**Powershell**

```powershell
Get-ADReplicationUpToDatenessVectorTable -Target DC1,DC2
```



比较两个DC是否同步，需要比较他们各自的UTDV。因为该表存储了DC认为其他各个DC最高的USN。

比较DC1，DC2，那么得到DC1的UTDV表，将DC1的highest USN与DC2认为的DC1的highest USN进行比较，若不同则可查看谁未完成复制，反之亦然。



# 查看DC间Unreplicated Changes

**CMD**

```powershell
repadmin /showchanges <DC1Name> <NamingContextDN>
repadmin /showchanges <DC2Name> <NamingContextDN>
```

若发现DC间信息不一致



# 强制复制

**Active Directory Sites and Services**

Replicate Now

**CMD**

```powershell
repadmin /replicate <DC1Name> <DC2Name> <NamingContextDN>
```

**PowerShell**

```powershell
$strDCname = <DomainDNSName>
$context = New-Object
System.DirectoryServices.ActiveDirectory.DirectoryContext('DirectoryServer',$strDCname)
$dc = 
[System.DIrectoryServices.ActiveDirectory.DomainController]
::getDomainController($context)
$strPartDN = "<Partition DN>"
$dc.TriggerSyncReplicaFromNeighbors($strPartDN)
```

PowerShell命令则使得DC触发与其所有replication partners的复制。



# Enabling and Disabling Replication

**CMD**

```powershell
repadmin /options <DCName> +DISABLE_OUTBOUND_REPL

repadmin /options <DCName> -DISABLE_OUTBOUND_REPL

repadmin /options <DCName> +DISABLE_INBOUND_REPL

repadmin /options <DCName> -DISABLE_INBOUND_REPL
```

当在某DC进行重大变更时可以启用，比如对schema进行更改。



# Enabling Strict or Loose Replication Conisitency

**修改注册表**

```powershell
# Enable strict
> reg add HKLM\System\CurrentControlSet\Services\NTDS\Parameters /v "Strict
Replication Consistency" /t REG_DWORD /d 1

# Enable loose
> reg add HKLM\System\CurrentControlSet\Services\NTDS\Parameters /v "Strict
Replication Consistency" /t REG_DWORD /d 0
```

**CMD**

```powershell
repadmin /regkey <DCName> +strict
repadmin /regkey <DCName> -strict

repadmin /regkey * +strict
```

开启后，DC将不再复制lingering objects，这种拒绝也会记录下 Event ID 1804，同时也是监测是否有Lingering objects渗透入forest的方法。



# 获得某DC的Replication Partners

**CMD**

```powershell
dsquery * "cn=NTDS Settings,cn=<DCName>,cn=Servers,cn=<SiteName>,
cn=Sites,cn=Configuration,<ForestRootDN> -filter
(objectcategory=NTDSConnection) -attr *
```

**PowerShell**

```powershell
Get-ADReplicationConnection -Server "<DCName>"
```

















