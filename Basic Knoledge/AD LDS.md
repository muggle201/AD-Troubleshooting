# AD LDS

Active Directory Lightweight Directory Service

与AD使用相同的Code，因此他们可以实现相同的功能，具体用于保护Domain Controllers中的数据。

假设你有一个Web Server向客户提供服务，假如将该Web Server直接安置于Domain Controller中，那么AD中一些重要数据有暴露风险。那么可以独立设置一个Web Server安装AD LDS，DC可以将User Account复制到Web Server，Web Server可以用来验证用户身份。至于其他的Objects则仍在AD数据库中受到保护，另外也可以在Web Server中存储其他Application Data，这些Application Data也不必存储于DC，AD数据库中。

#### Table of Contents
1. [Feature of AD LDS](## Feature of AD LDS)





## Difference between AD LDS and AD DS

- Supports multiple instances
- Runs on client OS
- Does not require DNS
  可以将全部数据存储于一台机器，因此也不需要去寻找其他服务
- No Group Policy Support
- No Global Catalog Support
- Cannot manage workstations/Servers
- Supports different sites and replication
  - Does not support trusts



 ## High Speed Access

Application可以更快的直接获取数据，而无需再通过网络去取得数据，因为LDS与Application就在一台机器上。
123123


## Provide Authentication and Security





