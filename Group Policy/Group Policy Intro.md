# What is a Group Policy

仅需一次便可配置用户环境，之后通过操作系统来配置环境。

> **Local Group Policy**
>
> Path: \%windows%\System32\GroupPolicy
>
> 当需要对小部分机器设置，或client端未加域。



# Group Policy and Active Directory Hierarchy

Group Policy遵循AD的层级结构，仅能链接至SDOUs。

> objectClass = Site\domainDNS\OrganizationalUnit



## Order of Group Policy Application

应用顺序参照 Local - Site - Domain - OUs，默认情况下，之前应用的policy将被后续的无论是**Enabled**或**Disabled**的policy覆盖；而那些**Not Configured**的policy不会覆盖之前应用的policy。

- Block Inheritance
- No Override



# Where GPOs Stored

Group Policy objects, named with a *GUID*:

- Group Policy Container (Stored in Active Directory)
  - Version
  - Status
  - Componentes with settings in GPO
- Group Policy Template (Stored in SYSVOL)
  - Gpt.ini
    - List of CSE
    - User Configuration
    - Computer Configuration 
  - Registry.pol
    - Registry settings from ADMX



## Group Policy Container (GPC)

Path: CN=Policies,CN=System,DC=domain,DC=local



### LDP View

1. LDP.EXE
2. Connections - Connect...
   1. FQDN of DC
   2. port == 389
3. Connections - Bind...
4. View - Tree
   1. DN of the Domain
5. Navigate to the **Policies\GUID**



### **Attribute**

- *displayname*: GPO的易读名称
- *gPCFileSysPath*: SYSVOL路径
- *gPCMachineExtensionNames*: Machine端所需的CSE
- *gPCUserEntensionNames*: User端所需的CSE

> **Important**
>
> *gPLink*: 该属性并不属于GPO，但可在GPO所在位置找到该属性，该属性用于让该container下的object知道有什么GPO需要去执行。



### **总结**

GPC让client端知道：

- 哪些GPO
- 哪些CSE
- 哪里找到GPO contents



## Group Policy Template