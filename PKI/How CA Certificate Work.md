> The Caesar Cipher
>
> Algorithm (Date,Key) --- Encrypted









# CPPolicy.inf and Policy.inf

共同点：

- 由Administrator手动创建并定义
- 在Root及Subordinate CA创建时使用
- Are defined on the signing CA where you sign and issue the certificate, not the CA where the request is generated. (?)

不同

- CAPolicy.inf必须在安装前存放于%Systemroot%
- Policy.inf则存放于requesting computer的任意位置，任意名称

.inf文件的term

- Section
- Key
- Value



### Name Constraints

通过在CA上配置的CAPolicy.inf，添加该项，以限制允许或不包含的namespace。

CA则通过subject及subject alternate name对比自己的CAPolicy.inf来做出判断。



**Common Filter**

DIRECTORYNAME = 'DC=contoso,DC=com'

DNS = .contoso.com

UPN = @contoso.com

IPADDRESS = 192.168.1.0/255.255.255.0



**Result**

- Permitted
- Not permitted
- Excluded



**Rules**

- Excluded namespaces take precedence over permitted namespaces
- 作用于subject任何名称
- 从属CA不能允许被parent CA拒绝的namespace。
- subject的name及alternate name必须全部符合constraints
- 



### Policy Mapping

不同PKI hierarchies中类似的policy映射。

| Element | Sample Values|
| --- | --- |
| [PolicyMappingExtensions] | < foreign identifier >  = < local identifier > |

The qualified subordinate CA that contains this mapping is called the ***issuer CA*** and the subordinate CA whose policies have been mapped is called the ***subject CA***. 

**Issuer CA** subordiantes the **Subject CA**.



### Policy Constraints

CA层级结构，requires及inhibits的policy mapping深度。



### Application Policy





若certificate的extension包含application policy与EKU，那么EKU将被忽略。



### Basic Constraints

在另一结构中信任的CA层级深度。



### CRL (Certificate Revocation List) Distributions Points



### NewRequest

Mandatory for .inf file.

- If this section is missing, the following error message is displayed:
  **INF file line not found 0xe0000102 (INF: -536870654)**
- If this section is empty, the folloing error message is dispalyed:
  **Incorrect function. 0x1 (WIN32: 1)**

#### EncipherOnly

默认为False，若True，则key只能用于加密；若False，则key用于加密及其他目的。

#### ProviderName

```powershell
certutil -csplist
```

#### RenewalCert

若想更新现存certificate，必须指定hash value。

可以通过查看指定的certificate的Thumbprint属性查看。

#### Requestername

AD中的samAccountName

Requestname = "Domain\username"

####  Subject

Subject = CN=computer01.contoso.com

Subject = CN=Jow,CN=Users,DC=Contoso,DC=com



# CA Certificate Processes and Interactions

**Two type**

- End entity与CA共有的
- CA独特的

**Certificates验证过程**

- Certificate Discovery
  从Group Policy，Enterprise Policy，AIA等收集certificates
- Path Validation
  检查路径所有certificate直到root CA certificate
- Revocation Checking
  确认每个certificate不在CRL中



## Create Root CA Certificates

- Wizard
- CAPolicy.inf
  必须存于机器的systemroot

## Renew Root CA Certificates

仅在以下情况需要renew：

- Compromised
- 添加Certificate Policies
- 更改CDP/AIA path
- Partition a CRL

所有更改必须先在CAPolicy.inf文件中进行更改。











