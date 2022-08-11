## Intro

Types of CRLs:

- Base CRLs
- Delta CRLs
- Partitioned CRLs
  Via Issuing Distribution Point (IDP) extension, onlyContainsUsersCerts and onlyContainsCACerts fields去识别对应的CRLs

## Components Used  for Certs Status Checking

- CryptoAPI
- Certificates
- Certificate Stores
  Run ***certmgr.msc*** 



## Certificate Revocation Lists

A CRL是一个文件，由CA创建并签名，包含了被创建并被revoked证书的Serial Numbers.

![image-20220724141852452](C:\Users\dddih\AppData\Roaming\Typora\typora-user-images\image-20220724141852452.png)



### CRL version 2 Format

![image-20220724234503619](C:\Users\dddih\AppData\Roaming\Typora\typora-user-images\image-20220724234503619.png)



- **Issuer**	Issuing CA's DN

- Effective date

- Next update

- CRL Extensions

  - AKI
  - IssuerAltName
  - IDP
  - Signature algorithm
  - Freshest CRL

- CRL Entries

  ![image-20220724234939415](C:\Users\dddih\AppData\Roaming\Typora\typora-user-images\image-20220724234939415.png)

  - Serial Number
  - Revocation Date
  - Extensions
  - CRL Reason Code



### CRL Reason Codes



### CRL Creation

每个Revoked certs的serial number都将存于CA数据库中，并成为CRL的一部分，直到过期。一般而言，revoked且expired cert将在CRL额外保存一个interval直到client检测到expired，因此也不必检测expired cert的revocation。

若组织希望在CRL中一直保留revoked certificate无论是否expired，运行以下命令：

```
certutil -setreg ca\CRLFlags +CRLF_UBLISH_EXPIRED_CERT_CRLS
```

> 注意：过大的CRLs有performance issue。

### Delta CRLs

PKI中的挑战之一便为决定CRLs的最佳发布计划。若频繁发布完整的base CRL，将造成过大的网络流量，若不太频繁，又会使得client延迟确认newly revoked certificate。

> Clients将缓存CRL直到expired。

Delta CRLs则是发布自从上次发布base CRL后revoked certificates。客户可以较大间隔下载base CRL，较小间隔下载delta CRL。

> delta CRLs间隔应大于AD中Configuration NC复制到全部DC所需时间。

Delta CRL与下载base CRLs并不冲突。Base CRL在初始化阶段，及过期或快过期时，必须下载。Delta CRL也会要求client来下载base CRL以获取更精准的参考。

##### Delta CRL Extension

- **Delta CRL Indicator**	能接受的最早base CRL，若没有则CryptoAPI将尝试获取新base CRL。
- **Certificate Hold Processing**	若一个被revoked的Cert的status为*CertificateHold*，则需要一项”RemovedFromCRL“，以表明存在于base CRL中的一项将被un-revoked。
- **Distribution Point Name**	若该值与subject certificate中CDP Extension匹配，则该CRL被认为有效。
- 





