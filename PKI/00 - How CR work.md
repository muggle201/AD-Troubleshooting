# How Certificate Revocation Works



## 基本Certificate Chain验证

1. 使用本地缓存的certificates建立所有可能的certificate chain。若并非以root /self-signed certificate结尾，则CryptoAPI选择一条最佳chain并尝试通过AIA extension获取issuer certificate以完成chain。该过程将一直重复，直至获取到root/self-signed certificate。
2. 从root CA开始往下检查
3. 对每一个以root/self-signed certificate结束的certificate chain进行revocation checking。
4. Revocation checking对certificate chain中所有证书检查。



### Chain building

CryptoAPI尝试建立所有可能的Certificate Chain，并从以下位置获得certificate：

- Application提供，一些application可能预载所有证书并分发给client
- 已被certificate validation engine （Crypt32.dll）cache的一组certificates
- 本地certificates，并包含通过group policy发布的certificate。
- CrptoAPI缓存在本地磁盘的certificate
- 通过AIA extension标注的位置，从网络获取。



### Certificate Validation

当CryptoAPI开始验证certificate chain(s)中的每个certificates

1. CryptoAPI确认证书是否属于Untrusted certificate store，若存在于该store则直接disallowed。
2. 确认certificate是否包含Stapled OCSP response，若有且有效，则以该值验证revocation status。
3. 若存在一个CRL匹配issuer name，则使用该CRL
4. 若stapled response或CRL不存在，则CryptoAPI必须通过URL retrieval来决定该证书的revocation状态。
5. URLs for OCSP和CDP以下列顺序建立：
   - OCSP URLs from Group Policy
   - ORCS URLS from AIA extension
   - CRL URLs from CDP extension



以下两种情况，CryptoAPI可能在检索OCSP URLs之前检索CRLs

- Cached OCSP responses以超过设定值，该值由group policy设置
- Group policy配置了CRLs优先于OCSP

> 仅评估终止于root CA的Certificate chain



## 确认Revocation信息

若发现证书被revoked，那么revocation date则通过比较当前时间与CRL或OCSP response中的RevocationDate来确认。



## Network Retrieval and Caching

CryptoAPI首先在自身的diks cache确认是否有有效的revocation object，若无则执行network retrieval。



### Basic Operation

若没找到，则Crypto开始backgroup thread对每一个存在的URL开始network retrieval，默认每个calling thread等待15秒。

1. 若超过15秒，报告*Offline Error*，进行下一个URL。
2. 若application在第一次backgroung retriveal进行时发起第二次certificate验证，则第二次立即失败。

Crypto能防止从unreachable URLs获取，为拒绝持续的对unreachable URLs尝试：

1. Unreachable URL会被添加入Unreachable URLs List。
2. CryptoAPI确认下次对unreachable URLs发起尝试的最早时间。在该时间前尝试会立即失败，并报报告*Offline Error*。
3. 到时间后，CryptoAPI会继续尝试，若失败则延长时间，最好30分钟。
4. 若成功，则间隔重置为15秒



### HTTP Operations



### LDAP Server Retrieval

若尝试从LDAP server下载CRL，则开始以下：

1. 若host name未包含在LDAP URL中，则默认该CRL位于AD中并向最近的DC发起LDAP query
2. CryptoAPI最多发起3次尝试
   1. 首先bind LDAP server启用mutual authentication with LDAP_OPT_VERSION set to V3，Kerberos
   2. 若server回复LDAP_AUTH_METHOD_NOT_SUPPORTED或LDAP_INVALID_CREDENTIALS，则CryptoAPI使用anonymous authentication （zero lenght username）with LDAP_OPT_VERSION set to V3。
   3. 若失败，则再次尝试LDAP_OPT_VERSION set to V2



### Disk and Memory Caches

使用以下两种来存储CRLs和OCSP responses：

- Disk Cache。存储CRLs及OCSP responses的副本，位于Local file system，直到过期。
- Memory Cache。存储指定process使用的revocation信息，若process中止，则flush。

| Location     | Windows XP and Windows Server 2003                           | Windows Vista and Windows Server 2008                        |
| :----------- | :----------------------------------------------------------- | :----------------------------------------------------------- |
| Per User     | C:\Documents and Settings\username\Application Data\Microsoft\CryptnetUrlCache | C:\Users\username\AppData\LocalLow\ Microsoft\CryptnetUrlCache |
| Per Computer | C:\Windows\System32\config\ systemprofile\Application Data\ Microsoft\CryptnetUrlCache | C:\Windows\System32\config\ systemprofile\AppData\LocalLow\ Microsoft\CryptnetUrlCache |



#### Related Command

- Disk Cache

```powershell
# Delete CRL Cache
certutil -urlcache crl delete
# Delete OCSP cache
certutil -urlcache ocsp delete
# Delete All
certutil -urlcache * delete

# View CRL
certutil -urlcache crl
# View OCSP
certutil -urlcache ocsp
```

- Memory Cache

相较于清除Disk Cache，更推荐使得Memory Cache无效

```powershell
# Invalidate All
certutil -setreg chain\ChainChcheResyncFiletime @now
# Invalidate cached items in 1day,2hours
certutil -setreg chain\ChainChcheResyncFiletime @now+1:2
# Identify the last time that the cache was invalidated
certutil -getreg chain\ChainCacheResyncFiletime

```

> 若ChainCacheResyncFiletime从未被手动创建，那么该值将不存在且getreg无法运行。Reset该值，通过setreg命令将该值设定的足够老。
