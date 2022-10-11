reference:

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee619754(v=ws.10)?redirectedfrom=MSDN

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776447(v%3dws.10)



在信任证书前，Windows将进行检查：

- Valid certificate
- Valid certificate path

通过以下三个不同又相互关联的过程来决定：（CryptoAPI）

- Certificate Discovery

- Path Validation

  通过Certificate及Issuer Certificate来完成以Self-Signed Certificate终止的层级结构。

- Revocation Checking

  Revocation Checking将发生在Chain building过程中或Chain building完成之后。



# Chain Building

建立一条Trust Chain/ Certificate Path的过程，从End Certificate到一个可信的root CA。



Chain Building的过程将通过检查certificate path中的每一张证书来验证该路径。这些certificate从以下获取：

- Intermediate Certification Authorities store
- Trusted Root Certification Authorities store
- 证书的AIA属性中的URL



若CryptoAPI发现路径中的任一证书有问题，或无法获取证书，那么该路径则作为nontrusted certification path被丢弃。

为提升表现，CryptoAPI会将sub CA证书存储在Intermediate Certification Authorities中来方便之后使用。



# Certificate Storage



