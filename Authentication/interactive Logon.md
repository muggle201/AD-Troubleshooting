# What is Interactive Logon

- Authentication
  - Validating a user's identity
- Authorization
  - After authentication, "Authorization and Access Control" technologies determining if the user could access the local/network resources.

## Scenarios

- Locally
  - Physical Access
- Remotely
  - Terminal Services

- Local Account
- Domain Account

### Local Logon

Requires that the user have a user account in the SAM on the local computer.

Local user account ang group membership information is used to manage access to local resources.

### Domain Logon

Requires that the user have a user account in the domain.

Domain user account and group membership information is used to manage access to domain and local resources.

# How Interactive Logon Works

## Interactive Logon Architecture

**Components**

- Winlogon
- Graphical Identification and Authentication (GINA) dynamic-link library (DLL)
- Local Security Authority
- Authentication packages (NTLM and Kerberos)

### Local Logon

允许用户进入到local computer。

当用户本地登录时，通过将Authentication Package发送给SAM数据库以验证身份。该过程无需网络。

![LocalLogon](../IMG/local%20logon.jpeg)

**Process Order**
1. Winlogon
2. GINA DLL - Collect user's credentials and send to LSA
3. LSA verify the credentials, send Access Token to Winlogon
4. Active the user's shell by creating a new process (ie. Explorer.exe)

### Domain Logon

Both *Computer* and *User* have to be verified, since they are considered equal security principals.

> On a domain-joined computer, Windows is hard-coded to show only the last logged on user or Other user. Additional tiles for other users to log on are available only for computers joined to a workgroup.

![DoaminLogon](../img/DomainLogon.jpeg)

**Process Order**
1. Winlogon
2. GINA DLL - Collect user's credentials and send to LSA
3. LSA determine logon type. (Local/Domain Account)
4. LSA send Kerberos Authentication Package
5. DC verify the crendential.
6. Return the result to LSA.
7. Access Token generated.
8. Next Process

