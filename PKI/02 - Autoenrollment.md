



## Configure Certificate auto-enrollment

1. 选择Default Domain Policy
2. Navigate to Computer\User Configuration - Policies - Windows Settings - Security Settings - Certificate Services Client - Auto-Enrollment.
   1. Configuration Model, Enabled
   2. Renew expired certificates, Update Pending certificates, remove revoked certificates
   3. Update certificates that use certificate templates





## Certificate Autoenrollment Lab



### Minimum Requirement

- User and Machine应到对certificate template有Read，Enroll，Auto Enroll permission。
- “Supply in the request”不该被enabled，若启用则需手动填充细节。
- 在group policy中开启以下
  Computer Configuration -Windows Settings - Security Settings - Public Key Policies - Certificate Services Client - Auto-Enrollment

当满足以上，那么autoenrollment将在以下阶段enroll certificate：

- 机器重启
- logon
- GPO refresh interval



Manually Trigger Autoenrollment

```
certutil -pulse
```



> Note: Autoenrollment可能导致用户的personal store安装多个证书。
>
> 通过如图设置以避免
>
> ![img](https://social.technet.microsoft.com/wiki/cfs-filesystemfile.ashx/__key/communityserver-wikis-components-files/00-00-00-00-05/6303.auto4.jpg)



