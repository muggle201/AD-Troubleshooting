ConvertFrom-StringData @'
id_rdsserverprogress=Gathering RDS Information:
id_rdswmiget=Getting Win32_TerminalServiceSetting from WMI.
id_rdswmigeterror=ERROR: WMI not working. unable to get Win32_TerminalServiceSetting.
id_rdswmigetsolution=Please verify that WMI service running using wbemtest.
id_rdsiis=Getting IIS configuration.
id_rdspowershell=Getting RDS configuration using PowerShell. (could take up to 3 minutes/role).
id_rdssaved=Saved:
'@
