```
netsh 

trace

netsh trace show scenarios

netsh trace show scenario <scenario name>

netsh trace show providers

netsh trace show CaptureFilterHelp

netsh trace netsh trace show interface

netsh trace start capture=yes report=yes ipv4.address=%target% tracefile="C:\Logs\%computername%_nettrace.etl"

//Reboot needed
persisten = yes

netsh trace stop
```



Error

"There is no trace session currently in progress."

Cause: Not run in the elevated CMD.



