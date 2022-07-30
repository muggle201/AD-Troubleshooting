# The Debug Log Format

DFSR debug log 一致且可预期的。

## Header

> FRS Log Sequence:1 Index:1 **Computer**:2003MEM20 **TimeZone**:Eastern Standard Time (GMT-05:00) **Build**:[Feb 16 2007 20:14:20 built by: srv03_sp2_rtm] Enterprise=1 
> Configuration logLevel:4 maxEntryCount:200000 maxFileCount:100 logPath:\\.\C:\WINDOWS\debug\ 



| Field                  | Description         |
| ---------------------- | ------------------- |
| Computer               | 收log的机器         |
| TimeZone               | 时间                |
| Build                  | 版本                |
| Configuration loglevel | debug 级别，默认为4 |
| Maxentrycount          |                     |
| Maxfilecount           |                     |
| Logpath                | Output folder       |

## Single-line messages

