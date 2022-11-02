W32Time.dll

%systemroot%\System32



Important for security issue, such as any Kerberos-aware application.



## Critical Factors for Accurate Time

- Solid Source Clock
  - Hardware/Stratum 1 source
  - Secure time sore to avoid time based attacks
- Stable Client Clock
  - Firmware updates
- Symmetrical NTP communication



## Why Important

- Cryptography Algorithms
- Distributed Systems (Cluster/SQL/Exchange)
- AD Replication



# Windows Time Service Architecture

The Windows timer service consists of the following components:

- Service Control Manager
- Windows Time Service Manager
- Clock Discipline
- Time Providers



Basic steps:

1. Input Providers

   Request and receive time samples from configured NTP source

2. Windows Time Service Manager

   Collects all sample and pass them to clock discipline

3. Clock Discipline

   Select the best time sample

4. Clock Discipline

   Adjust the system time

5. Output Provider (optional)

   Send the time to any computer requesting time synchronization



# Windows Time Service Time Protocols

A time protocol is responsible for determining the best time sample and converging the clock



NTP Algorithms

- Clock-filtering Algorithm
  Sift through time samples that are received from time source.
  Determine the best time samples from each source.
- Clock-selection Algorithm
  Determine the most accurate time server



These information will be then passed to Clock Discipline Algorithms, which used these information to correct the time.



NTP Provider

Pluggable, obtaining time samples or providing time samples.



NTP Security

NTP packet should be signed with computer's Kerberos session key from Net Logon Service, unsigned packet will be rejected.

































Reference:

[Support boundary for high-accuracy time | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/support-boundary)

