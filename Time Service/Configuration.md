# Configure w32tm on PDC in the Forest Root Domain



Configure NTP source:

- Internal time source
  - Hardware clock

- External time source
  - Microsoft Time Server (time.windows.com)
  - NIST
  - USNO

> Synchronize with an external time source would be less secure.



## Steps



1. Log on the 1st DC

2. Run following command with elevated CMD
   ```
   w32tm /stripchart /computer:<target> /samples:<number> /dataonly
   ```

3. Open UDP port 123 for outgoing traffic

4. Open UDP port 123

5. Run the following command the configure PDC
   ```
   w32tm /config /manualpeerlist:<peers> /syncfromflags:manual /reliable:yes /update
   ```

   

# Configure a client compute for automatic domain time synchronization

```
w32tm /config /syncfromflags:domhier /update

net stop w32time && net start w32time
```

