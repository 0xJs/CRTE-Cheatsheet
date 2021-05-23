# Domain Enumeration
* [Powerview Domain](#Powerview-Domain)
* [Powerview Users, groups and computers](#Powerview-users-groups-and-computers) 
* [Powerview Shares](#Powerview-shares)
* [Powerview GPO](#Powerview-GPO)
* [Powerview ACL](#Powerview-ACL)
* [Powerview Domain Trust](#Powerview-Domain-Trust)
* [User Hunting](#User-Hunting)
* [Bloodhound](#Bloodhound)

## Powerview Domain
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
```
. ./PowerView.ps1
```

#### Get current domain
```
Get-NetDomain
```

#### Get object of another domain
```
Get-NetDomain -Domain <domainname>
```

#### Get Domain SID for the current domain
```
Get-DomainSID
```

#### Get the domain password policy
```
Get-DomainPolicy
Get-DomainPolicyData
(Get-DomainPolicy)."System Access"
net accounts /domain
```

## Powerview users groups and computers
#### Get Information of domain controller
```
Get-NetDomainController
Get-NetDomainController | select-object Name
```

#### Get information of users in the domain
```
Get-NetUser
Get-NetUser -Username <username>
```

#### Get list of all users
```
Get-NetUser | select samaccountname
```

#### Get list of usernames, last logon and password last set
```
Get-NetUser | select samaccountname, lastlogon, pwdlastset
Get-NetUser | select samaccountname, lastlogon, pwdlastset | Sort-Object -Property lastlogon
```

#### Get list of usernames and their groups
```
Get-NetUser | select samaccountname, memberof
```

#### Get list of all properties for users in the current domain
```
get-userproperty -Properties pwdlastset
```

#### Get descripton field from the user
```
Find-UserField -SearchField Description -SearchTerm "built"
Get-netuser | Select-Object samaccountname,description
```

#### Get computer information
```
Get-NetComputer
Get-NetComputer -FullData
Get-NetComputer -Computername <computername> -FullData
```

#### Get computers with operating system ""
```
Get-NetComputer -OperatingSystem "*Server 2016*"
```

#### Get list of all computer names and operating systems
```
Get-NetComputer -fulldata | select samaccountname, operatingsystem, operatingsystemversion
```

#### List all groups of the domain
```
Get-NetGroup
Get-NetGroup -GroupName *admin*
Get-NetGroup -Domain <domain>
```

#### Get all the members of the group
```
Get-NetGroupMember -Groupname "Domain Admins" -Recurse
Get-NetGroupMember -Groupname "Domain Admins" -Recurse | select MemberName
```

#### Get the group membership of a user
```
Get-NetGroup -Username <username>
```

#### List all the local groups on a machine (needs admin privs on non dc machines)
```
Get-NetlocalGroup -Computername <computername> -ListGroups
```

#### Get Member of all the local groups on a machine (needs admin privs on non dc machines)
```
Get-NetlocalGroup -Computername <computername> -Recurse
```

#### Get actively logged users on a computer (needs local admin privs)
```
Get-NetLoggedon -Computername <computername>
```

#### Get locally logged users on a computer (needs remote registry rights on the target)
```
Get-LoggedonLocal -Computername <computername>
```

#### Get the last logged users on a computer (needs admin rights and remote registary on the target)
```
Get-LastLoggedOn -ComputerName <computername>
```

## Powerview shares
#### Find shared on hosts in the current domain
```
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC
```

#### Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```

#### Get all fileservers of the domain
```
Get-NetFileServer
```

## Powerview GPO
#### Get list of GPO's in the current domain
```
Get-NetGPO
Get-NetGPO -Computername <computername>
```

#### Get GPO's which uses restricteds groups or groups.xml for interesting users
```
Get-NetGPOGroup
```

#### Get users which are in a local group of a machine using GPO
```
Find-GPOComputerAdmin -Computername <computername>
```

#### Get machines where the given user is member of a specific group
```
Find-GPOLocation -Username student244 -Verbose
```

#### Get OU's in a domain
```
Get-NetOU -Fulldata
```

#### Get machines that are part of an OU
```
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}
```

#### Get GPO applied on an OU
gplink from Get-NetOU -Fulldata
```
Get-NetGPO -GPOname "{<gplink>}"
```

## Powerview ACL
#### Get the ACL's associated with the specified object
```
Get-ObjectACL -SamAccountName <accountname> -ResolveGUIDS
```

#### Get the ACL's associated with the specified prefix to be used for search
```
Get-ObjectACL -ADSprefix ‘CN=Administrator,CN=Users’ -Verbose
```

#### Get the ACL's associated with the specified path
```
Get-PathAcl -Path \\<Domain controller>\sysvol
```

#### Search for interesting ACL's
```
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
```

#### Search of interesting ACL's for the current user
```
Invoke-ACLScanner | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
```

## Powerview Domain trust
#### Get a list of all the domain trusts for the current domain
```
Get-NetDomainTrust
```

#### Get details about the forest
```
Get-NetForest
```

#### Get all domains in the forest
```
Get-NetForestDomain
Get-NetforestDomain -Forest <domain name>
```

#### Get global catalogs for the current forest
```
Get-NetForestCatalog
Get-NetForestCatalog -Forest <domain name>
```

#### Map trusts of a forest
```
Get-NetForestTrust
Get-NetForestTrust -Forest <domain name>
Get-NetForestDomain -Verbose | Get-NetDomainTrust
```

## User Hunting
### Check Local Admin Access
#### Powerview
```
Find-LocalAdminAccess -Verbose
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

#### Find computers where DA has sessions
```
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "StudentUsers"
```

#### Find computers where a domain admin session is available and current user has admin access
```
Find-DomainUserLocation -CheckAccess
```

#### Find computers (File servers and distributed file servers) where a domain admin session is available
```
Find-DomainUserLocation –Stealth
```

##  BloodHound
https://github.com/BloodHoundAD/BloodHound
```
cd Ingestors
. ./sharphound.ps1
Invoke-Bloodhound -CollectionMethod all -Verbose
Invoke-Bloodhound -CollectionMethod Acl -Verbose
Invoke-Bloodhound -CollectionMethod Sessions -Verbose
Invoke-Bloodhound -CollectionMethod LoggedOn -Verbose

#Copy neo4j-community-3.5.1 to C:\
#Open cmd
cd C:\neo4j\neo4j-community-3.5.1-windows\bin
neo4j.bat install-service
neo4j.bat start
#Browse to BloodHound-win32-x64
Run BloodHound.exe
#Change credentials and login
```
