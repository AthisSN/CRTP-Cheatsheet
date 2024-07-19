# CRTP Cheatsheet

# Domain Enumeration

#### PowerView Script 
https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1
```
Import-Module .\PowerView.ps1
```
#### Current and Other Domain Enumeration
```
Get-Domain
Get-Domain -Domain domain_name
```
#### SID of the Current Domain
```
Get-DomainSID
```
#### Domain Controller 
```
Get-DomainController
Get-DomainController -Domain domain_name
```
## Domain User Enumeration
#### List of Users in Current Domain
```
Get-DomainUser
Get-DomainUser -Identity user_name
```
#### Properties of Users in the current domain
```
Get-DomainUser -Identity user_name -Properties*
Get-DomainUser -Properties samaccountname
```
#### Searching for a particular string in a user's attribute
```
Get-DomainUser -LDAPFilter "Description=*built*" | select name, Description
```
#### Enumerating Computers in the current domain
```
Get-DomainComputer
Get-DomainComputer | select name
Get-DomainComputer -Operating System "*Server 2022*"
```
## Domain Group Enumeration
#### Groups in the current and other domains
```
Get-DomainGroup
Get-DomainGroup | select name
Get-DomainGroup -Domain domain_name
```
#### Groups containing the word in a group name
```
Get-DomainGroup *admin*
```
#### All members of the Domain Admin group
```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
#### Enumerating Group Membership of a user
```
Get-DomainGroup -UserName "user_name"
```
#### Listing All local groups on a machine
```
Get-NetLocalGroup
Get-NetLocalGroup -ComputerName computer_name
```
#### Members of Local Group "Administrators" on a machine
```
Get-NetLocalGroupMember
Get-NetLocalGroupMember -ComputerName computer_name -GroupName Administrators
```
#### Actively logged user on a computer
```
Get-NetLoggedon
Get-NetLoggedon -ComputerName computer_name 
```
#### Locally Logged Users on a computer
```
Get-LoggedonLocal
Get-LoggedonLocal -ComputerName computer_name
```
#### Last Logged User on a computer
```
Get-LastLoggedOn
Get-LastLoggedOn -ComputerName computer_name
```
### Enumerating Sensitive Shares and Files
#### Shares of Host in a current domain
```
Invoke-ShareFinder -Verbose
```
#### Sensitive Files on computers in the domain
```
Invoke-FileFinder -Verbose
```
#### Getting all fileservers of the domain
```
Get-NetFileServer
```
### GPO Enumeration
#### GPO in the current domain
```
Get-DomainGPO
Get-DomainGPO -ComputerIdentity computer_name
```
 #### Restricted Groups
 ```
Get-DomainGPOLocalGroup
```
#### Users which are in a local group of a machine using GPO
```
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity comp_name
```
#### Machines where the given user is a member of specific group 
```
Get-DomainGPOUserLocalGroupMapping -Identity user_name -Verbose
```
### OU Enumeration
#### OUs in a Domain
```
Get-DomainOU
```
#### GPO Applied on an OU 
```
Get-NetOU
Get-DomainDomainGPO -Identity "GPOName"
```
### ACL Enumeration
#### ACLs associated with specified object
```
Get-DomainObjectAcl -samaccountname name -ResolveGUIDs
```
#### ACLs associated with the specified prefix to be used for search 
```
Get-DomainObjectAcl -SearchBase "LDAP://CN=Domain Admins, CN=Users, DC=dcname -ResolveGUIDs -Verbose
```
#### Searching for Interesting ACEs
```
FindInterestingDomainACL -ResolveGUIDs
```
#### ACLs associated with the specified path 
```
Get-PathAcl -Path "\\dc.domain\sysvol"
```
### Trust Enumeration
#### All Domain Trust for the current and other domains
```
Get-DomainTrust
Get-DomainTrust -Domain domain_name
```
#### Forest Mapping
```
Get-Forest
Get-Forest -Forest forest_name
```
#### Domains in the current forest
```
Get-ForestDomain
Get-ForestDomain -Forest forest_name
```
#### Global Catalog for the current forest
```
Get-ForestGlobalCatalog -Forest forest_name
```
### User Hunting
#### Machine on the current domain where the user has local admin access
```
Find-LocalAdminAccess -Verbose
```
#### Computers where a DA (or specified user/group) has sessions
```
Find-DomainUserLocation
Find-DomainUserLocation -UserGroupIdentity "Group_name"
```
#### Computers where a DA session is available and current user has admin access
```
Find-DomainUserLocation -CheckAccess
```
#### Computers (File Servers and Distributed FS) where a DA session is available
```
Find-DomainUserLocation -Stealth
```
#### List Sessions on Remote Machine
```
Invoke-SessionHunter -FailSafe
```
#### List Sessions on Remote Machine (OPSEC Friendly)
```
Invoke-SessionHunter -NoPortScan -Targets Target_file_path
```
### BloodHound 
```
SharpHound.ps1
```
```
Invoke-BloodHound -CollectionMethod All
```
```
SharpHound.exe
```
#### BloodHound Stealther Usage 
```
Invoke-BloodHound -Stealth
```
```
SharpHound.exe --stealth
```
#### Avoiding MDI 
```
Invoke-BloodHound -ExcludeDCs
```



