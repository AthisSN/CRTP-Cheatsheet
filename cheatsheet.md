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





