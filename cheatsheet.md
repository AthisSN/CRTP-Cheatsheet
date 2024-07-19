# CRTP Cheatsheet

# Domain Enumeration

#### PowerView Script 
```
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```
#### Current Domain
```
Get-Domain
```
#### Object of Other Domain
```
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
#### 
