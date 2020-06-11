remove-module AD.TimedGroupMembership -ErrorAction SilentlyContinue
import-module .\AD.TimedGroupMembership.psm1

$User  = 'TGMTester1'
$Group = 'SDL-TGMTest1'

$minutes = 30

Set-ADTGMGroupMember -User $User -Group $Group -Minutes $minutes -validate $true
Get-ADTGMGroupMember -User $User -Group $Group
#$Groupstatus = Get-ADGroup $Group -Property Member -ShowMemberTimeToLive | Where Name -eq $User
$User  = 'TGMTester2'
#Set-ADTGMGroupMember -User $User -Group $Group -Minutes $minutes -validate $true
Get-ADTGMGroupMember -User $User -Group $Group
$Group = 'SUG-TGMTest3'
$User  = 'TGMTester3'
Set-ADTGMGroupMember -User $User -Group $Group -Minutes $minutes -validate $true
Get-ADTGMGroupMember -User $User -Group $Group

Get-ADTGMGroup -Group $Group
$User  = 'TGMTester1'
Get-ADTGMUser -User $User
$User  = 'TGMTester2'
Set-ADTGMGroupMember -User $User -Group $Group -Minutes $minutes -validate $true
Get-ADTGMGroupMember -User $User -Group $Group
Get-ADTGMUser -User $User
