<#
 .Synopsis
  Active Directory Timed Group Membership module

 .Description
  Allows for Privelege Access Management feature to be enabled in the Forest and provide functions to set and get users and groups,
  supporting the management of timed group membership of a user into a group

 .Requires
  import-module activedirectory
 
 .Example
  See TGM_Examples.ps1
#>


function Get-ADTGMStatus {
    Param(
       [Parameter(Mandatory=$false)]
       [boolean]$ReturnStatus=$false
    ) #end param

# Check PIM Feature is enabled
    $ForestPartition = (Get-ADForest).PartitionContainer
    $status = Get-ADOptionalFeature -Filter {Name -like "Privileged*"}
    $ForestMode = (Get-ADForest).ForestMode
    $DomainMode = (Get-ADDomain).DomainMode
    $ModePass = ($ForestMode -like '*2016*' -or $ForestMode -like '*2019*') -and ($DomainMode -like '*2016*' -or $DomainMode -like '*2019*')

    # Check Forest Mode
    if(!$ReturnStatus) {
        $ForestPass = ($ForestMode -like '*2016*' -or $ForestMode -like '*2019*')
        $DomainPass = ($DomainMode -like '*2016*' -or $DomainMode -like '*2019*')

        if($ForestPass) {
            write-host "Forest Mode OK ($ForestMode)" -ForegroundColor green
        } else {
            write-host "Forest Mode must be at least 2016 to support PAM" -ForegroundColor red
        }

        #Check Domain Mode
        if($DomainPass) {
            write-host "Domain Mode OK ($DomainMode)" -ForegroundColor green
        } else {
            write-host "Domain Mode must be at least 2016 to support PAM" -ForegroundColor red
        }
    }

    if($ModePass -and $status.EnabledScopes -match $ForestPartition) {
        if($ReturnStatus) { return $true }
        else { Write-host "PAM Enabled. (Irreversible)" -ForegroundColor green }
    } else {  
        if($ReturnStatus) { return $false }
        else {
            write-host "PAM NOT Enabled" -ForegroundColor yellow
            write-host " NOTE: Use Set-ADTGMPAMEnable to enable" -ForegroundColor yellow
        }
    }
}

# Enable PAM Feature on Forest. Must confirm action as process is irreversable.
function Set-ADTGMPAMEnable {
    [CmdletBinding(
    SupportsShouldProcess=$True,
    ConfirmImpact=’High’
    )]param ()

    # Get domain name information
    $domain = (Get-ADDomain).DNSRoot

    # Check to see if PAM is current disabled and verify -confirm or interactive confirmation before performing action
    if(!(Get-ADTGMStatus -ReturnStatus $true) -and ($PSCmdlet.ShouldProcess("Enables Privileged Access Management Feature on $domain"))) {
        $domain = (Get-ADDomain).DNSRoot
        write-host "Forest $domain is compatible with Privileged Access Management Feature" -ForegroundColor green
        write-host "Enabling Privileged Access Management Feature on $domain" -ForegroundColor yellow
        Enable-ADOptionalFeature "Privileged Access Management Feature" -Scope ForestOrConfigurationSet -Target $domain
        Get-ADTGMStatus
    } # If not confirmed and PAM is disabled. Advise on usage. 
    elseif(!(Get-ADTGMStatus -ReturnStatus $true)) {
        $status = Get-ADTGMStatus -ReturnStatus $true
        if(!$status) { 
            write-host 'WARNING: Use "-confirm" parameter to enable Privileged Access Management Feature' -ForegroundColor red
            write-host "         This will make a change to the $domain forest" -ForegroundColor red
            write-host '         The action is irreversible.' -ForegroundColor red
        }
    } else {
        write-host "PAM Already Enabled" -foregroundColor green
    }
}

function Get-ADTGMGroupMember {
    # Need to account for different scenarios:
    # 1. Group has no members
    # 2. Group has user as normal (non-TTL) member
    # 3. Group has user as TTL member
    # 4. Group has members but not the user requested

    Param(
       [Parameter(Mandatory=$true)]
       [string]$User='',
       [Parameter(Mandatory=$true)]
       [string]$Group=''
    ) #end param

    $CurrentTime = Get-Date
    $Groupstatus = @()
    $Groupstatus = Get-ADGroup $Group -Property Member -ShowMemberTimeToLive -ErrorAction SilentlyContinue

    if($Groupstatus.Member.Count -ge 1) {
            For($n=0;$n -le ($Groupstatus.Member.Count);$n++) {
                $Member = $Groupstatus.Member[$n]
                if($Member -imatch $User -and $Member -like '<TTL=*') {
                    $TTLSeconds = ($Member -split ',')[0].Replace('<TTL=','').Replace('>','')
                    $TTL = New-TimeSpan -Seconds $TTLSeconds
                    $ExpiryTime = $CurrentTime.Add($TTL)
                    $Report = [PSCustomObject]@{    
                      User            = $User
                      Group           = $Group
                      CurrentTime     = $CurrentTime
                      TTLExpiryTime   = $ExpiryTime
                      TTLSeconds      = $TTLSeconds
                      TTLTimeSpan     = $TTL
                      Status          = 'TTL MEMBER'
                      isTTL           = $true
                    }
                    $Report
                    break
                    #write-host "User $User has access to $Group for $minutes minutes. Expiring $ExpiryTime" -Verbose
                } elseif($Member -imatch $User) {
                    # User is a member of the group, but not with a TTL
                    $Report = [PSCustomObject]@{    
                        User        = $User
                        Group       = $Group
                        CurrentTime = $CurrentTime
                        TTLExpiry   = ''
                        TTLSeconds  = ''
                        TTLTimeSpan = ''
                        Status      = 'STANDARD MEMBER'
                        isTTL       = $false

                    }
                    $Report
                } #If
            } #For

            # If the group has members, but not the one we've attempted to add. Report failure
            if($Report.User -ne $User) {
                $Report = [PSCustomObject]@{    
                    User        = $User
                    Group       = $Group
                    CurrentTime = $CurrentTime
                    TTLExpiry   = ''
                    TTLSeconds  = ''
                    TTLTimeSpan = ''
                    Status      = 'User NOT Member'
                    isTTL       = $false
                }
                $Report
                #$Groupstatus.Member
            }
     # If the Members can't be listed for the group. Report failure
     } else {
            $Report = [PSCustomObject]@{    
              User        = $User
              Group       = $Group
              CurrentTime = $CurrentTime
              TTLExpiry   = ''
              TTLSeconds  = ''
              TTLTimeSpan = ''
              Status      = 'NO MemberTimeToLive Members'
              isTTL       = $false
            }
            $Report
            #$Groupstatus.Member 
    }
}

function Set-ADTGMGroupMember {
    Param(
       [Parameter(Mandatory=$true)]
       [string]$User='',
       [Parameter(Mandatory=$true)]
       [string]$Group='',
       [Parameter(Mandatory=$true)]
       [int32]$Minutes=1,
       [boolean]$validate=$false
    ) #end param

    Try{
        $setminutes = New-TimeSpan -Minutes $minutes
        $status = Add-ADGroupMember -Identity $Group -Members $User -MemberTimeToLive $setminutes -ErrorAction SilentlyContinue
    } Catch {
        return $false    
    }    
    if($validate) {
        Get-ADTGMGroupMember -User $User -Group $Group
    }
}

function Get-ADTGMUser {
    Param(
       [Parameter(Position=0,Mandatory=$true)]
       [string]$User=''
    ) #end param
    
    $UserDetails = Get-ADUser -Identity $User -Properties Name,CN,DisplayName,DistinguishedName,Mail,userPrincipalName,GivenName,MemberOf,Enabled
    #$UserDetails
    $AllGroups = @()
    ForEach($Member in $UserDetails.MemberOf) {
        $GroupName = (Get-ADGroup -Identity $Member -Properties Name).Name
        $GroupDetails = Get-ADTGMGroupMember -User $User -Group $GroupName
        if($GroupDetails.isTTL) {
            $AllGroups += [PSCustomObject]@{    
                User            = $UserDetails.Name
                UserDN          = $UserDetails.DistinguishedName
                Group           = $GroupName
                TTLExpiryTime   = $GroupDetails.TTLExpiryTime
                TTLSeconds      = $GroupDetails.TTLSeconds
                TTLTimeSpan     = $GroupDetails.TTLTimeSpan
                Status          = $GroupDetails.Status
                isTTL           = $true
                }
        } else {
            $AllGroups += [PSCustomObject]@{    
                User            = $UserDetails.Name
                UserDN          = $UserDetails.DistinguishedName
                Group           = $GroupName
                TTLExpiryTime   = ''
                TTLSeconds      = ''
                TTLTimeSpan     = ''
                Status          = $GroupDetails.Status
                isTTL           = $false
                }
        }
    }
    if($AllGroups.count -eq 0) {
                $AllGroups += [PSCustomObject]@{    
                User            = $UserDetails.Name
                DistinguishedName = $UserDetails.DistinguishedName
                Group           = ''
                TTLExpiryTime   = ''
                TTLSeconds      = ''
                TTLTimeSpan     = ''
                Status          = 'No Group Membership'
                isTTL           = $false
                }
    }
    $AllGroups
}

function Get-ADTGMGroup     {

    Param(
       [Parameter(Mandatory=$true)]
       [string]$Group=''
    ) #end param

    $GroupDetails = @()
    $AllReports = @()
    $GroupDetails = Get-ADGroup $Group -Property Member -ShowMemberTimeToLive -ErrorAction SilentlyContinue
    $CurrentTime = Get-Date

    if($GroupDetails.Member.Count -ge 1) {
            ForEach($Member in $GroupDetails.Member) {
                # Check if the membership is prefixed with a TTL. If so, extract it
                if($Member -like '<TTL=*') {
                    $TTLSeconds = ($Member -split ',')[0].Replace('<TTL=','').Replace('>','')
                    $TTL = New-TimeSpan -Seconds $TTLSeconds
                    $TTLExpiryTime = $CurrentTime.Add($TTL)
                    $UserDN = $Member.Replace("<TTL=$TTLSeconds>,",'')
                    $isTTL = $true
                } else {
                    $TTLSeconds = ''
                    $TTL = ''
                    $TTLExpiryTime = ''
                    $UserDN = $Member
                    $isTTL = $false
                }
                
                # Get the user details so we return the samAccountName rather than just the DN. Can be expanded to return more if necessary
                $User = (Get-ADUser -Identity $UserDN -Properties samAccountName).samAccountName
                $Report = [PSCustomObject]@{    
                  User            = $User
                  UserDN          = $UserDN
                  Group           = $Group
                  GroupDN         = $GroupDetails.DistinguishedName
                  GroupScope      = $GroupDetails.GroupScope
                  GroupCategory   = $GroupDetails.GroupCategory
                  CurrentTime     = $CurrentTime
                  TTLExpiryTime   = $TTLExpiryTime
                  TTLSeconds      = $TTLSeconds
                  TTLTimeSpan     = $TTL
                  isTTL           = $isTTL
                }
                $AllReports += $Report
            } #For

     # If the Members can't be listed for the group. Report failure by providing largely empty object
     } else {
            $Report = [PSCustomObject]@{    
              User            = ''
              UserDN          = ''
              Group           = $Group
              GroupDN         = $GroupDetails.DistinguishedName
              GroupScope      = $GroupDetails.GroupScope
              GroupCategory   = $GroupStatus.GroupCategory
              CurrentTime     = $CurrentTime
              TTLExpiry       = ''
              TTLSeconds      = ''
              TTLTimeSpan     = ''
              }
            $AllReports += $Report
    }
    $AllReports
}

Export-ModuleMember -Function Get-ADTGMGroup,Get-ADTGMUser,Get-ADTGMGroupMember,Get-ADTGMStatus,Set-ADTGMPAMEnable

#New-ModuleManifest -Path S:\Server\Scripts\AD.TimedGroupMembership\AD.TimedGroupMembership.psd1 -ModuleVersion "1.0" -Author "Chris Harris"

