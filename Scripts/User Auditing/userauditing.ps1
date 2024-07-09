$authorized_users = @()
$authorized_admins = @()
$authorized_groups = @()
$rids = @()

$defaultUsers = "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount"
$defaultGroups = "Access Control Assistance Operators", "Administrators", "Backup Operators", "Certificate Service DCOM Access", "Cryptographic Operators", "Device Owners", "Distributed COM Users", "Event Log Readers", "Guests", "Hyper-V Administrators", "IIS_IUSRS", "Network Configuration Operators", "Performance Log Users", "Performance Monitor Users", "Power Users", "Print Operators", "RDS Endpoint Servers", "RDS Management Servers", "RDS Remote Access Servers", "Remote Desktop Users", "Remote Management Users", "Replicator", "Storage Replica Administrators", "System Managed Accounts Group", "Users"

foreach($admin in $(Get-Content -Path ".\admins.txt")){
    $authorized_admins += $admin
    $authorized_users += $admin
}

foreach($user in $(Get-Content -Path ".\users.txt")){
    $authorized_users += $user
}

foreach($group in $(Get-Content -Path ".\groups.txt")){
    $authorized_groups += $group
}


$all_users = (Get-LocalUser | Where-Object { $_.Name -notin $defaultUsers }).Name | Format-Table -HideTableHeaders | Out-String
$all_users = $all_users -split "`n"
$all_users = $all_users[0..($all_users.Count - 2)]

For ($i = 0; $i -lt $all_users.Length; $i++){
    $all_users[$i] = $all_users[$i].Substring(0, $all_users[$i].Length - 1)
}

#Check for unathorized users
foreach ($user in $all_users){
    if ($user -notin $authorized_users){
        Write-Host "Unauthorized user " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host " detected" -ForegroundColor Red
    }
}

$all_groups = Get-LocalGroup
#Check for unauthorized groups
foreach ($group in $all_groups){
    if ($group -notin $defaultGroups -and $group -notin $authorized_groups){
        Write-Host "Unauthorized group " -NoNewline -ForegroundColor Red
        Write-Host $group -NoNewline -ForegroundColor DarkYellow
        Write-Host " detected" -ForegroundColor Red
    }
}

#Check for unauthorized administrators
foreach ($user in Get-LocalGroupMember "Administrators"){
    if ($user -notin $authorized_admins){
        Write-Host "Unauthorized administrator " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host " detected" -ForegroundColor Red
    }
}

#Check for authorized users
foreach ($user in $authorized_users){
    if ($user -notin $all_users){
        Write-Host "Authorized user " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host " NOT detected" -ForegroundColor Red
    }
}

$users = Get-LocalUser

#Fix user properties
foreach ($user in $users){
    net user $user.name "Cyb3rV0ID@2023" | Out-Null
    net user $user.name /passwordreq:yes | Out-Null
    net user $user.name /passwordchg:yes | Out-Null
    net user $user.name /expires:"never" | Out-Null
    Set-LocalUser -Name $user.name -PasswordNeverExpires $false | Out-Null
    net user $user.name /logonpasswordchg:yes | Out-Null
}

#Check for enabled default users
foreach ($user in $users){
    if ($user -in $defaultUsers -and $user.Enabled){
        Write-Host "Default account " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host " is enabled" -ForegroundColor Red
    }
}

#Check user properties
foreach ($user in $users){
    if ($user.Name -in $defaultUsers){
        continue
    }
    if (-not $user.PasswordExpires -and -not $user.UserMayChangePassword){
        Write-Host "User " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host "'s password never expires" -ForegroundColor Red
    }
    if (-not $user.UserMayChangePassword){
        Write-Host "User " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host " cannot change password" -ForegroundColor Red
    }
    if (-not $user.PasswordRequired){
        Write-Host "User " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host " doesn't require a password" -ForegroundColor Red
    }
    if ($null -ne $user.PasswordLastSet){
        Write-Host "User " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host " doesn't have to change password on next login" -ForegroundColor Red
    }
    if (-not $user.Enabled){
        Write-Host "User " -NoNewline -ForegroundColor Red
        Write-Host $user -NoNewline -ForegroundColor DarkYellow
        Write-Host " is disabled" -ForegroundColor Red
    }
}

#Password Hints, Login UI, and RID hijacking
$sam = Get-ItemProperty -Path 'HKLM:\SAM\SAM\Domains\Account\Users\*'
for ($i=0; $i -lt $sam.Length-1; $i++){
    if($sam[$i].PSObject.Properties.Name -contains 'UserPasswordHint'){
        Write-Host "Password hint under " -NoNewline -ForegroundColor Red
        Write-Host $sam[$i].pschildname -NoNewline -ForegroundColor DarkYellow
        Write-Host " detected" -ForegroundColor Red
    }
    if($sam[$i].PSObject.Properties.Name -contains 'UserDontShowInLogonUI'){
        Write-Host "RID " -NoNewline -ForegroundColor Red
        Write-Host $sam[$i].pschildname -NoNewline -ForegroundColor DarkYellow
        Write-Host " Doesn't show up in login screen" -ForegroundColor Red
    }
    $rid = $sam[$i]."F"[49].toString("X2") + $sam[$i]."F"[48].toString("X2")
    if($rid -ne $sam[$i].pschildname.substring(4,4)){
        Write-Host "RID " -NoNewline -ForegroundColor Red
        Write-Host $sam[$i].pschildname -NoNewline -ForegroundColor DarkYellow
        Write-Host " hijacking detected" -ForegroundColor Red
    }
    $rids += $rid
}
Write-Host "List of RIDs:" -ForegroundColor Cyan
$rids

Write-Host "----------------------------------------------------------------------------" -ForegroundColor Cyan
$users | Format-Table name,principalsource,accountexpires,objectclass
$all_groups | Format-Table name,principalsource,objectclass
Write-Host "----------------------------------------------------------------------------" -ForegroundColor Cyan
foreach ($group in $all_groups){
    Write-Host $group.name: -ForegroundColor Blue
    Get-LocalGroupMember $group.Name | Format-Table objectclass,principalsource,name
}