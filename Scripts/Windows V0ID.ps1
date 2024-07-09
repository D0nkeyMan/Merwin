$failedChecks = @()
$failedChecks = @()

function printLogo {
    Write-Output "
     /\        /\
    //\\      //\\
   (/\ \\,,,,/// \)
     \ '''''' /
     (___)(___)-.
      (0)  (0)''-._
       |~   ~ , '-._
       |      |  '-._
       |     /\   '-._        __..---'''''-.._.._
       |     | \   '-._  _.--'                _  '.
       )     |  \      ''                     \'\  \
      /      |   \                             | '\ \
     /_....__)    \                            |   '\\
    /        \     |                          /      ))
   |          |    |                         /      ((((
   |          |    |                        /        ))))
   | () ()    |     \     |          |  _.-'         (((
   '.        .'      '._. |______..| |-'|
     '------'           | || |     | || |
                        | || |     | || |   Developed by Donkey
                        | || |     | || |    From team Cyber V0ID!
                        | || |     | || |
                  _____ | || |_____| || |
                 /        |  /       |  |
                 \________\__\_______\__\"
}

function basicUserCheck{
  $users = Get-LocalUser
  $dangerous = "Administrator", "Guest", "CyberNoob", "CyberPro", "DefaultAccount", "WDAGUtilityAccount"
  $adminFound = $false
  $guestFound = $false

  foreach($u in $users){
    $name = $u.Name
    $status = $u.Enabled

    # Does Admin and Guest exist with default names
    if ($name -eq "Administrator"){
      $adminFound = $true
    }
    elseif ($name -eq "Guest"){
      $guestFound = $true
    }

    # Does each user have the correct enabled status
    if ($name -in $dangerous -and $status -eq $true){
      $output = "Dangerous user {0} is enabled!" -f $name
      $Global:failedChecks += $output
      Write-Warning $output
    }
    elseif ($name -notin $dangerous -and $status -eq $false){
      $output = "Safe user {0} is disabled!" -f $name
      $Global:failedChecks += $output
      Write-Warning $output
    }

    # Check account expiration date
    if ($u.AccountExpires){
      $output = "User {0} will expire!" -f $name
      $Global:failedChecks += $output
      Write-Warning $output
    }

    # Check if user can change password
    if ($u.UserMayChangePassword -eq $false){
      $output = "User {0} cannot change their password!" -f $name
      $Global:failedChecks += $output
      Write-Warning $output
    }

    # Check if password is required
    if ($u.PasswordRequired -eq $false){
      $output = "User {0} does not require a password!" -f $name
      $Global:failedChecks += $output
      Write-Warning $output
    }

    # Check if user must change password at next login
    if ($u.PasswordExpires -eq $true -or $u.PasswordLastSet -eq $true){
      $output = "User {0} does not need to change password at next login" -f $name
      $Global:failedChecks += $output
      Write-Warning $output
    }

    # Check password changeable date
    if ($u.PasswordChangeableDate -eq $false){
      $output = "User {0} has a password changeable date!" -f $name
      $Global:failedChecks += $output
      Write-Warning $output
    }
  }

  # Check Admin and Guest for existance
  if ($adminFound -eq $false){
    $output = "Default administrator account not found!"
    $Global:failedChecks += $output
    Write-Warning $output
  }
  if ($guestFound -eq $false){
    $output = "Default guest account not found!"
    $Global:failedChecks += $output
    Write-Warning $output
  }
}

function advancedUserCheck{
  $samUserKeys = Get-ChildItem HKLM:\SAM\SAM\Domains\Account\Users\*
  foreach ($user in $samUserKeys){
    foreach ($property in $user.Property){
      if ($property.Contains("Hint")){
        $output = "User with SAM identifier {0} has a password hint!" -f $user.name.substring(49)
        $Global:failedChecks += $output
        Write-Warning $output
      }
    }
  }
}

function reportReg($id, $name, $regKey, $regVal, $foundValue, $hardenedValue){
  $output = "ID: {0}`nName: {1}`nRegistry Key: {2}`nRegistry Value: {3}`nFound Value: {4}`nHardened Value: {5}`n" -f $id, $name, $regKey, $regVal, $foundValue, $hardenedValue
  $Global:failedChecks += $output
  Write-Output $output
}

function checkDiff($id, $name, $method, $regKey, $regVal, $val){
  switch ($method) {
    "RegistryVal" {
      $foundValue = (Get-ItemProperty -Path $regKey -name $regVal *>&1).$regVal -join ", "

      if ($foundValue -ne $val -and $foundValue -ne ""){
        reportReg $id $name $regKey $regVal $foundValue $val
      }
    }
    "RegistryKey" {
      $foundValue = (Get-Item -Path $regKey *>&1).property -join ", "

      if ($foundValue -ne $val -and $foundValue -ne ""){
        reportReg $id $name $regKey "N/A" $foundValue $val
      }
    }
  }
}

function hardenRegistry($regKey, $regVal, $hardenedValue, $operator){
  if (!(Test-Path $regKey)) {
    New-Item -Path $regKey -Force
  }
  $isNumber = [Int32]::TryParse($hardenedValue, [ref]$null)
  if ($isNumber){
    Set-ItemProperty -Path $regKey -Name $regVal -Value $hardenedValue -Type DWORD
  }
  else{
    Set-ItemProperty -Path $regKey -Name $regVal -Value $hardenedValue
  }
}

function checkRegistry($id, $name, $regKey, $regVal, $hardenedValue, $operator){
  $foundValue = (Get-ItemProperty -Path $regKey -name $regVal).$regVal
  $failed = $false

  switch($operator){
    "=" {
      if ($foundValue -ne $hardenedValue){
        $failed = $true
      }
    }
    "<=" {
      if ([int]$foundValue -gt [int]$hardenedValue){
        $failed = $true
      }
    }
    "<=!0" {
      if ([int]$foundValue -gt [int]$hardenedValue -or $foundValue -eq "0"){
        $failed = $true
      }
    }
    ">=" {
      if ([int]$foundValue -lt [int]$hardenedValue){
        $failed = $true
      }
    }
  }

  if ($failed){
    reportReg $id $name $regKey $regVal $foundValue $hardenedValue
  }
}

function reset(){
  $Global:failedChecks = @()
  Write-Output $Global:failedChecks
}

function hardenService($name, $hardened){
  $service = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($service){
    switch ($hardened) {
      "Manual"{
        Set-Service -Name $name -StartupType Manual
      }
      "Automatic"{
        Set-Service -Name $name -StartupType Automatic
        Start-Service -Name $name
      }
      "Disabled"{
        Stop-Service -Name $name
        Set-Service -Name $name -StartupType Disabled
      }
    }
  }
}

function checkService($name, $hardened){
  $service = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($service){
    if ($service.StartType -ne $hardened){
      $output = "Service Name: {0}`nCurrent Status: {1}`nHardened Status: {2}`n" -f $name, $service.StartType, $hardened
      $Global:failedChecks += $output
      Write-Output $output
    }
  }
}

$diff = Import-Csv ./diff.csv
$vulns = Import-Csv ./registry.csv
$services = Import-Csv ./services.csv

reset

do {
  Clear-Host
  printLogo
  Write-Host "=== Menu ==="
  Write-Host "0. Diff"
  Write-Host "1. Check Registry"
  Write-Host "2. Check Services"
  Write-Host "3. Check Users"
  Write-Host "4. Harden Registry"
  Write-Host "5. Harden Services"
  Write-Host "6. View"
  Write-Host "7. Reset"
  Write-Host "8. Exit"

  $choice = Read-Host "Enter your choice (0-8)"

  switch ($choice) {
      '0' {
          Write-Host "Diffing the system..."
          For ($i = 0; $i -lt $diff.Length; $i++){
            checkDiff $diff[$i].ID $diff[$i].Name $diff[$i].Method $diff[$i].RegistryPath $diff[$i].RegistryItem $vulns[$i].Value
          }
          $output = "Found {0} vulnerabilites..." -f $Global:failedChecks.Length
          Write-Output $output
          break
      }
      '1' {
          Write-Host "Checking registry configurations..."
          For ($i = 0; $i -lt $vulns.Length; $i++){
            checkRegistry $vulns[$i].ID $vulns[$i].Name $vulns[$i].RegistryPath $vulns[$i].RegistryItem $vulns[$i].RecommendedValue $vulns[$i].Operator
          }
          $output = "Found {0} vulnerabilites..." -f $Global:failedChecks.Length
          Write-Output $output
          break
      }
      '2' {
          Write-Host "Checking service configurations..."
          For ($i = 0; $i -lt $services.Length; $i++){
            checkService $services[$i].SName $services[$i].Hardened
          }
          $output = "Found {0} vulnerabilites..." -f $Global:failedChecks.Length
          Write-Output $output
          break
      }
      '3' {
          Write-Host "Checking user configurations..."
          basicUserCheck
          advancedUserCheck
          $output = "Found {0} vulnerabilites..." -f $Global:failedChecks.Length
          Write-Output $output
          break
      }
      '4' {
          Write-Host "Hardening the registry..."
          For ($i = 0; $i -lt $vulns.Length; $i++){
            hardenRegistry $vulns[$i].RegistryPath $vulns[$i].RegistryItem $vulns[$i].RecommendedValue $vulns[$i].Operator
          }
          break
      }
      '5' {
          Write-Host "Hardening service configurations..."
          For ($i = 0; $i -lt $services.Length; $i++){
            hardenService $services[$i].SName $services[$i].Hardened
          }
          break
      }
      '6' {
          Write-Host "Here are the found vulnerabilities..."
          For ($i = 0; $i -lt $Global:failedChecks.Length; $i++){
            Write-Output $Global:failedChecks[$i]
          }
          $output = "Found {0} vulnerabilites..." -f $Global:failedChecks.Length
          Write-Output $output
          break
      }
      '7' {
          Write-Host "Now resetting found vulnerabilities..."
          reset
          break
      }
      '8' {
          Write-Host "Exiting..."
          return
      }
      default {
          Write-Host "Invalid choice. Please select a valid option."
      }
  }

  # Prompt the user to press any key to continue
  Write-Host "`nPress any key to continue..."
  $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} while ($true)