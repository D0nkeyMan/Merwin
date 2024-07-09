function Check-Signature {
  param (
    [string]$path,
    [string]$fileExtension
  )

  $signedFiles = @()
  $unsignedFiles = @()

  # Recursively search for files with the specified extension in the input path
  $files = Get-ChildItem -Path $path -Recurse -Include "*.$fileExtension" -Force -ErrorAction SilentlyContinue

  # Iterate through each file
  foreach ($file in $files) {
    try {
        if (!($file.Fullname -match "WinSxS") -and !($file.Fullname -match "assembly")){
            $signature = Get-AuthenticodeSignature $file.FullName
            if ($signature.Status -eq "Valid") {
                $signedFiles += $file
                $copyrightStuff = (Get-Item $file.FullName)
                if(($signature.SignerCertificate.Issuer -match 'Microsoft Windows') -or ($copyrightStuff.VersionInfo.LegalCopyright -match 'Microsoft Corporation') -or ($copyrightStuff.VersionInfo.LegalCopyright -match 'VMware')){}
                else {
                    Write-Warning "$file is signed but the SignerCertificate Issuer/Copyright does not match Microsoft Windows"
                }
            }
            else{
                $unsignedFiles += $file
            }
        }
    }
    catch {
        # Ignore any permission errors and continue checking other files
        Write-Warning "Error accessing file: $file.FullName. Error: $_"
    }
  }

  foreach ($file in $unsignedFiles) {
    Write-Host $file.FullName
  }
}

$path = Read-Host "Enter the path to search in"
$fileExtension = Read-Host "Enter the file extension to search for (e.g. exe, dll, etc.)"
Check-Signature -path $path -fileExtension $fileExtension