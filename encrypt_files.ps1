# Define paths
$FolderPath = "C:\Users\AakashChopra\Desktop\test12345"
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$EncryptionKeyPath = "$DesktopPath\encryption_key.txt"

# Generate a random encryption key if it doesn't exist
if (!(Test-Path $EncryptionKeyPath)) {
    try {
        Write-Host "Generating encryption key..."
        # Generate a 32-byte random key
        $RandomBytes = New-Object byte[] 32
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($RandomBytes)
        $Key = [System.Convert]::ToBase64String($RandomBytes)
        # Save the key to the file
        Set-Content -Path $EncryptionKeyPath -Value $Key -Encoding ASCII
        Write-Host "Encryption key saved to $EncryptionKeyPath. Keep it safe!"
    } catch {
        Write-Error "Failed to generate encryption key: $_"
        exit 1
    }
} else {
    try {
        # Read the existing key
        $Key = Get-Content -Path $EncryptionKeyPath -Raw
        if ([string]::IsNullOrWhiteSpace($Key)) {
            throw "Encryption key file is empty."
        }
    } catch {
        Write-Error "Failed to read the encryption key: $_"
        exit 1
    }
}

# Convert the key to bytes
$KeyBytes = [System.Convert]::FromBase64String($Key)

# Encrypt a file
function Encrypt-File {
    param (
        [string]$FilePath
    )
    $EncryptedFilePath = "$FilePath.enc"
    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = $KeyBytes
    $Aes.GenerateIV()
    $IV = $Aes.IV

    $Encryptor = $Aes.CreateEncryptor()
    $EncryptedBytes = $Encryptor.TransformFinalBlock($FileBytes, 0, $FileBytes.Length)
    
    # Save IV + encrypted content
    [System.IO.File]::WriteAllBytes($EncryptedFilePath, $IV + $EncryptedBytes)
    Remove-Item $FilePath
    Write-Host "Encrypted: $FilePath -> $EncryptedFilePath"
}

# Encrypt all files in the folder and subfolders
Get-ChildItem -Path $FolderPath -Recurse -File | Where-Object {
    $_.Name -ne "encryption_key.txt" -and $_.Extension -ne ".enc"
} | ForEach-Object {
    Encrypt-File -FilePath $_.FullName
}

Write-Host "Encryption completed!"
