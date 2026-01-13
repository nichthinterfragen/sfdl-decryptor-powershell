function Decrypt-Base64AES128CBC {
    param([string]$Base64String, [string]$Password)
    
    try {
        $encryptedBytes = [System.Convert]::FromBase64String($Base64String)
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $key = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))
        $md5.Dispose()
        
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.IV = $encryptedBytes[0..15]
        
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 16, $encryptedBytes.Length - 16)
        $aes.Dispose()
        
        return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    } catch { return $null }
}

function Decrypt-AllBase64InSFDL {
    param([string]$InputFilePath, [string]$Password)
    
    if (-not (Test-Path $InputFilePath)) {
        throw "Datei nicht gefunden: $InputFilePath"
    }
    
    $xmlDoc = New-Object System.Xml.XmlDocument
    $xmlDoc.Load($InputFilePath)
    
    $nodes = $xmlDoc.SelectNodes("//text()")
    $decryptedCount = 0
    
    foreach ($node in $nodes) {
        if ($node.Value -and $node.Value.Length -gt 10) {
            try {
                [System.Convert]::FromBase64String($node.Value)
                $decryptedValue = Decrypt-Base64AES128CBC -Base64String $node.Value -Password $password
                if ($decryptedValue) {
                    $node.InnerText = $decryptedValue
                    $decryptedCount++
                }
            } catch { }
        }
    }
    
    # <Encrypted>true</Encrypted> zu <Encrypted>false</Encrypted> ändern
    $encryptedNodes = $xmlDoc.SelectNodes("//Encrypted")
    foreach ($node in $encryptedNodes) {
        if ($node.InnerText -eq "true") {
            $node.InnerText = "false"
        }
    }
    
    $outputPath = $InputFilePath -replace '\.sfdl$', '_decrypted.sfdl'
    $xmlDoc.Save($outputPath)
    return $outputPath
}

# Hauptprogramm
$password = Read-Host "Passwort"
$files = Get-ChildItem -Path . -Filter "*.sfdl" -File | Where-Object { $_.Name -notlike "*_decrypted.sfdl" }

if ($files.Count -eq 0) {
    Write-Host "Keine .sfdl Dateien im aktuellen Ordner gefunden."
    exit
}

Write-Host "Gefundene SFDL-Dateien:"
$files | ForEach-Object { Write-Host $_.Name }

$files | ForEach-Object {
    Write-Host "Verarbeite SFDL-Datei: $($_.Name)"
    try {
        $result = Decrypt-AllBase64InSFDL -InputFilePath $_.FullName -Password $password
    } catch {
        Write-Error "Fehler bei $_.Name: $($_.Exception.Message)"
    }
}