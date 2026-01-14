function Decrypt-Base64AES128CBC {
    param([string]$Base64String, [string]$Password)
    try {
        $encryptedBytes = [Convert]::FromBase64String($Base64String)
        $key = [Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Password))
        $aes = [Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.IV = $encryptedBytes[0..15]
        $decryptedBytes = $aes.CreateDecryptor().TransformFinalBlock($encryptedBytes, 16, $encryptedBytes.Length - 16)
        $aes.Dispose()
        return [Text.Encoding]::UTF8.GetString($decryptedBytes)
    } catch { return $null }
}
$password = Read-Host "Passwort"
Get-ChildItem -Path . -Filter "*.sfdl" -File | Where-Object { $_.Name -notlike "*_decrypted.sfdl" } | ForEach-Object {
    try {
        $xmlDoc = [xml](Get-Content $_.FullName)
        $encryptedNode = $xmlDoc.SelectSingleNode("//Encrypted")
        if ($encryptedNode -and $encryptedNode.InnerText -eq "false") {
            Write-Host "Überspringe SFDL-Datei $($_.Name) - SFDL-Datei nicht verschlüsselt! Entschlüsselung nicht notwendig."
            return
        }
        Write-Host "SFDL-Datei $($_.Name) wird entschlüsselt."
        $xmlDoc.SelectNodes("//text()") | ForEach-Object {
            if ($_.Value -and $_.Value.Length -gt 10) {
                try {
                    [Convert]::FromBase64String($_.Value) | Out-Null
                    $decrypted = Decrypt-Base64AES128CBC -Base64String $_.Value -Password $password
                    if ($decrypted) { $_.InnerText = $decrypted }
                } catch {}
            }
        }
        $xmlDoc.SelectNodes("//Encrypted") | Where-Object { $_.InnerText -eq "true" } | ForEach-Object { $_.InnerText = "false" }
        $outputPath = $_.FullName.Replace(".sfdl", "_decrypted.sfdl")
        $xmlDoc.Save($outputPath)
		$filenamedecrypted = $_.Name.Replace(".sfdl", "_decrypted.sfdl")
		Write-Host "Entschlüsselte SFDL-Datei gespeichert als $filenamedecrypted."
    } catch { Write-Error "Fehler bei $($_.Name): $($_.Exception.Message)" }
}
