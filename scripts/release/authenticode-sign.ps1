[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]]$Artifacts
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $env:SIORB_WINDOWS_PFX_BASE64) { throw "SIORB_WINDOWS_PFX_BASE64 is required" }
if (-not $env:SIORB_WINDOWS_PFX_PASSWORD) { throw "SIORB_WINDOWS_PFX_PASSWORD is required" }
if (-not $env:SIORB_WINDOWS_TIMESTAMP_URL) { throw "SIORB_WINDOWS_TIMESTAMP_URL is required" }
$signToolCommand = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($signToolCommand) {
    $signTool = $signToolCommand.Source
}
else {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits/10/bin"
    $architecture = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
    $signTool = Get-ChildItem -LiteralPath $kitsRoot -Filter signtool.exe -File -Recurse |
        Where-Object { $_.Directory.Name -eq $architecture } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $signTool) { throw "signtool.exe is required" }
}

$pfx = Join-Path ([System.IO.Path]::GetTempPath()) ("siorb-signing-{0}.pfx" -f [guid]::NewGuid())
try {
    [System.IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:SIORB_WINDOWS_PFX_BASE64))
    foreach ($artifact in $Artifacts) {
        $item = Get-Item -LiteralPath $artifact
        $isReparsePoint = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        if ($item.PSIsContainer -or $isReparsePoint) { throw "Artifact must be a regular non-symlink file: $artifact" }
        & $signTool sign /fd SHA256 /td SHA256 `
            /tr $env:SIORB_WINDOWS_TIMESTAMP_URL `
            /f $pfx /p $env:SIORB_WINDOWS_PFX_PASSWORD `
            $item.FullName
        if ($LASTEXITCODE -ne 0) { throw "Signing failed for $artifact" }
        & $signTool verify /pa /v $item.FullName
        if ($LASTEXITCODE -ne 0) { throw "Signature verification failed for $artifact" }
    }
}
finally {
    if (Test-Path -LiteralPath $pfx) {
        Remove-Item -LiteralPath $pfx -Force
    }
}
