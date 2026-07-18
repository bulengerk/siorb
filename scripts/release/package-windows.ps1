[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Version,
    [ValidateSet("x64", "arm64")][string]$Architecture = "x64",
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "Version must be stable MAJOR.MINOR.PATCH"
}
$binaryItem = Get-Item -LiteralPath $Binary
$binaryIsReparsePoint = ($binaryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
if (-not $binaryItem.Exists -or $binaryItem.PSIsContainer -or $binaryIsReparsePoint) {
    throw "Binary must be a regular non-symlink file"
}
$wixCommand = Get-Command wix -ErrorAction SilentlyContinue
if ($wixCommand) {
    $wix = $wixCommand.Source
}
else {
    $candidate = Join-Path $HOME ".dotnet/tools/wix.exe"
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "WiX CLI ('wix') is required"
    }
    $wix = $candidate
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$wxs = Join-Path $root "packaging/windows/siorb.wxs"
$license = Join-Path $root "LICENSE"
$outputParent = Split-Path -Parent $Output
if ($outputParent) {
    New-Item -ItemType Directory -Force -Path $outputParent | Out-Null
}

& $wix build `
    -arch $Architecture `
    -d "SiorbVersion=$Version" `
    -d "SiorbBinary=$($binaryItem.FullName)" `
    -d "LicensePath=$license" `
    -o $Output `
    $wxs
if ($LASTEXITCODE -ne 0) {
    throw "WiX build failed with exit code $LASTEXITCODE"
}
