$ErrorActionPreference = 'Stop';

$packageName= 'Batin'
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$url64      = 'https://github.com/ahmeddwalid/Batin/releases/download/v0.2.0/Batin-windows-x86_64.exe'
$checksum64 = 'PLACEHOLDER_SHA256_WINDOWS_X64'
$url32      = 'https://github.com/ahmeddwalid/Batin/releases/download/v0.2.0/Batin-windows-i686.exe'
$checksum32 = 'PLACEHOLDER_SHA256_WINDOWS_I686'

$packageArgs = @{
  packageName   = $packageName
  unzipLocation = $toolsDir
  fileType      = 'exe'
  url64         = $url64
  checksum64    = $checksum64
  checksumType64= 'sha256'
  url           = $url32
  checksum      = $checksum32
  checksumType  = 'sha256'
}

Install-ChocolateyPackage @packageArgs
