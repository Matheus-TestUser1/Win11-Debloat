#Requires -Version 5.1
# Launch only the reviewed local copy. No remote downloads or shortened URLs.
& (Join-Path $PSScriptRoot 'win11debloater.ps1') @args
