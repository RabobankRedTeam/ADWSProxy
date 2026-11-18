<#
.SYNOPSIS
  Regenerates the ADWS WCF client proxy (ADWSProxy/ADWS/ActiveDirectoryWebService.cs) with dotnet-svcutil.

.DESCRIPTION
  dotnet-svcutil is pinned as a local tool in .config/dotnet-tools.json (rollForward: true, so it runs on a
  newer installed runtime without the .NET 9 runtime its apphost asks for). This script restores that tool and
  regenerates the proxy from a live ADWS domain controller's WS-MetadataExchange endpoint. The ADWS metadata is
  the same on every DC, so any reachable DC works.

  The raw output is written to this ServiceReference folder, not over the source file, because the committed
  ActiveDirectoryWebService.cs has been post-processed (formatted, CS8981 pragmas). Review the output, apply the
  project formatting, and copy it to ADWSProxy/ADWS/ only if the generated contract actually changed.

  Note: svcutil bakes the -DomainController host name into the GetDefaultEndpointAddress helpers. Those defaults
  are unused at run time (Connection.cs builds its own EndpointAddress), so the baked host does not matter.

.EXAMPLE
  ./Regenerate.ps1 -DomainController corpdc01.corp.internal
#>
param(
    [Parameter(Mandatory)][string]$DomainController,
    [int]$Port = 9389
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
# svcutil refuses to overwrite an existing output file, so clear a previous run first.
Remove-Item -LiteralPath (Join-Path $PSScriptRoot "ActiveDirectoryWebService.cs") -Force -ErrorAction SilentlyContinue
Push-Location $repoRoot
try
{
    dotnet tool restore
    dotnet tool run dotnet-svcutil `
        "net.tcp://${DomainController}:${Port}/ActiveDirectoryWebServices/mex" `
        --namespace "*,ADWSProxy.ADWS" `
        --outputDir "ServiceReference" `
        --outputFile "ActiveDirectoryWebService.cs" `
        --serializer XmlSerializer `
        --targetFramework net10.0 `
        --sync
}
finally
{
    Pop-Location
}

Write-Host ""
Write-Host "Generated ServiceReference/ActiveDirectoryWebService.cs."
Write-Host "Review and format it, then copy to ADWSProxy/ADWS/ only if the contract changed."
