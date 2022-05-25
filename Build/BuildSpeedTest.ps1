param([string]$rid = 'linux-x64')
$ErrorActionPreference = 'Stop'

dotnet --info

$net_tfm = 'net6.0'
$configuration = 'Release'
$output_dir = "$PSScriptRoot\..\src\CryptoBase.SpeedTest\bin\$configuration"
$proj_path = "$PSScriptRoot\..\src\CryptoBase.SpeedTest\CryptoBase.SpeedTest.csproj"
function New-App
{
    param([string]$rid)
    Write-Host 'Building'

    $outdir = "$output_dir\$net_tfm"
    $publishDir = "$outdir\publish"

    Remove-Item $publishDir -Recurse -Force -Confirm:$false -ErrorAction Ignore

    dotnet publish "$proj_path" -c $configuration -f $net_tfm -p:PublishSingleFile=true --self-contained true -p:PublishTrimmed=True -r $rid
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}

New-App $rid