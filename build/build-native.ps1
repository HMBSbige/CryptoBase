param([string]$target = 'x86_64-pc-windows-msvc')
$ErrorActionPreference = 'Stop'

rustup show

$rids = @{
	"x86_64-pc-windows-msvc"         = "win-x64" ;
	"i686-pc-windows-msvc"           = "win-x86" ;
	"aarch64-pc-windows-msvc"        = "win-arm64" ;
	"x86_64-apple-darwin"            = "osx-x64" ;
	"aarch64-apple-darwin"           = "osx-arm64" ;
	"x86_64-unknown-linux-gnu"       = "linux-x64" ;
	"aarch64-unknown-linux-gnu"      = "linux-arm64" ;
	"armv7-unknown-linux-gnueabihf"  = "linux-arm" ;
	"x86_64-unknown-linux-musl"      = "linux-musl-x64" ;
	"aarch64-unknown-linux-musl"     = "linux-musl-arm64" ;
	"armv7-unknown-linux-musleabihf" = "linux-musl-arm" ;
}
$rid = $rids[$target]
$native_name = 'cryptobase_native'

if ($rid.StartsWith('win-')) {
	$lib_name = "$native_name.dll"
}
elseif ($rid.StartsWith('osx-')) {
	$lib_name = "lib$native_name.dylib"
}
else {
	$lib_name = "lib$native_name.so"
}

$proj = 'CryptoBase'
$rust_proj = 'cryptobase'
$rust_dir = "$PSScriptRoot\..\native\$rust_proj"
$source_path = "$rust_dir\target\$target\release\$lib_name"
$target_dir = "$PSScriptRoot\..\src\$proj\runtimes\$rid\native"

Push-Location $rust_dir
try {
	Write-Host "Building $target..."
	if ($rid.StartsWith('linux-')) {
		cross build --release --target $target
	}
	else {
		cargo build --release --target $target
	}
	if ($LASTEXITCODE) { exit $LASTEXITCODE }
}
finally {
	Pop-Location
}

Write-Host "Moving $lib_name..."
New-Item -ItemType Directory -Path $target_dir -Force > $null
Move-Item -Path $source_path -Destination "$target_dir\$lib_name" -Force

Write-Host "Done."
