# Builds portable-smb-server for win-x64 and linux-x64.
#
#   .\build.ps1                      -> .\bin\{win-x64,linux-x64}\
#   .\build.ps1 -OutDir C:\rclone_test_env\bin   (the rclone_tester layout)
param(
    [string]$OutDir = "$PSScriptRoot\bin"
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# The whole point of this project is zero dependencies - fail the build if any
# ever sneak into go.mod.
if (Select-String -Path go.mod -Pattern '^\s*require' -Quiet) {
    throw "go.mod contains a require directive - the project must have no dependencies"
}

go vet ./...
if ($LASTEXITCODE -ne 0) { throw "go vet failed" }

$env:CGO_ENABLED = '0'
$targets = @(
    @{ GOOS = 'windows'; Dir = 'win-x64';   Name = 'portable-smb-server.exe' },
    @{ GOOS = 'linux';   Dir = 'linux-x64'; Name = 'portable-smb-server' }
)
foreach ($t in $targets) {
    $env:GOOS = $t.GOOS
    $env:GOARCH = 'amd64'
    $out = Join-Path $OutDir $t.Dir
    New-Item -ItemType Directory -Force $out | Out-Null
    $exe = Join-Path $out $t.Name
    go build -trimpath -ldflags '-s -w' -o $exe .
    if ($LASTEXITCODE -ne 0) { throw "go build failed for $($t.GOOS)" }
    Write-Host "built $exe"
}
$env:GOOS = ''
$env:GOARCH = ''
