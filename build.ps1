# Builds portable-smb-server for win-x64, linux-x64, linux-arm64, osx-x64 and osx-arm64,
# all into one folder as portable-smb-server-<target>[.exe].
#
#   .\build.ps1                  -> .\bin\
#   .\build.ps1 -OutDir C:\out
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
    @{ GOOS = 'windows'; GOARCH = 'amd64'; Target = 'win-x64';     Ext = '.exe' },
    @{ GOOS = 'linux';   GOARCH = 'amd64'; Target = 'linux-x64';   Ext = '' },
    @{ GOOS = 'linux';   GOARCH = 'arm64'; Target = 'linux-arm64'; Ext = '' },
    @{ GOOS = 'darwin';  GOARCH = 'amd64'; Target = 'osx-x64';     Ext = '' },
    @{ GOOS = 'darwin';  GOARCH = 'arm64'; Target = 'osx-arm64';   Ext = '' }
)
New-Item -ItemType Directory -Force $OutDir | Out-Null
foreach ($t in $targets) {
    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    $exe = Join-Path $OutDir "portable-smb-server-$($t.Target)$($t.Ext)"
    go build -trimpath -ldflags '-s -w' -o $exe .
    if ($LASTEXITCODE -ne 0) { throw "go build failed for $($t.GOOS)/$($t.GOARCH)" }
    Write-Host "built $exe"
}
$env:GOOS = ''
$env:GOARCH = ''
