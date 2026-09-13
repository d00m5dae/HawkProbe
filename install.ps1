$ErrorActionPreference = "Stop"
$base = "https://github.com/d00m5dae/HawkProbe/releases/latest/download"
$name = "hawkprobe-windows-amd64.exe"
$dir = Join-Path $env:LOCALAPPDATA "Programs\HawkProbe"
$exe = Join-Path $dir "hawkprobe.exe"
$tmp = Join-Path $env:TEMP $name
$sums = Join-Path $env:TEMP "hawkprobe-SHA256SUMS"

Invoke-WebRequest -Uri "$base/$name" -OutFile $tmp
Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums
$line = Get-Content $sums | Where-Object { $_ -match [regex]::Escape($name) } | Select-Object -First 1
if ($line) {
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 $tmp).Hash.ToLower()
    if ($expected -ne $actual) { throw "checksum verification failed" }
}

New-Item -ItemType Directory -Force -Path $dir | Out-Null
Move-Item -Force $tmp $exe
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(';') + ";" + $dir), "User")
}
Remove-Item -Force $sums -ErrorAction SilentlyContinue
Write-Host "installed: $exe"
Write-Host "open a new terminal and run: hawkprobe version"
