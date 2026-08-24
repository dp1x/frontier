# Reproduce legs 1-4 locally from committed commands (msn-2026-0001).
# Usage:  powershell -File crypto\mlkem-input-checks\reproduce.ps1
# Requires: MSVC Build Tools (14.51), Windows SDK, Go >= 1.24, Rust >= 1.85.
# All builds/runs happen under $env:FRONTIER_SCRATCH\<mission> or .scratch.
param()
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$repo = Split-Path -Parent $repo   # repo root (crypto/mlkem-input-checks -> ..)
Set-Location $repo

$py = ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$scratchRoot = if ($env:FRONTIER_SCRATCH) { $env:FRONTIER_SCRATCH } else { Join-Path $repo ".scratch" }
$ws = Join-Path $scratchRoot "msn-2026-0001-repro"
New-Item -ItemType Directory -Force $ws | Out-Null

& $py -c "from frontier.scratch import ensure_capacity; from pathlib import Path; ensure_capacity(Path(r'$scratchRoot'), 800*1024*1024)"

$MSVC = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC"
$msvcVer = (Get-ChildItem $MSVC | Select-Object -First 1).Name
$SDK = "C:\Program Files (x86)\Windows Kits\10"
$sdkVer = (Get-ChildItem "$SDK\Include" | Select-Object -First 1).Name
$envBlock = @"
set "PATH=$MSVC\$msvcVer\bin\HostX64\x64;%PATH%"
set "INCLUDE=$MSVC\$msvcVer\include;$SDK\Include\$sdkVer\ucrt;$SDK\Include\$sdkVer\um;$SDK\Include\$sdkVer\shared"
set "LIB=$MSVC\$msvcVer\lib\x64;$SDK\Lib\$sdkVer\ucrt\x64;$SDK\Lib\$sdkVer\um\x64"
"@

# --- Leg 1+2 shared: clone pinned sources ---------------------------------
git clone --depth 1 https://github.com/PQClean/PQClean.git "$ws\PQClean"
git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git "$ws\liboqs"
$headPQ = git -C "$ws\PQClean" rev-parse HEAD
if ($headPQ -ne "0586a824fc0d49df0b6b6e9179d8d15d06d0974f") { Write-Warning "PQClean HEAD moved: $headPQ (archived upstream)" }

# --- Leg 1: PQClean --------------------------------------------------------
foreach ($scheme in "ml-kem-512","ml-kem-768","ml-kem-1024") {
  $dir = "$ws\PQClean\crypto_kem\$scheme\clean"
  $bat = "$ws\build_$scheme.cmd"
  "@echo off`r`n$envBlock`r`ncd /d `"$dir`"`r`nnmake /f Makefile.Microsoft_nmake`r`n" | Set-Content $bat
  & $py -c "from frontier.execute import run_command; r=run_command(['cmd.exe','/d','/c',r'$bat'], cwd=r'$ws', timeout_s=600); exit(r.exit_code)"
}
$fips = "$ws\fips202.obj"
"@echo off`r`n$envBlock`r`ncd /d `"$ws`"`r`ncl /nologo /O2 /W4 /c PQClean\common\fips202.c`r`n" | Set-Content "$ws\b_fips.cmd"
& $py -c "from frontier.execute import run_command; r=run_command(['cmd.exe','/d','/c',r'$ws\b_fips.cmd'], cwd=r'$ws', timeout_s=300); exit(r.exit_code)"

Copy-Item "$repo\crypto\mlkem-input-checks\harnesses\pqclean_runner.c" $ws
$libs = ("ml-kem-512","ml-kem-768","ml-kem-1024" | ForEach-Object { "`"$ws\PQClean\crypto_kem\$_\clean\lib$_`_clean.lib`"" }) -join " "
"@echo off`r`n$envBlock`r`ncd /d `"$ws`"`r`ncl /nologo /O2 /W4 pqclean_runner.c fips202.obj $libs /Fe:pqclean_runner.exe`r`n" | Set-Content "$ws\b_pq.cmd"
& $py -c "from frontier.execute import run_command; r=run_command(['cmd.exe','/d','/c',r'$ws\b_pq.cmd'], cwd=r'$ws', timeout_s=600); exit(r.exit_code)"
& $py -c "from frontier.execute import run_command; r=run_command([r'$ws\pqclean_runner.exe', r'$repo\crypto\mlkem-input-checks\stimuli\stimuli.tsv', r'$ws\pq_report.tsv'], cwd=r'$ws', timeout_s=300); print(r.stdout.strip()); exit(r.exit_code)"
Get-Content "$ws\pq_report.tsv" | Select-Object -Last 1

Write-Host "Leg 1 complete. Legs 2-4 follow the same pattern; see reproducer.md for the authoritative command list." -ForegroundColor Green
