#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the DefenderAtlas Collector and the trigger worker with MinGW g++.
.DESCRIPTION
    Produces two executables in the collector/ directory:

      - trigger_worker.exe           short-lived, one-shot attachment trigger
      - defenderatlas_collector.exe  the collection engine

    The Collector runs the trigger out-of-process (SubprocessTrigger) so that
    a crash in shell32's IAttachmentExecute background threads can never kill
    the collection run.
    Links ole32 (COM), wintrust/crypt32 (WinVerifyTrust) and bcrypt (SHA-256).
.NOTES
    Requires g++ (x86_64-w64-mingw32) on PATH.
#>
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$common = @("-std=c++17", "-O2", "-Wall", "-Wextra", "-DUNICODE", "-D_UNICODE", "-municode")
$libs = @("-lole32", "-lwintrust", "-lcrypt32", "-lbcrypt")

$workerSources = @(
    "trigger_worker.cpp",
    "attachment_trigger.cpp",
    "util.cpp"
)

$collectorSources = @(
    "main.cpp",
    "collector.cpp",
    "procmon.cpp",
    "procmon_filter.cpp",
    "subprocess_trigger.cpp",
    "timeout_strategy.cpp",
    "procmon_activity_strategy.cpp",
    "dataset.cpp",
    "experiment.cpp",
    "metadata.cpp",
    "config.cpp",
    "json.cpp",
    "log.cpp",
    "util.cpp"
)

Write-Host "Building trigger_worker.exe ..."
& g++ $common $workerSources -o "trigger_worker.exe" $libs
if ($LASTEXITCODE -ne 0) {
    Write-Host "trigger_worker.exe build failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Building defenderatlas_collector.exe ..."
& g++ $common $collectorSources -o "defenderatlas_collector.exe" $libs
if ($LASTEXITCODE -ne 0) {
    Write-Host "defenderatlas_collector.exe build failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Built: $here\trigger_worker.exe, $here\defenderatlas_collector.exe" -ForegroundColor Green
exit 0
