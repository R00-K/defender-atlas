#Requires -Version 5.1
<#
.SYNOPSIS
    DefenderAtlas Research Dataset Generator
.DESCRIPTION
    Generates a reproducible dataset of PE files for DefenderAtlas research.
    Uses only official Windows binaries and self-generated C++ programs.
.NOTES
    This is NOT malware. This is a research dataset for studying
    Microsoft Defender's file scanning behavior.
#>

param(
    [string]$BasePath = "\\VBoxSvr\000\DefenderAtlas\datasets"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
$generatedOn = (Get-Date).ToString("o")

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  DefenderAtlas Research Dataset Generator" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan
Write-Host "Base path: $BasePath"
Write-Host "Timestamp: $generatedOn`n"

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-SHA256 {
    param([string]$Path)
    $hash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    return $hash
}

function Get-MD5 {
    param([string]$Path)
    $hash = (Get-FileHash -Path $Path -Algorithm MD5).Hash
    return $hash
}

function Get-SignatureStatus {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        return $sig.Status.ToString()
    } catch {
        return "NotSigned"
    }
}

function Get-FileVersionInfo {
    param([string]$Path)
    try {
        $info = Get-Item $Path -ErrorAction Stop
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        return @{
            CompanyName    = if ($versionInfo.CompanyName) { $versionInfo.CompanyName } else { "" }
            ProductName    = if ($versionInfo.ProductName) { $versionInfo.ProductName } else { "" }
            FileVersion    = if ($versionInfo.FileVersion) { $versionInfo.FileVersion } else { "" }
            ProductVersion = if ($versionInfo.ProductVersion) { $versionInfo.ProductVersion } else { "" }
            FileDescription = if ($versionInfo.FileDescription) { $versionInfo.FileDescription } else { "" }
        }
    } catch {
        return @{
            CompanyName    = ""
            ProductName    = ""
            FileVersion    = ""
            ProductVersion = ""
            FileDescription = ""
        }
    }
}

function Get-PEArchitecture {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -ge 0x40) {
            $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
            if ($peOffset + 4 -lt $bytes.Length) {
                $peSignature = [BitConverter]::ToInt32($bytes, $peOffset)
                if ($peSignature -eq 0x4550) { # "PE\0\0"
                    $machine = [BitConverter]::ToInt16($bytes, $peOffset + 4)
                    switch ($machine) {
                        0x014C { return "x86" }
                        0x8664 { return "x64" }
                        0xAA64 { return "ARM64" }
                        default { return "Unknown($machine)" }
                    }
                }
            }
        }
        return "Unknown"
    } catch {
        return "Unknown"
    }
}

function Get-PESections {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $numSections = [BitConverter]::ToInt16($bytes, $peOffset + 6)
        $optionalHeaderSize = [BitConverter]::ToInt16($bytes, $peOffset + 20)
        $sectionStart = $peOffset + 24 + $optionalHeaderSize
        $sections = @()
        for ($i = 0; $i -lt $numSections -and ($sectionStart + ($i * 40) + 40) -le $bytes.Length; $i++) {
            $offset = $sectionStart + ($i * 40)
            $nameBytes = $bytes[$offset..($offset + 7)]
            $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
            $sections += $name
        }
        return $sections
    } catch {
        return @()
    }
}

function Get-PETimestamp {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $timestamp = [BitConverter]::ToInt32($bytes, $peOffset + 8)
        if ($timestamp -gt 0) {
            $epoch = [DateTimeOffset]::FromUnixTimeSeconds($timestamp)
            return $epoch.ToString("o")
        }
        return ""
    } catch {
        return ""
    }
}

function Get-SizeCategory {
    param([long]$Size)
    if ($Size -lt 102400) { return "tiny" }
    elseif ($Size -lt 512000) { return "small" }
    elseif ($Size -lt 2097152) { return "medium" }
    elseif ($Size -lt 10485760) { return "large" }
    else { return "huge" }
}

# ============================================================
# PART 1: SIGNED WINDOWS EXECUTABLES
# ============================================================
Write-Host "`n=== PART 1: Collecting Signed Windows Executables ===" -ForegroundColor Green

$signedDir = Join-Path $BasePath "signed"
$signedSamples = @()

# Preferred binaries with size estimates
$preferredBinaries = @(
    @{ Name = "notepad.exe"; Path = "C:\Windows\System32\notepad.exe" },
    @{ Name = "calc.exe"; Path = "C:\Windows\System32\calc.exe" },
    @{ Name = "cmd.exe"; Path = "C:\Windows\System32\cmd.exe" },
    @{ Name = "regedit.exe"; Path = "C:\Windows\System32\regedit.exe" },
    @{ Name = "mspaint.exe"; Path = "C:\Windows\System32\mspaint.exe" },
    @{ Name = "ping.exe"; Path = "C:\Windows\System32\ping.exe" },
    @{ Name = "ipconfig.exe"; Path = "C:\Windows\System32\ipconfig.exe" },
    @{ Name = "tasklist.exe"; Path = "C:\Windows\System32\tasklist.exe" },
    @{ Name = "whoami.exe"; Path = "C:\Windows\System32\whoami.exe" },
    @{ Name = "net.exe"; Path = "C:\Windows\System32\net.exe" },
    @{ Name = "find.exe"; Path = "C:\Windows\System32\find.exe" },
    @{ Name = "fc.exe"; Path = "C:\Windows\System32\fc.exe" },
    @{ Name = "more.com"; Path = "C:\Windows\System32\more.com" }
)

# Scan System32 and SysWOW64 for additional signed EXEs to fill categories
Write-Host "Scanning for additional signed executables..."
$searchPaths = @("C:\Windows\System32", "C:\Windows\SysWOW64")
$allExes = @()

foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        $exes = Get-ChildItem -Path $searchPath -Filter "*.exe" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 1024 }
        $allExes += $exes
    }
}

Write-Host "Found $($allExes.Count) candidate executables"

# Categorize by size, pick best ones
$categories = @{
    tiny   = @{ min = 0; max = 102400; samples = @(); target = 6 }
    small  = @{ min = 102400; max = 512000; samples = @(); target = 6 }
    medium = @{ min = 512000; max = 2097152; samples = @(); target = 5 }
    large  = @{ min = 2097152; max = 10485760; samples = @(); target = 4 }
    huge   = @{ min = 10485760; max = [long]::MaxValue; samples = @(); target = 3 }
}

# Add preferred binaries first
foreach ($pref in $preferredBinaries) {
    if (Test-Path $pref.Path) {
        $item = Get-Item $pref.Path
        $cat = Get-SizeCategory -Size $item.Length
        if ($categories.ContainsKey($cat) -and $categories[$cat].samples.Count -lt $categories[$cat].target) {
            $categories[$cat].samples += $item
        }
    }
}

# Fill remaining slots from scanned EXEs
foreach ($exe in $allExes) {
    $cat = Get-SizeCategory -Size $exe.Length
    if ($categories.ContainsKey($cat) -and $categories[$cat].samples.Count -lt $categories[$cat].target) {
        # Skip duplicates
        $existing = $categories[$cat].samples | Where-Object { $_.FullName -eq $exe.FullName }
        if (-not $existing) {
            $categories[$cat].samples += $exe
        }
    }
}

# Copy and create manifests for each signed sample
$signedCounter = 0
foreach ($catName in @("tiny", "small", "medium", "large", "huge")) {
    $cat = $categories[$catName]
    Write-Host "`n  Category '$catName': $($cat.samples.Count) samples" -ForegroundColor Yellow

    foreach ($exe in $cat.samples) {
        $signedCounter++
        $id = "signed_{0}_{1:D3}" -f $catName, $signedCounter
        $sampleDir = Join-Path $signedDir $catName

        $destExe = Join-Path $sampleDir "$id.exe"
        $destManifest = Join-Path $sampleDir "$id.manifest.json"

        try {
            Copy-Item -Path $exe.FullName -Destination $destExe -Force

            $sha256 = Get-SHA256 -Path $destExe
            $md5 = Get-MD5 -Path $destExe
            $sigStatus = Get-SignatureStatus -Path $destExe
            $fileInfo = Get-FileVersionInfo -Path $destExe
            $arch = Get-PEArchitecture -Path $destExe
            $sections = Get-PESections -Path $destExe
            $peTimestamp = Get-PETimestamp -Path $destExe

            $manifest = [ordered]@{
                sample_id    = $id
                display_name = $exe.Name
                category     = "signed"
                sub_category = $catName
                type         = "native_pe"
                signed       = $true
                compiler     = @{
                    name     = "Microsoft"
                    version  = $fileInfo.FileVersion
                    language = "Native"
                    flags    = "Official Microsoft Build"
                }
                binary = @{
                    filename          = "$id.exe"
                    original_filename = $exe.Name
                    original_path     = $exe.FullName
                    size_bytes        = (Get-Item $destExe).Length
                    sha256            = $sha256
                    md5               = $md5
                    compile_timestamp = $peTimestamp
                    pe_timestamp      = $peTimestamp
                    architecture      = $arch
                }
                pe_features = @{
                    sections    = $sections
                    imports     = @()
                    exports     = @()
                    resources   = $true
                    certificate = ($sigStatus -eq "Valid")
                    overlay     = $false
                    dotnet      = $false
                }
                metadata = @{
                    company_name    = $fileInfo.CompanyName
                    product_name    = $fileInfo.ProductName
                    file_version    = $fileInfo.FileVersion
                    product_version = $fileInfo.ProductVersion
                    description     = $fileInfo.FileDescription
                    signature       = $sigStatus
                }
                dataset = @{
                    generated  = $false
                    source_file = ""
                    created_by = "DefenderAtlas Dataset Generator"
                    created_on = $generatedOn
                }
                research = @{
                    procmon_trace   = $null
                    analysis_report = $null
                    timeline        = $null
                    phase_detection = $null
                    findings        = @()
                    rule_matches    = @()
                    confidence      = $null
                    notes           = ""
                }
            }

            $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $destManifest -Encoding UTF8

            $signedSamples += [ordered]@{
                sample_id = $id
                category  = "signed"
                sub_category = $catName
                signed    = $true
                path      = "$catName/$id.exe"
                manifest  = "$catName/$id.manifest.json"
                sha256    = $sha256
                size_bytes = (Get-Item $destExe).Length
                company   = $fileInfo.CompanyName
                product   = $fileInfo.ProductName
                version   = $fileInfo.FileVersion
                signature = $sigStatus
                arch      = $arch
            }

            Write-Host "    [+] $id.exe ($((Get-Item $destExe).Length / 1KB)KB) - $($fileInfo.CompanyName)" -ForegroundColor Gray
        } catch {
            Write-Host "    [-] Failed to process $($exe.Name): $_" -ForegroundColor Red
        }
    }
}

Write-Host "`n  Total signed samples: $($signedSamples.Count)" -ForegroundColor Green

# ============================================================
# PART 2: WINDOWS DRIVERS
# ============================================================
Write-Host "`n=== PART 2: Collecting Windows Drivers ===" -ForegroundColor Green

$driversDir = Join-Path $BasePath "drivers"
$driverSamples = @()
$driversPath = "C:\Windows\System32\drivers"

$preferredDrivers = @(
    "disk.sys", "tcpip.sys", "kbdclass.sys", "ndis.sys", "acpi.sys",
    "fltmgr.sys", "msrpc.sys", "CI.sys", "WdFilter.sys", "CLASSPNP.SYS",
    "mountmgr.sys", "volmgr.sys", "partmgr.sys", "diskdump.sys",
    "dxgkrnl.sys", "dxgmms1.sys", "nvlddmkm.sys", "atikmpag.sys",
    "USBPORT.SYS", "usbhub.sys", "HIDCLASS.SYS", "mouclass.sys",
    "storport.sys", "spaceport.sys", "fileinfo.sys", "Wof.sys",
    "ntfs.sys", "fastfat.sys", "ReFs.sys", "udfs.sys"
)

$driverFiles = @()
foreach ($drv in $preferredDrivers) {
    $drvPath = Join-Path $driversPath $drv
    if (Test-Path $drvPath) {
        $driverFiles += Get-Item $drvPath
    }
}

# Also scan for more drivers if we need more
if ($driverFiles.Count -lt 15) {
    $moreDrivers = Get-ChildItem -Path $driversPath -Filter "*.sys" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 1024 } |
        Sort-Object Length
    foreach ($d in $moreDrivers) {
        if ($driverFiles.Count -ge 20) { break }
        $exists = $driverFiles | Where-Object { $_.FullName -eq $d.FullName }
        if (-not $exists) {
            $driverFiles += $d
        }
    }
}

$driverCounter = 0
foreach ($drv in $driverFiles) {
    $driverCounter++
    $id = "driver_{0:D3}" -f $driverCounter
    $destFile = Join-Path $driversDir "$id.sys"
    $destManifest = Join-Path $driversDir "$id.manifest.json"

    try {
        Copy-Item -Path $drv.FullName -Destination $destFile -Force

        $sha256 = Get-SHA256 -Path $destFile
        $md5 = Get-MD5 -Path $destFile
        $sigStatus = Get-SignatureStatus -Path $destFile
        $fileInfo = Get-FileVersionInfo -Path $destFile
        $arch = Get-PEArchitecture -Path $destFile
        $sections = Get-PESections -Path $destFile
        $peTimestamp = Get-PETimestamp -Path $destFile

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = $drv.Name
            category     = "driver"
            sub_category = "kernel_driver"
            type         = "native_pe"
            signed       = $true
            compiler     = @{
                name     = "Microsoft WDK"
                version  = $fileInfo.FileVersion
                language = "Native"
                flags    = "Official Microsoft Driver Build"
            }
            binary = @{
                filename          = "$id.sys"
                original_filename = $drv.Name
                original_path     = $drv.FullName
                size_bytes        = (Get-Item $destFile).Length
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = ($sigStatus -eq "Valid")
                overlay     = $false
                dotnet      = $false
            }
            metadata = @{
                company_name    = $fileInfo.CompanyName
                product_name    = $fileInfo.ProductName
                file_version    = $fileInfo.FileVersion
                product_version = $fileInfo.ProductVersion
                description     = $fileInfo.FileDescription
                signature       = $sigStatus
            }
            dataset = @{
                generated  = $false
                source_file = ""
                created_by = "DefenderAtlas Dataset Generator"
                created_on = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $destManifest -Encoding UTF8

        $driverSamples += [ordered]@{
            sample_id   = $id
            category    = "driver"
            signed      = $true
            path        = "drivers/$id.sys"
            manifest    = "drivers/$id.manifest.json"
            sha256      = $sha256
            size_bytes  = (Get-Item $destFile).Length
            company     = $fileInfo.CompanyName
            product     = $fileInfo.ProductName
            version     = $fileInfo.FileVersion
            signature   = $sigStatus
            arch        = $arch
            original    = $drv.Name
        }

        Write-Host "  [+] $id.sys ($((Get-Item $destFile).Length / 1KB)KB) - $($drv.Name)" -ForegroundColor Gray
    } catch {
        Write-Host "  [-] Failed to process $($drv.Name): $_" -ForegroundColor Red
    }
}

Write-Host "  Total driver samples: $($driverSamples.Count)" -ForegroundColor Green

# ============================================================
# PART 3: SELF-GENERATED UNSIGNED EXECUTABLES
# ============================================================
Write-Host "`n=== PART 3: Generating Unsigned C++ Executables ===" -ForegroundColor Green

$unsignedDir = Join-Path $BasePath "unsigned"
$unsignedSamples = @()
$gppVersion = (g++ --version 2>&1 | Select-Object -First 1) -replace '.*?(g\+\+ \(.*?\)).*','$1'

# Target sizes in bytes
$targetSizes = @(
    @{ Label = "010k"; Bytes = 10240;  FriendlySize = "10KB" },
    @{ Label = "050k"; Bytes = 51200;  FriendlySize = "50KB" },
    @{ Label = "100k"; Bytes = 102400; FriendlySize = "100KB" },
    @{ Label = "500k"; Bytes = 512000; FriendlySize = "500KB" },
    @{ Label = "1m";   Bytes = 1048576; FriendlySize = "1MB" },
    @{ Label = "5m";   Bytes = 5242880; FriendlySize = "5MB" },
    @{ Label = "10m";  Bytes = 10485760; FriendlySize = "10MB" },
    @{ Label = "20m";  Bytes = 20971520; FriendlySize = "20MB" }
)

$unsignedCounter = 0

# --- CATEGORY A: Minimal Hello World ---
Write-Host "`n  Category A: Hello World" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "hello"
foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_hello_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    # Calculate padding needed
    $paddingSize = [Math]::Max(0, $size.Bytes - 4096)
    $paddingArrays = ""
    $chunks = @()
    $chunkSize = 4096
    $remaining = $paddingSize

    while ($remaining -gt 0) {
        $thisChunk = [Math]::Min($chunkSize, $remaining)
        $numInts = [Math]::Floor($thisChunk / 4)
        if ($numInts -gt 0) {
            $chunks += "volatile unsigned char padding_data_$($chunks.Count)[$($numInts * 4)];"
            $remaining -= $thisChunk
        } else {
            break
        }
    }

    $globalDecls = $chunks -join "`n"

    $fillLines = @()
    for ($ci = 0; $ci -lt $chunks.Count; $ci++) {
        $arrName = "padding_data_$ci"
        $fillLines += "    memset($arrName, 0, sizeof($arrName));"
    }
    $fillBody = $fillLines -join "`n"

    $cppSource = @"
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Padding arrays to reach target size: $($size.FriendlySize)
$globalDecls

void fill_padding() {
$fillBody
}

int main() {
    printf("Hello, DefenderAtlas! Sample: $id\n");
    printf("Target size: $($size.FriendlySize)\n");
    printf("This is a research sample for studying Microsoft Defender behavior.\n");

    // Use volatile to prevent optimization
    volatile int x = 0;
    for (int i = 0; i < 100; i++) {
        x += i;
    }
    printf("Result: %d\n", x);

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Hello World $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "hello"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "hello"
            signed      = $false
            path        = "unsigned/hello/$id/$id.exe"
            manifest    = "unsigned/hello/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY B: Many Imports ---
Write-Host "`n  Category B: Many Imports" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "imports"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_imports_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $paddingSize = [Math]::Max(0, $size.Bytes - 8192)
    $numArrays = [Math]::Floor($paddingSize / 4096)
    $arrayDecls = @()
    for ($i = 0; $i -lt $numArrays; $i++) {
        $arrayDecls += "unsigned char import_pad_${i}[4096];"
    }
    $globalData = $arrayDecls -join "`n"

    $cppSource = @"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <shellapi.h>
#include <winbase.h>
#include <processthreadsapi.h>
#include <fileapi.h>
#include <handleapi.h>
#include <synchapi.h>
#include <debugapi.h>
#include <errhandlingapi.h>
#include <memoryapi.h>
#include <profileapi.h>
#include <sysinfoapi.h>
#include <timeapi.h>
#include <heapapi.h>
#include <memoryapi.h>
#include <wingdi.h>
#include <winuser.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

$globalData

int main() {
    printf("Many Imports Sample: $id\n");

    // Touch all imports to ensure they're linked
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    HMODULE hUser = GetModuleHandleA("user32.dll");
    HMODULE hGdi = GetModuleHandleA("gdi32.dll");

    char buf[MAX_PATH];
    GetModuleFileNameA(NULL, buf, MAX_PATH);
    printf("Path: %s\n", buf);

    DWORD pid = GetCurrentProcessId();
    printf("PID: %lu\n", pid);

    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    printf("Perf: %lld / %lld\n", counter.QuadPart, freq.QuadPart);

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    printf("Memory: %lu%% used\n", mem.dwMemoryLoad);

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    printf("PageSize: %lu\n", sysInfo.dwPageSize);

    SYSTEMTIME st;
    GetSystemTime(&st);
    printf("Time: %04d-%02d-%02d\n", st.wYear, st.wMonth, st.wDay);

    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
    printf("Result: %d\n", x);

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") -lws2_32 -liphlpapi -lgdi32 -luser32 -mwindows 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Many Imports $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "imports"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static -lws2_32 -liphlpapi -lgdi32 -luser32 -mwindows"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "imports"
            signed      = $false
            path        = "unsigned/imports/$id/$id.exe"
            manifest    = "unsigned/imports/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY C: Large Global Arrays ---
Write-Host "`n  Category C: Large Global Arrays" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "arrays"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_arrays_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $dataSize = [Math]::Max(0, $size.Bytes - 2048)
    $numInts = [Math]::Floor($dataSize / 4)

    $cppSource = @"
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Large global array: $numInts integers ($($dataSize) bytes)
volatile int global_data[$numInts];

void initialize_data() {
    for (int i = 0; i < $numInts; i++) {
        global_data[i] = i * 7 + 13;
    }
}

int compute_checksum() {
    int sum = 0;
    for (int i = 0; i < $numInts; i++) {
        sum += global_data[i];
    }
    return sum;
}

int main() {
    printf("Arrays Sample: $id\n");
    printf("Global array: %d integers\n", $numInts);

    initialize_data();
    int checksum = compute_checksum();
    printf("Checksum: %d\n", checksum);

    // Verify first and last elements
    printf("First: %d, Last: %d\n", (int)global_data[0], (int)global_data[$numInts - 1]);

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Large Global Arrays $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "arrays"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "arrays"
            signed      = $false
            path        = "unsigned/arrays/$id/$id.exe"
            manifest    = "unsigned/arrays/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY D: Large Resource-like Data ---
Write-Host "`n  Category D: Resource-like Data (Large Embedded Strings)" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "resources"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_resources_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $dataSize = [Math]::Max(0, $size.Bytes - 2048)
    $numChars = [Math]::Floor($dataSize / 2)

    $cppSource = @"
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Embedded resource-like data
static const char embedded_data[$numChars + 1] =
"$(for ($i = 0; $i -lt [Math]::Min($numChars, 100); $i++) { [char](0x41 + ($i % 26)) })" ;

// Use additional approach for large data
static unsigned char resource_blob[$dataSize];

void init_resource_blob() {
    for (int i = 0; i < $dataSize; i++) {
        resource_blob[i] = (unsigned char)((i * 31 + 7) & 0xFF);
    }
}

int main() {
    printf("Resource Data Sample: $id\n");
    printf("Embedded data length: %d chars\n", (int)strlen(embedded_data));

    init_resource_blob();

    unsigned int checksum = 0;
    for (int i = 0; i < $dataSize; i++) {
        checksum = (checksum << 1) ^ resource_blob[i];
    }
    printf("Blob checksum: 0x%08X\n", checksum);
    printf("First 64 bytes: ");
    for (int i = 0; i < 64 && i < $dataSize; i++) {
        printf("%02X ", resource_blob[i]);
    }
    printf("\n");

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Resource Data $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "resources"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "resources"
            signed      = $false
            path        = "unsigned/resources/$id/$id.exe"
            manifest    = "unsigned/resources/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY E: Many Functions ---
Write-Host "`n  Category E: Many Functions" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "functions"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_functions_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $dataSize = [Math]::Max(0, $size.Bytes - 4096)
    $numFuncs = [Math]::Floor($dataSize / 128)
    $numFuncs = [Math]::Min($numFuncs, 5000)

    $funcBodies = @()
    for ($i = 0; $i -lt $numFuncs; $i++) {
        $funcBodies += "int func_${i}(int x) { return x * $i + $i; }"
    }
    $allFuncs = $funcBodies -join "`n"

    $callLines = @()
    for ($i = 0; $i -lt $numFuncs; $i += 50) {
        $callLines += "    sum += func_${i}(i);"
    }
    $allCalls = $callLines -join "`n"

    $cppSource = @"
#include <cstdio>

// $numFuncs generated functions
$allFuncs

int main() {
    printf("Many Functions Sample: $id\n");
    printf("Function count: $numFuncs\n");

    long long sum = 0;
    for (int i = 0; i < 10000; i++) {
$allCalls
    }
    printf("Result: %lld\n", sum);

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Many Functions $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "functions"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "functions"
            signed      = $false
            path        = "unsigned/functions/$id/$id.exe"
            manifest    = "unsigned/functions/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY F: Large Switch Statements ---
Write-Host "`n  Category F: Large Switch Statements" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "switches"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_switches_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $dataSize = [Math]::Max(0, $size.Bytes - 4096)
    $numCases = [Math]::Floor($dataSize / 32)
    $numCases = [Math]::Min($numCases, 8000)

    $caseLines = @()
    for ($i = 0; $i -lt $numCases; $i++) {
        $caseLines += "        case ${i}: result += ${i}; break;"
    }
    $allCases = $caseLines -join "`n"

    $cppSource = @"
#include <cstdio>

int process_value(int x) {
    int result = 0;
    switch (x % $numCases) {
$allCases
        default: result = 0; break;
    }
    return result;
}

int main() {
    printf("Large Switch Sample: $id\n");
    printf("Case count: $numCases\n");

    long long total = 0;
    for (int i = 0; i < 100000; i++) {
        total += process_value(i);
    }
    printf("Result: %lld\n", total);

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Large Switch Statements $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "switches"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "switches"
            signed      = $false
            path        = "unsigned/switches/$id/$id.exe"
            manifest    = "unsigned/switches/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY G: Recursive Algorithms ---
Write-Host "`n  Category G: Recursive Algorithms" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "recursion"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_recursion_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $dataSize = [Math]::Max(0, $size.Bytes - 4096)
    $numTables = [Math]::Floor($dataSize / 512)
    $numTables = [Math]::Min($numTables, 200)

    $tableDecls = @()
    for ($t = 0; $t -lt $numTables; $t++) {
        $size2 = 64
        $vals = @()
        for ($i = 0; $i -lt $size2; $i++) {
            $vals += (($i * $t + 7) % 1000)
        }
        $tableDecls += "static const int table_${t}[$size2] = { $($vals -join ', ') };"
    }
    $allTables = $tableDecls -join "`n"

    $lookupLines = @()
    for ($t = 0; $t -lt [Math]::Min($numTables, 50); $t++) {
        $lookupLines += "        sum += table_${t}[i % 64];"
    }
    $allLookups = $lookupLines -join "`n"

    $cppSource = @"
#include <cstdio>
#include <cstdlib>

$allTables

unsigned long long fib_memo[100];

unsigned long long fib(int n) {
    if (n <= 1) return n;
    if (fib_memo[n] != 0) return fib_memo[n];
    fib_memo[n] = fib(n - 1) + fib(n - 2);
    return fib_memo[n];
}

int main() {
    printf("Recursive Algorithms Sample: $id\n");
    printf("Lookup tables: $numTables\n");

    // Fibonacci
    memset(fib_memo, 0, sizeof(fib_memo));
    unsigned long long fibResult = fib(50);
    printf("Fib(50) = %llu\n", fibResult);

    // Table lookups
    long long sum = 0;
    for (int i = 0; i < 100000; i++) {
$allLookups
    }
    printf("Lookup sum: %lld\n", sum);

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Recursive Algorithms $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "recursion"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "recursion"
            signed      = $false
            path        = "unsigned/recursion/$id/$id.exe"
            manifest    = "unsigned/recursion/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY H: File I/O ---
Write-Host "`n  Category H: File I/O" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "fileio"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_fileio_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $dataSize = [Math]::Max(0, $size.Bytes - 4096)
    $bufSize = [Math]::Min($dataSize, 65536)

    $cppSource = @"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

unsigned char io_buffer[$bufSize];

void generate_data(unsigned char* buf, int len, int seed) {
    for (int i = 0; i < len; i++) {
        buf[i] = (unsigned char)((seed * 31 + i * 17) & 0xFF);
    }
}

int main() {
    printf("File I/O Sample: $id\n");
    printf("Buffer size: $bufSize bytes\n");

    // Create temp file
    char tmpPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpPath);
    strcat(tmpPath, "defenderatlas_test_$id.tmp");

    // Write phase
    HANDLE hFile = CreateFileA(tmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD totalWritten = 0;
        int iterations = $([Math]::Ceiling($dataSize / $bufSize));
        for (int i = 0; i < iterations; i++) {
            generate_data(io_buffer, $bufSize, i);
            DWORD written;
            WriteFile(hFile, io_buffer, $bufSize, &written, NULL);
            totalWritten += written;
        }
        CloseHandle(hFile);
        printf("Written: %lu bytes to %s\n", totalWritten, tmpPath);
    }

    // Read phase
    hFile = CreateFileA(tmpPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD totalRead = 0;
        DWORD bytesRead;
        while (ReadFile(hFile, io_buffer, $bufSize, &bytesRead, NULL) && bytesRead > 0) {
            totalRead += bytesRead;
        }
        CloseHandle(hFile);
        printf("Read: %lu bytes\n", totalRead);
    }

    // Cleanup
    DeleteFileA(tmpPath);

    printf("File I/O complete.\n");
    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "File I/O $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "fileio"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "fileio"
            signed      = $false
            path        = "unsigned/fileio/$id/$id.exe"
            manifest    = "unsigned/fileio/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY I: Network API Imports ---
Write-Host "`n  Category I: Network API Imports" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "network"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_network_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $dataSize = [Math]::Max(0, $size.Bytes - 4096)
    $numInts = [Math]::Floor($dataSize / 4)

    $cppSource = @"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windivert.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

volatile unsigned char net_padding[$dataSize];

void init_padding() {
    for (int i = 0; i < $dataSize; i++) {
        net_padding[i] = (unsigned char)((i * 13 + 5) & 0xFF);
    }
}

int main() {
    printf("Network API Sample: $id\n");

    // Initialize Winsock (but do NOT connect)
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result == 0) {
        printf("Winsock initialized: %s\n", wsaData.szDescription);

        // List available addresses (local only)
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        result = getaddrinfo("127.0.0.1", "80", &hints, &res);
        if (result == 0) {
            printf("Resolved 127.0.0.1:80 successfully\n");
            freeaddrinfo(res);
        }

        WSACleanup();
    }

    // Get adapter info (local only)
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    result = GetAdaptersInfo(adapterInfo, &bufLen);
    if (result == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        int count = 0;
        while (pAdapter) {
            count++;
            pAdapter = pAdapter->Next;
        }
        printf("Adapters found: %d\n", count);
    }

    init_padding();

    unsigned int checksum = 0;
    for (int i = 0; i < $dataSize; i++) {
        checksum += net_padding[i];
    }
    printf("Checksum: 0x%08X\n", checksum);

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") -lws2_32 -liphlpapi 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Network API Imports $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "network"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static -lws2_32 -liphlpapi"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "network"
            signed      = $false
            path        = "unsigned/network/$id/$id.exe"
            manifest    = "unsigned/network/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

# --- CATEGORY J: Thread Creation ---
Write-Host "`n  Category J: Thread Creation" -ForegroundColor Yellow
$catDir = Join-Path $unsignedDir "threads"
$unsignedCounter = 0

foreach ($size in $targetSizes) {
    $unsignedCounter++
    $id = "unsigned_threads_{0:D3}" -f $unsignedCounter
    $sampleDir = Join-Path $catDir $id
    New-Item -ItemType Directory -Path $sampleDir -Force | Out-Null

    $dataSize = [Math]::Max(0, $size.Bytes - 4096)
    $numInts = [Math]::Floor($dataSize / 4)

    $cppSource = @"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

volatile long shared_counter = 0;
volatile unsigned char thread_data[$dataSize];

DWORD WINAPI thread_func(LPVOID param) {
    int id = *(int*)param;
    for (int i = 0; i < 10000; i++) {
        InterlockedIncrement(&shared_counter);
        int idx = (id * 1000 + i) % $dataSize;
        thread_data[idx] = (unsigned char)((id + i) & 0xFF);
    }
    return 0;
}

int main() {
    printf("Thread Creation Sample: $id\n");

    memset((void*)thread_data, 0, $dataSize);

    HANDLE threads[8];
    int threadIds[8];

    for (int i = 0; i < 8; i++) {
        threadIds[i] = i;
        threads[i] = CreateThread(NULL, 0, thread_func, &threadIds[i], 0, NULL);
    }

    WaitForMultipleObjects(8, threads, TRUE, INFINITE);

    for (int i = 0; i < 8; i++) {
        CloseHandle(threads[i]);
    }

    printf("Shared counter: %ld\n", shared_counter);

    unsigned int checksum = 0;
    for (int i = 0; i < $dataSize; i++) {
        checksum += thread_data[i];
    }
    printf("Data checksum: 0x%08X\n", checksum);

    return 0;
}
"@

    Set-Content -Path (Join-Path $sampleDir "source.cpp") -Value $cppSource -Encoding UTF8

    $exePath = Join-Path $sampleDir "$id.exe"
    $logPath = Join-Path $sampleDir "compile.log"

    $compileResult = & g++ -O0 -static -o $exePath (Join-Path $sampleDir "source.cpp") -lpthread 2>&1
    $compileResult | Out-File -FilePath $logPath -Encoding UTF8

    if (Test-Path $exePath) {
        $sha256 = Get-SHA256 -Path $exePath
        $md5 = Get-MD5 -Path $exePath
        $fileSize = (Get-Item $exePath).Length
        $arch = Get-PEArchitecture -Path $exePath
        $sections = Get-PESections -Path $exePath
        $peTimestamp = Get-PETimestamp -Path $exePath

        $manifest = [ordered]@{
            sample_id    = $id
            display_name = "Thread Creation $($size.FriendlySize)"
            category     = "unsigned"
            sub_category = "threads"
            type         = "native_pe"
            signed       = $false
            compiler     = @{
                name     = "MinGW GCC"
                version  = $gppVersion
                language = "C++"
                flags    = "-O0 -static -lpthread"
            }
            binary = @{
                filename          = "$id.exe"
                original_filename = ""
                original_path     = ""
                size_bytes        = $fileSize
                sha256            = $sha256
                md5               = $md5
                compile_timestamp = $peTimestamp
                pe_timestamp      = $peTimestamp
                architecture      = $arch
            }
            pe_features = @{
                sections    = $sections
                imports     = @()
                exports     = @()
                resources   = $false
                certificate = $false
                overlay     = $false
                dotnet      = $false
            }
            metadata     = @{}
            dataset = @{
                generated   = $true
                source_file = "source.cpp"
                created_by  = "DefenderAtlas Dataset Generator"
                created_on  = $generatedOn
            }
            research = @{
                procmon_trace   = $null
                analysis_report = $null
                timeline        = $null
                phase_detection = $null
                findings        = @()
                rule_matches    = @()
                confidence      = $null
                notes           = ""
            }
        }

        $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $sampleDir "manifest.json") -Encoding UTF8

        $unsignedSamples += [ordered]@{
            sample_id   = $id
            category    = "unsigned"
            sub_category = "threads"
            signed      = $false
            path        = "unsigned/threads/$id/$id.exe"
            manifest    = "unsigned/threads/$id/manifest.json"
            sha256      = $sha256
            size_bytes  = $fileSize
            arch        = $arch
        }

        Write-Host "    [+] $id.exe ($($fileSize / 1KB)KB)" -ForegroundColor Gray
    } else {
        Write-Host "    [-] Failed to compile $id" -ForegroundColor Red
    }
}

Write-Host "`n  Total unsigned samples: $($unsignedSamples.Count)" -ForegroundColor Green

# ============================================================
# PART 4 & 7: MASTER DATASET INDEX
# ============================================================
Write-Host "`n=== PART 4/7: Generating Master Dataset Index ===" -ForegroundColor Green

$allSamples = @()

# Add signed samples
foreach ($s in $signedSamples) {
    $allSamples += [ordered]@{
        sample_id   = $s.sample_id
        category    = $s.category
        sub_category = $s.sub_category
        signed      = $s.signed
        path        = "signed/$($s.path)"
        manifest    = "signed/$($s.manifest)"
        sha256      = $s.sha256
        size_bytes  = $s.size_bytes
        metadata    = [ordered]@{
            company   = $s.company
            product   = $s.product
            version   = $s.version
            signature = $s.signature
            arch      = $s.arch
        }
    }
}

# Add driver samples
foreach ($s in $driverSamples) {
    $allSamples += [ordered]@{
        sample_id   = $s.sample_id
        category    = $s.category
        sub_category = "kernel_driver"
        signed      = $s.signed
        path        = $s.path
        manifest    = $s.manifest
        sha256      = $s.sha256
        size_bytes  = $s.size_bytes
        metadata    = [ordered]@{
            company   = $s.company
            product   = $s.product
            version   = $s.version
            signature = $s.signature
            arch      = $s.arch
            original  = $s.original
        }
    }
}

# Add unsigned samples
foreach ($s in $unsignedSamples) {
    $allSamples += [ordered]@{
        sample_id   = $s.sample_id
        category    = $s.category
        sub_category = $s.sub_category
        signed      = $s.signed
        path        = $s.path
        manifest    = $s.manifest
        sha256      = $s.sha256
        size_bytes  = $s.size_bytes
        metadata    = [ordered]@{
            arch = $s.arch
        }
    }
}

$masterIndex = [ordered]@{
    version      = "1.0"
    generator    = "DefenderAtlas Research Dataset Generator"
    generated_on = $generatedOn
    total_samples = $allSamples.Count
    summary      = [ordered]@{
        signed_executables = $signedSamples.Count
        drivers            = $driverSamples.Count
        unsigned_executables = $unsignedSamples.Count
    }
    samples      = $allSamples
}

$indexPath = Join-Path $BasePath "index.json"
$masterIndex | ConvertTo-Json -Depth 10 | Set-Content -Path $indexPath -Encoding UTF8
Write-Host "  Generated index.json with $($allSamples.Count) samples" -ForegroundColor Green

# ============================================================
# PART 5 & 9: DATASET REPORT & QUALITY CHECKS
# ============================================================
Write-Host "`n=== PART 5/9: Generating Dataset Report & Quality Checks ===" -ForegroundColor Green

# Quality checks
$qualityIssues = @()

# Check all signed files exist
foreach ($s in $signedSamples) {
    $fullPath = Join-Path $BasePath "signed/$($s.path)"
    if (-not (Test-Path $fullPath)) {
        $qualityIssues += "Missing signed sample: $($s.sample_id)"
    }
}

# Check all driver files exist
foreach ($s in $driverSamples) {
    $fullPath = Join-Path $BasePath $s.path
    if (-not (Test-Path $fullPath)) {
        $qualityIssues += "Missing driver sample: $($s.sample_id)"
    }
}

# Check all unsigned files exist
foreach ($s in $unsignedSamples) {
    $fullPath = Join-Path $BasePath $s.path
    if (-not (Test-Path $fullPath)) {
        $qualityIssues += "Missing unsigned sample: $($s.sample_id)"
    }
}

# Check all manifests exist
$allManifestChecks = @()
$allManifestChecks += $signedSamples | ForEach-Object { @{ id = $_.sample_id; path = "signed/$($_.manifest)" } }
$allManifestChecks += $driverSamples | ForEach-Object { @{ id = $_.sample_id; path = $_.manifest } }
$allManifestChecks += $unsignedSamples | ForEach-Object { @{ id = $_.sample_id; path = $_.manifest } }

foreach ($m in $allManifestChecks) {
    $fullPath = Join-Path $BasePath $m.path
    if (-not (Test-Path $fullPath)) {
        $qualityIssues += "Missing manifest for: $($m.id)"
    }
}

# Size distribution analysis
$sizeDistribution = @{
    "under_100KB"  = 0
    "100KB_500KB"  = 0
    "500KB_1MB"    = 0
    "1MB_5MB"      = 0
    "5MB_10MB"     = 0
    "10MB_20MB"    = 0
    "over_20MB"    = 0
}

foreach ($s in $allSamples) {
    $size = $s.size_bytes
    if ($size -lt 102400) { $sizeDistribution["under_100KB"]++ }
    elseif ($size -lt 512000) { $sizeDistribution["100KB_500KB"]++ }
    elseif ($size -lt 1048576) { $sizeDistribution["500KB_1MB"]++ }
    elseif ($size -lt 5242880) { $sizeDistribution["1MB_5MB"]++ }
    elseif ($size -lt 10485760) { $sizeDistribution["5MB_10MB"]++ }
    elseif ($size -lt 20971520) { $sizeDistribution["10MB_20MB"]++ }
    else { $sizeDistribution["over_20MB"]++ }
}

# Category distribution
$categoryDist = @{}
foreach ($s in $allSamples) {
    $key = "$($s.category)/$($s.sub_category)"
    if (-not $categoryDist.ContainsKey($key)) { $categoryDist[$key] = 0 }
    $categoryDist[$key]++
}

# Architecture distribution
$archDist = @{}
foreach ($s in $allSamples) {
    $arch = if ($s.metadata -and $s.metadata.arch) { $s.metadata.arch } else { "Unknown" }
    if (-not $archDist.ContainsKey($arch)) { $archDist[$arch] = 0 }
    $archDist[$arch]++
}

# Size stats
$totalSize = ($allSamples | Measure-Object -Property size_bytes -Sum).Sum
$minSize = ($allSamples | Measure-Object -Property size_bytes -Minimum).Minimum
$maxSize = ($allSamples | Measure-Object -Property size_bytes -Maximum).Maximum
$avgSize = ($allSamples | Measure-Object -Property size_bytes -Average).Average

# Find missing categories
$expectedCategories = @("hello", "imports", "arrays", "resources", "functions", "switches", "recursion", "fileio", "network", "threads")
$presentCategories = $categoryDist.Keys | ForEach-Object { ($_ -split "/")[1] }
$missingCategories = $expectedCategories | Where-Object { $_ -notin $presentCategories }

# Generate report
$report = @"
# DefenderAtlas Research Dataset Report

Generated: $generatedOn
Generator: DefenderAtlas Research Dataset Generator v1.0

---

## Summary

| Metric | Count |
|--------|-------|
| Total Samples | $($allSamples.Count) |
| Signed Executables | $($signedSamples.Count) |
| Windows Drivers | $($driverSamples.Count) |
| Unsigned Executables | $($unsignedSamples.Count) |

## Size Distribution

| Range | Count |
|-------|-------|
| Under 100 KB | $($sizeDistribution["under_100KB"]) |
| 100 KB - 500 KB | $($sizeDistribution["100KB_500KB"]) |
| 500 KB - 1 MB | $($sizeDistribution["500KB_1MB"]) |
| 1 MB - 5 MB | $($sizeDistribution["1MB_5MB"]) |
| 5 MB - 10 MB | $($sizeDistribution["5MB_10MB"]) |
| 10 MB - 20 MB | $($sizeDistribution["10MB_20MB"]) |
| Over 20 MB | $($sizeDistribution["over_20MB"]) |

## Size Statistics

- Total dataset size: $([Math]::Round($totalSize / 1MB, 2)) MB
- Smallest sample: $([Math]::Round($minSize / 1KB, 2)) KB
- Largest sample: $([Math]::Round($maxSize / 1MB, 2)) MB
- Average size: $([Math]::Round($avgSize / 1KB, 2)) KB

## Category Distribution

| Category | Count |
|----------|-------|
$($categoryDist.GetEnumerator() | Sort-Object Name | ForEach-Object { "| $($_.Key) | $($_.Value) |" })

## Architecture Distribution

| Architecture | Count |
|--------------|-------|
$($archDist.GetEnumerator() | Sort-Object Name | ForEach-Object { "| $($_.Key) | $($_.Value) |" })

## Signed Executables

### Tiny (< 100 KB)
$($signedSamples | Where-Object { $_.sub_category -eq "tiny" } | ForEach-Object { "- **$($_.sample_id)** - $($_.product) ($([Math]::Round($_.size_bytes / 1KB, 1)) KB) - Signature: $($_.signature)" })

### Small (100-500 KB)
$($signedSamples | Where-Object { $_.sub_category -eq "small" } | ForEach-Object { "- **$($_.sample_id)** - $($_.product) ($([Math]::Round($_.size_bytes / 1KB, 1)) KB) - Signature: $($_.signature)" })

### Medium (500 KB - 2 MB)
$($signedSamples | Where-Object { $_.sub_category -eq "medium" } | ForEach-Object { "- **$($_.sample_id)** - $($_.product) ($([Math]::Round($_.size_bytes / 1KB, 1)) KB) - Signature: $($_.signature)" })

### Large (2 MB - 10 MB)
$($signedSamples | Where-Object { $_.sub_category -eq "large" } | ForEach-Object { "- **$($_.sample_id)** - $($_.product) ($([Math]::Round($_.size_bytes / 1MB, 2)) MB) - Signature: $($_.signature)" })

### Huge (> 10 MB)
$($signedSamples | Where-Object { $_.sub_category -eq "huge" } | ForEach-Object { "- **$($_.sample_id)** - $($_.product) ($([Math]::Round($_.size_bytes / 1MB, 2)) MB) - Signature: $($_.signature)" })

## Drivers

$($driverSamples | ForEach-Object { "- **$($_.sample_id)** ($($_.original)) - $([Math]::Round($_.size_bytes / 1KB, 1)) KB - Signature: $($_.signature)" })

## Unsigned Executables by Category

### A - Hello World (Minimal)
$($unsignedSamples | Where-Object { $_.sub_category -eq "hello" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### B - Many Imports
$($unsignedSamples | Where-Object { $_.sub_category -eq "imports" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### C - Large Global Arrays
$($unsignedSamples | Where-Object { $_.sub_category -eq "arrays" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### D - Resource-like Data
$($unsignedSamples | Where-Object { $_.sub_category -eq "resources" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### E - Many Functions
$($unsignedSamples | Where-Object { $_.sub_category -eq "functions" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### F - Large Switch Statements
$($unsignedSamples | Where-Object { $_.sub_category -eq "switches" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### G - Recursive Algorithms
$($unsignedSamples | Where-Object { $_.sub_category -eq "recursion" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### H - File I/O
$($unsignedSamples | Where-Object { $_.sub_category -eq "fileio" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### I - Network API Imports
$($unsignedSamples | Where-Object { $_.sub_category -eq "network" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

### J - Thread Creation
$($unsignedSamples | Where-Object { $_.sub_category -eq "threads" } | ForEach-Object { "- **$($_.sample_id)** - $([Math]::Round($_.size_bytes / 1KB, 1)) KB" })

## Quality Checks

$($qualityIssues | ForEach-Object { "- [ ] $_" })
$($qualityIssues.Count -eq 0 ? "- [x] All files verified present" : "")

## Missing Categories

$($missingCategories.Count -eq 0 ? "None - all expected categories are present." : ($missingCategories | ForEach-Object { "- $_" }))

## Estimated Research Coverage

- **Signed binaries**: Covers Microsoft official executables across all size ranges
- **Drivers**: Covers kernel-mode drivers from various subsystems (storage, network, input, display, USB)
- **Unsigned categories**: Each category tests a different PE analysis dimension:
  - A (hello): Minimal PE structure
  - B (imports): Complex import directory
  - C (arrays): Large .data/.bss sections
  - D (resources): Embedded data patterns
  - E (functions): High code complexity
  - F (switches): Branch-heavy control flow
  - G (recursion): Stack-intensive patterns
  - H (fileio): File system API usage
  - I (network): Network API imports
  - J (threads): Multi-threaded patterns

## Future Automation

This dataset is designed for direct use with DefenderAtlas:

```
defenderatlas experiment datasets/
```

Each sample includes a manifest.json with reserved fields for:
- ProcMon traces
- Analysis reports
- Timeline data
- Phase detection results
- Findings and rule matches

## Reproducibility

This dataset is fully reproducible:
1. All unsigned executables are generated from C++ source code
2. Compiler: MinGW GCC (g++)
3. All signed executables are official Microsoft binaries
4. All drivers are official Windows kernel drivers
5. No external downloads or untrusted sources used
6. SHA256 hashes provided for verification

---

*This dataset is for research purposes only. It is NOT malware.*
*Generated by DefenderAtlas Research Dataset Generator*
"@

$reportPath = Join-Path (Split-Path $BasePath -Parent) "DATASET_REPORT.md"
$report | Set-Content -Path $reportPath -Encoding UTF8
Write-Host "  Generated DATASET_REPORT.md" -ForegroundColor Green

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  Dataset Generation Complete!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Total samples: $($allSamples.Count)" -ForegroundColor White
Write-Host "  Signed: $($signedSamples.Count) | Drivers: $($driverSamples.Count) | Unsigned: $($unsignedSamples.Count)" -ForegroundColor White
Write-Host "  Quality issues: $($qualityIssues.Count)" -ForegroundColor $(if ($qualityIssues.Count -eq 0) { "Green" } else { "Yellow" })
Write-Host ""
Write-Host "  Output:" -ForegroundColor White
Write-Host "    $indexPath" -ForegroundColor Gray
Write-Host "    $reportPath" -ForegroundColor Gray
Write-Host ""
