$ErrorActionPreference = "Stop"
$pluginName = "codex-control-plane-hooks"

function Write-LauncherFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message
    )

    [Console]::Error.WriteLine("${pluginName}: $Message")
}

function Initialize-NativeMethods {
    if ($null -ne ("CodexLauncherNative" -as [type])) {
        return
    }

    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class CodexLauncherNative
{
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileAttributeReparsePoint = 0x00000400;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile
    );

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int fileInformationClass,
        out FileAttributeTagInfo fileInformation,
        uint bufferSize
    );

    public static SafeFileHandle OpenDirectoryDeleteLock(string path)
    {
        return CreateFileW(
            path,
            0,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero
        );
    }

    public static SafeFileHandle OpenFileDeleteLock(string path)
    {
        return CreateFileW(
            path,
            0,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero
        );
    }

    public static bool IsReparsePoint(SafeFileHandle handle)
    {
        FileAttributeTagInfo information;
        if (!GetFileInformationByHandleEx(
            handle,
            9,
            out information,
            (uint)Marshal.SizeOf(typeof(FileAttributeTagInfo))))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return (information.FileAttributes & FileAttributeReparsePoint) != 0;
    }
}
"@ -ErrorAction Stop | Out-Null
}

function Lock-DirectoryChain {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[System.IDisposable]] $Locks
    )

    $directories = New-Object System.Collections.Generic.List[string]
    $current = [System.IO.Path]::GetFullPath($Path)
    while ($null -ne $current) {
        if (Test-Path -LiteralPath $current -PathType Container) {
            $directories.Insert(0, $current)
        }
        $parent = [System.IO.Directory]::GetParent($current)
        $current = if ($null -eq $parent) { $null } else { $parent.FullName }
    }
    foreach ($directory in $directories) {
        $handle = [CodexLauncherNative]::OpenDirectoryDeleteLock($directory)
        if ($handle.IsInvalid -or [CodexLauncherNative]::IsReparsePoint($handle)) {
            $handle.Dispose()
            throw "Untrusted directory path"
        }
        $Locks.Add($handle)
    }
}

function Lock-FileAgainstReplacement {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[System.IDisposable]] $Locks
    )

    $handle = [CodexLauncherNative]::OpenFileDeleteLock($Path)
    if ($handle.IsInvalid -or [CodexLauncherNative]::IsReparsePoint($handle)) {
        $handle.Dispose()
        throw "Untrusted file path"
    }
    $Locks.Add($handle)
}

function Close-PathLocks {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[System.IDisposable]] $Locks
    )

    for ($index = $Locks.Count - 1; $index -ge 0; $index--) {
        try {
            $Locks[$index].Dispose()
        }
        catch {
        }
    }
    $Locks.Clear()
}

if ([String]::IsNullOrWhiteSpace($env:PLUGIN_DATA)) {
    Write-LauncherFailure -Message "runtime is not configured"
    exit 127
}

try {
    if (-not [System.IO.Path]::IsPathRooted($env:PLUGIN_DATA)) {
        throw "Plugin data path must be absolute"
    }
    $pluginData = [System.IO.Path]::GetFullPath($env:PLUGIN_DATA)
    if (-not (Test-Path -LiteralPath $pluginData -PathType Container)) {
        throw "Plugin data directory does not exist"
    }
    $manifestPath = Join-Path $pluginData "runtime.json"
}
catch {
    Write-LauncherFailure -Message "runtime manifest is invalid"
    exit 126
}

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    Write-LauncherFailure -Message "runtime is not configured"
    exit 127
}

$pathLocks = New-Object System.Collections.Generic.List[System.IDisposable]
try {
    Initialize-NativeMethods
    Lock-DirectoryChain -Path $pluginData -Locks $pathLocks
    Lock-FileAgainstReplacement -Path $manifestPath -Locks $pathLocks
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    if (
        $manifestBytes.Length -eq 0 -or
        $manifestBytes.Length -gt 16384 -or
        ($manifestBytes.Length -ge 3 -and
            $manifestBytes[0] -eq 0xEF -and
            $manifestBytes[1] -eq 0xBB -and
            $manifestBytes[2] -eq 0xBF)
    ) {
        throw "Invalid runtime manifest encoding or size"
    }
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $manifestJson = $strictUtf8.GetString($manifestBytes)
    $runtimeManifest = $manifestJson | ConvertFrom-Json -ErrorAction Stop
    $expectedFields = @(
        "schema_version",
        "interpreter",
        "python_version",
        "runtime_root",
        "configured_at"
    )
    $propertyMatches = [Regex]::Matches(
        $manifestJson,
        '"(?<key>(?:\\.|[^"\\])*)"\s*:'
    )
    if ($propertyMatches.Count -ne $expectedFields.Count) {
        throw "Invalid runtime manifest fields"
    }
    $actualFields = @($runtimeManifest.PSObject.Properties.Name)
    if ($actualFields.Count -ne $expectedFields.Count) {
        throw "Invalid runtime manifest fields"
    }
    foreach ($field in $expectedFields) {
        if (
            @($propertyMatches | Where-Object { $_.Groups["key"].Value -ceq $field }).Count -ne 1 -or
            @($actualFields | Where-Object { $_ -ceq $field }).Count -ne 1
        ) {
            throw "Invalid runtime manifest fields"
        }
    }
    if (
        ($runtimeManifest.schema_version -isnot [int] -and
            $runtimeManifest.schema_version -isnot [long]) -or
        $runtimeManifest.schema_version -ne 1 -or
        $runtimeManifest.interpreter -isnot [string] -or
        $runtimeManifest.python_version -isnot [string] -or
        $runtimeManifest.runtime_root -isnot [string] -or
        ($runtimeManifest.configured_at -isnot [string] -and
            $runtimeManifest.configured_at -isnot [datetime])
    ) {
        throw "Invalid runtime manifest field values"
    }

    $userProfile = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::UserProfile
    )
    if ([String]::IsNullOrWhiteSpace($userProfile)) {
        throw "Windows user profile is unavailable"
    }
    $expectedRuntimeRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $userProfile ".codex\runtimes\$pluginName")
    )
    if (-not [System.IO.Path]::IsPathRooted($runtimeManifest.runtime_root)) {
        throw "Runtime root must be absolute"
    }
    $runtimeRoot = [System.IO.Path]::GetFullPath($runtimeManifest.runtime_root)
    if (-not $runtimeRoot.Equals(
        $expectedRuntimeRoot,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Runtime root is not trusted"
    }
    if ($runtimeManifest.python_version -cnotmatch '^3\.12\.\d+$') {
        throw "Runtime version is invalid"
    }
    $configuredAtMatch = [Regex]::Match(
        $manifestJson,
        '"configured_at"\s*:\s*"(?<value>\d{4}-\d{2}-\d{2}T[^"\\]+Z)"'
    )
    if (-not $configuredAtMatch.Success) {
        throw "Runtime timestamp is invalid"
    }
    $configuredAtText = $configuredAtMatch.Groups["value"].Value
    $configuredAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
        $configuredAtText,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref] $configuredAt
    )) {
        throw "Runtime timestamp is invalid"
    }
    if (-not [System.IO.Path]::IsPathRooted($runtimeManifest.interpreter)) {
        throw "Runtime interpreter must be absolute"
    }
    $interpreter = [System.IO.Path]::GetFullPath($runtimeManifest.interpreter)
    $versionDirectory = [System.IO.Directory]::GetParent(
        [System.IO.Directory]::GetParent($interpreter).FullName
    ).FullName
    $runtimeId = [System.IO.Path]::GetFileName($versionDirectory)
    if ($runtimeId -cnotmatch '^py312-[0-9a-f]{16}$') {
        throw "Runtime identifier is invalid"
    }
    $expectedInterpreter = [System.IO.Path]::GetFullPath(
        (Join-Path $runtimeRoot "versions\$runtimeId\Scripts\python.exe")
    )
    if (-not $interpreter.Equals(
        $expectedInterpreter,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Runtime interpreter is not trusted"
    }
    if (-not (Test-Path -LiteralPath $interpreter -PathType Leaf)) {
        throw "Runtime interpreter does not exist"
    }
    $scriptsDirectory = [System.IO.Directory]::GetParent($interpreter).FullName
    Lock-DirectoryChain -Path $scriptsDirectory -Locks $pathLocks
    Lock-FileAgainstReplacement -Path $interpreter -Locks $pathLocks
    $hookScript = Join-Path $PSScriptRoot "control_plane_hook.py"
    if (-not (Test-Path -LiteralPath $hookScript -PathType Leaf)) {
        throw "Hook script does not exist"
    }
}
catch {
    Close-PathLocks -Locks $pathLocks
    Write-LauncherFailure -Message "runtime manifest is invalid"
    exit 126
}

$bootstrap = @'
import runpy
import sys

if sys.version_info[:2] != (3, 12):
    sys.stderr.write('codex-control-plane-hooks: configured runtime must use Python 3.12\n')
    raise SystemExit(126)

import ctypes
import os

event_name = os.environ.pop('CODEX_RUNTIME_READY_EVENT', '')
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
open_event = kernel32.OpenEventW
open_event.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
open_event.restype = ctypes.c_void_p
set_event = kernel32.SetEvent
set_event.argtypes = [ctypes.c_void_p]
set_event.restype = ctypes.c_int
close_handle = kernel32.CloseHandle
close_handle.argtypes = [ctypes.c_void_p]
close_handle.restype = ctypes.c_int
event_handle = open_event(0x0002, 0, event_name)
if not event_handle or not set_event(event_handle):
    sys.stderr.write('codex-control-plane-hooks: runtime verification failed\n')
    raise SystemExit(126)
close_handle(event_handle)

hook_path = sys.argv[1]
sys.argv = [hook_path]
runpy.run_path(hook_path, run_name='__main__')
'@

$childExit = 126
$eventName = "Local\CodexRuntimeReady-" + [Guid]::NewGuid().ToString("N")
$runtimeReadyEvent = [System.Threading.EventWaitHandle]::new(
    $false,
    [System.Threading.EventResetMode]::ManualReset,
    $eventName
)
$env:CODEX_RUNTIME_READY_EVENT = $eventName
try {
    & $interpreter -I -S -c $bootstrap $hookScript
    if ($runtimeReadyEvent.WaitOne(0) -and $null -ne $LASTEXITCODE) {
        $childExit = [int] $LASTEXITCODE
    }
    else {
        Write-LauncherFailure -Message "configured runtime could not be verified"
    }
}
catch {
    Write-LauncherFailure -Message "configured runtime could not be started"
}
finally {
    Remove-Item Env:\CODEX_RUNTIME_READY_EVENT -ErrorAction SilentlyContinue
    $runtimeReadyEvent.Dispose()
    Close-PathLocks -Locks $pathLocks
}
exit $childExit
