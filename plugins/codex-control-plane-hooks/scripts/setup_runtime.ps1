[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PythonPath,

    [Parameter(Mandatory = $false)]
    [string] $PluginDataPath,

    [Parameter(Mandatory = $false)]
    [string] $CodexHome,

    [Parameter(Mandatory = $false)]
    [switch] $PruneOldRuntime,

    [Parameter(Mandatory = $false)]
    [ValidateRange(2, 100)]
    [int] $Keep = 2
)

$ErrorActionPreference = "Stop"
$pluginName = "codex-control-plane-hooks"
$stagingDirectory = $null
$temporaryManifest = $null
$pathLocks = New-Object System.Collections.Generic.List[System.IDisposable]

function Initialize-NativeMethods {
    if ($null -ne ("CodexRuntimeNative" -as [type])) {
        return
    }

    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class CodexRuntimeNative
{
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileReadAttributes = 0x00000080;
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        IntPtr fileInformation,
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

    public static SafeFileHandle OpenDirectoryForRename(string path)
    {
        return CreateFileW(
            path,
            DeleteAccess | FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
            IntPtr.Zero
        );
    }

    public static SafeFileHandle OpenFileForRename(string path)
    {
        return CreateFileW(
            path,
            DeleteAccess | FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero
        );
    }

    public static SafeFileHandle OpenPruneGate(string path)
    {
        return CreateFileW(
            path,
            DeleteAccess | FileReadAttributes,
            FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero
        );
    }

    public static SafeFileHandle OpenFileForSafeDelete(string path)
    {
        return CreateFileW(
            path,
            DeleteAccess | FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint,
            IntPtr.Zero
        );
    }

    public static SafeFileHandle OpenDirectoryForSafeDelete(string path)
    {
        return CreateFileW(
            path,
            DeleteAccess | FileReadAttributes,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagBackupSemantics,
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

    public static void RenameByHandle(
        SafeFileHandle handle,
        string destinationName,
        bool replaceExisting)
    {
        string nativeDestination = @"\??\" + destinationName;
        byte[] name = System.Text.Encoding.Unicode.GetBytes(nativeDestination);
        int rootOffset = IntPtr.Size;
        int lengthOffset = IntPtr.Size * 2;
        int nameOffset = lengthOffset + sizeof(uint);
        int bufferSize = nameOffset + name.Length + sizeof(char);
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            for (int index = 0; index < bufferSize; index++)
            {
                Marshal.WriteByte(buffer, index, 0);
            }
            Marshal.WriteByte(buffer, 0, replaceExisting ? (byte)1 : (byte)0);
            Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
            Marshal.WriteInt32(buffer, lengthOffset, name.Length);
            Marshal.Copy(name, 0, IntPtr.Add(buffer, nameOffset), name.Length);
            if (!SetFileInformationByHandle(handle, 3, buffer, (uint)bufferSize))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static void DeleteByHandle(SafeFileHandle handle)
    {
        IntPtr information = Marshal.AllocHGlobal(1);
        try
        {
            Marshal.WriteByte(information, 0, 1);
            if (!SetFileInformationByHandle(handle, 4, information, 1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(information);
        }
    }
}
"@ -ErrorAction Stop | Out-Null
}

function Write-Failure {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message
    )

    [Console]::Error.WriteLine("${pluginName}: $Message")
}

function Stop-SafeFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message
    )

    throw [System.InvalidOperationException]::new($Message)
}

function Lock-DirectoryChain {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[System.IDisposable]] $Locks,

        [Parameter(Mandatory = $true)]
        [string] $Description,

        [Parameter(Mandatory = $false)]
        [string] $TrustedRoot
    )

    $directories = New-Object System.Collections.Generic.List[string]
    $current = [System.IO.Path]::GetFullPath($Path)
    $trusted = $null
    $trustedParent = $null
    if (-not [String]::IsNullOrWhiteSpace($TrustedRoot)) {
        $trusted = [System.IO.Path]::GetFullPath($TrustedRoot)
        $trustedParentInfo = [System.IO.Directory]::GetParent($trusted)
        if ($null -ne $trustedParentInfo) {
            $trustedParent = $trustedParentInfo.FullName
        }
    }
    while ($null -ne $current) {
        $parent = [System.IO.Directory]::GetParent($current)
        $isTrustedRoot = (
            $null -ne $trusted -and
            $current.Equals($trusted, [StringComparison]::OrdinalIgnoreCase)
        )
        # Sandboxed launchers can expose a sibling OS-managed user profile.
        # Never require delete-denying locks on a profile directory itself.
        $isPeerProfileRoot = (
            $null -ne $trustedParent -and
            $null -ne $parent -and
            $parent.FullName.Equals(
                $trustedParent,
                [StringComparison]::OrdinalIgnoreCase
            )
        )
        if ($isTrustedRoot -or $isPeerProfileRoot) {
            break
        }
        if (Test-Path -LiteralPath $current -PathType Container) {
            $directories.Insert(0, $current)
        }
        if ($null -eq $parent) {
            $current = $null
        }
        else {
            $current = $parent.FullName
        }
    }
    foreach ($directory in $directories) {
        $handle = [CodexRuntimeNative]::OpenDirectoryDeleteLock($directory)
        if ($handle.IsInvalid) {
            $handle.Dispose()
            Stop-SafeFailure -Message "$Description could not be locked safely"
        }
        $Locks.Add($handle)
        Assert-NoReparsePoint -Path $directory -Description $Description
    }
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

function Lock-FileAgainstReplacement {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[System.IDisposable]] $Locks,

        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    $handle = [CodexRuntimeNative]::OpenFileDeleteLock($Path)
    if ($handle.IsInvalid) {
        $handle.Dispose()
        Stop-SafeFailure -Message "$Description could not be locked safely"
    }
    $Locks.Add($handle)
    if ([CodexRuntimeNative]::IsReparsePoint($handle)) {
        Stop-SafeFailure -Message "$Description contains a reparse point"
    }
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    $current = [System.IO.Path]::GetFullPath($Path)
    while ($null -ne $current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (
                ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                Stop-SafeFailure -Message "$Description contains a reparse point"
            }
        }
        $parent = [System.IO.Directory]::GetParent($current)
        if ($null -eq $parent) {
            $current = $null
        }
        else {
            $current = $parent.FullName
        }
    }
}

function Get-FullExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Description,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Leaf", "Container")]
        [string] $PathType
    )

    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        Stop-SafeFailure -Message "$Description must be an absolute path"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType $PathType)) {
        Stop-SafeFailure -Message "$Description does not exist"
    }
    Assert-NoReparsePoint -Path $fullPath -Description $Description
    return $fullPath
}

function Assert-ManifestTargetSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PluginData,

        [Parameter(Mandatory = $true)]
        [string] $ManifestPath
    )

    Assert-NoReparsePoint -Path $PluginData -Description "PluginDataPath"
    if (Test-Path -LiteralPath $ManifestPath) {
        Assert-NoReparsePoint `
            -Path $ManifestPath `
            -Description "Existing runtime manifest"
        if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
            Stop-SafeFailure -Message "Existing runtime manifest must be a regular file"
        }
    }
}

function Get-PythonVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Interpreter
    )

    $version = & $Interpreter -I -S -c (
        "import sys; print('.'.join(map(str, sys.version_info[:3]))); " +
        "raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)"
    ) 2>$null
    if ($LASTEXITCODE -ne 0 -or $version.Count -ne 1) {
        Stop-SafeFailure -Message "PythonPath must identify Python 3.12"
    }
    return [string] $version
}

function Test-PluginDataName {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    return (
        $Name.Equals($pluginName, [StringComparison]::OrdinalIgnoreCase) -or
        $Name.StartsWith($pluginName + "-", [StringComparison]::OrdinalIgnoreCase)
    )
}

function Get-PluginDataDirectory {
    param(
        [Parameter(Mandatory = $false)]
        [string] $ExplicitPath,

        [Parameter(Mandatory = $false)]
        [string] $ExplicitCodexHome,

        [Parameter(Mandatory = $true)]
        [string] $UserProfile
    )

    $resolvedCodexHome = $null
    if (-not [String]::IsNullOrWhiteSpace($ExplicitCodexHome)) {
        $resolvedCodexHome = Get-FullExistingPath `
            -Path $ExplicitCodexHome `
            -Description "CodexHome" `
            -PathType "Container"
    }

    $selectedPath = $ExplicitPath
    if ([String]::IsNullOrWhiteSpace($selectedPath)) {
        $selectedPath = $env:PLUGIN_DATA
    }
    if (-not [String]::IsNullOrWhiteSpace($selectedPath)) {
        $candidate = Get-FullExistingPath `
            -Path $selectedPath `
            -Description "PluginDataPath" `
            -PathType "Container"
        if (-not (Test-PluginDataName -Name ([System.IO.Path]::GetFileName($candidate)))) {
            Stop-SafeFailure -Message "PluginDataPath does not name this plugin"
        }
        $dataRoot = [System.IO.Directory]::GetParent($candidate).FullName
        if (
            -not ([System.IO.Path]::GetFileName($dataRoot)).Equals(
                "data",
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not ([System.IO.Path]::GetFileName(
                [System.IO.Directory]::GetParent($dataRoot).FullName
            )).Equals("plugins", [StringComparison]::OrdinalIgnoreCase)
        ) {
            Stop-SafeFailure -Message "PluginDataPath is outside the fixed plugins data directory"
        }
        if ($null -ne $resolvedCodexHome) {
            $expectedDataRoot = [System.IO.Path]::GetFullPath(
                (Join-Path $resolvedCodexHome "plugins\data")
            )
            if (-not $dataRoot.Equals(
                $expectedDataRoot,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                Stop-SafeFailure -Message "PluginDataPath is outside CodexHome"
            }
        }
        return $candidate
    }

    if ($null -eq $resolvedCodexHome) {
        $resolvedCodexHome = Join-Path $UserProfile ".codex"
        $resolvedCodexHome = Get-FullExistingPath `
            -Path $resolvedCodexHome `
            -Description "CodexHome" `
            -PathType "Container"
    }
    $dataRoot = Join-Path $resolvedCodexHome "plugins\data"
    $dataRoot = Get-FullExistingPath `
        -Path $dataRoot `
        -Description "Codex plugin data directory" `
        -PathType "Container"
    $candidates = @(
        Get-ChildItem -LiteralPath $dataRoot -Directory -Force |
            Where-Object { Test-PluginDataName -Name $_.Name }
    )
    if ($candidates.Count -ne 1) {
        Stop-SafeFailure -Message "Expected one plugin-data candidate; found $($candidates.Count)"
    }
    return Get-FullExistingPath `
        -Path $candidates[0].FullName `
        -Description "PluginDataPath" `
        -PathType "Container"
}

function Get-RuntimeId {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Interpreter,

        [Parameter(Mandatory = $true)]
        [string] $Version
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes(
        $Interpreter.ToLowerInvariant() + "`n" + $Version
    )
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($bytes)
    }
    finally {
        $sha256.Dispose()
    }
    $hex = ([System.BitConverter]::ToString($digest)).Replace("-", "").ToLowerInvariant()
    return "py312-" + $hex.Substring(0, 16)
}

function Test-RuntimeInterpreter {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Interpreter
    )

    if (-not (Test-Path -LiteralPath $Interpreter -PathType Leaf)) {
        return $false
    }
    & $Interpreter -I -S -c (
        "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)"
    ) 2>$null
    return $LASTEXITCODE -eq 0
}

function Test-InterpreterActive {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Interpreter
    )

    try {
        $expectedPath = [System.IO.Path]::GetFullPath($Interpreter)
        $processes = @(
            Get-CimInstance `
                -ClassName Win32_Process `
                -Filter "Name = 'python.exe'" `
                -ErrorAction Stop
        )
        foreach ($process in $processes) {
            if ([String]::IsNullOrWhiteSpace($process.ExecutablePath)) {
                return $null
            }
            $processPath = [System.IO.Path]::GetFullPath($process.ExecutablePath)
            if ($processPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        $nativeProcesses = @(Get-Process -Name "python" -ErrorAction SilentlyContinue)
        foreach ($process in $nativeProcesses) {
            try {
                $processPath = $process.Path
            }
            catch {
                return $null
            }
            if ([String]::IsNullOrWhiteSpace($processPath)) {
                return $null
            }
            $processPath = [System.IO.Path]::GetFullPath($processPath)
            if ($processPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }
    catch {
        return $null
    }
}

function Remove-FileByHandle {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $handle = [CodexRuntimeNative]::OpenFileForSafeDelete($Path)
    if ($handle.IsInvalid) {
        $handle.Dispose()
        return $false
    }
    try {
        [CodexRuntimeNative]::DeleteByHandle($handle)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $handle.Dispose()
    }
}

function Remove-RuntimeTreeByHandle {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $false)]
        [int] $Depth = 0
    )

    if ($Depth -gt 64) {
        return $false
    }
    $handle = [CodexRuntimeNative]::OpenDirectoryForSafeDelete($Path)
    if ($handle.IsInvalid) {
        $handle.Dispose()
        return $false
    }
    try {
        if ([CodexRuntimeNative]::IsReparsePoint($handle)) {
            [CodexRuntimeNative]::DeleteByHandle($handle)
            return $true
        }
        foreach ($attempt in 1..3) {
            $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
            if ($children.Count -eq 0) {
                [CodexRuntimeNative]::DeleteByHandle($handle)
                return $true
            }
            foreach ($child in $children) {
                if ($child.PSIsContainer) {
                    $removed = Remove-RuntimeTreeByHandle `
                        -Path $child.FullName `
                        -Depth ($Depth + 1)
                }
                else {
                    $removed = Remove-FileByHandle -Path $child.FullName
                }
                if (-not $removed) {
                    return $false
                }
            }
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        $handle.Dispose()
    }
}

function Remove-OldRuntimes {
    param(
        [Parameter(Mandatory = $true)]
        [string] $VersionsRoot,

        [Parameter(Mandatory = $true)]
        [string] $CurrentInterpreter,

        [Parameter(Mandatory = $true)]
        [int] $KeepCount
    )

    try {
        $currentScripts = [System.IO.Directory]::GetParent($CurrentInterpreter)
        $currentDirectory = $currentScripts.Parent.FullName
        $candidates = @(
            Get-ChildItem -LiteralPath $VersionsRoot -Directory -Force |
                Where-Object {
                    $_.Name -match '^[a-z0-9][a-z0-9-]{0,63}$' -and
                    -not $_.FullName.Equals(
                        $currentDirectory,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                } |
                Sort-Object -Property LastWriteTimeUtc -Descending
        )
        $preserveOldCount = [Math]::Max(0, $KeepCount - 1)
        for ($index = $preserveOldCount; $index -lt $candidates.Count; $index++) {
            $candidate = $candidates[$index]
            $quarantineGate = $null
            try {
                $candidateInterpreter = Join-Path $candidate.FullName "Scripts\python.exe"
                $skipCandidate = $false
                foreach ($inspection in 1..2) {
                    Assert-NoReparsePoint `
                        -Path $candidate.FullName `
                        -Description "Old runtime candidate"
                    $active = Test-InterpreterActive -Interpreter $candidateInterpreter
                    if ($null -eq $active) {
                        [Console]::Error.WriteLine(
                            "${pluginName}: skipped an old runtime because active-process inspection failed"
                        )
                        $skipCandidate = $true
                        break
                    }
                    if ($active) {
                        [Console]::Error.WriteLine(
                            "${pluginName}: skipped an active old runtime"
                        )
                        $skipCandidate = $true
                        break
                    }
                }
                if ($skipCandidate) {
                    continue
                }
                Assert-NoReparsePoint `
                    -Path $candidate.FullName `
                    -Description "Old runtime candidate"
                $candidateHandle = [CodexRuntimeNative]::OpenDirectoryForRename(
                    $candidate.FullName
                )
                if ($candidateHandle.IsInvalid) {
                    $candidateHandle.Dispose()
                    [Console]::Error.WriteLine(
                        "${pluginName}: skipped an old runtime that could not be pruned"
                    )
                    continue
                }
                try {
                    if ([CodexRuntimeNative]::IsReparsePoint($candidateHandle)) {
                        [Console]::Error.WriteLine(
                            "${pluginName}: skipped an old runtime that could not be pruned"
                        )
                        continue
                    }
                    $quarantineDirectory = Join-Path $VersionsRoot (
                        ".prune-" + [Guid]::NewGuid().ToString("N")
                    )
                    [CodexRuntimeNative]::RenameByHandle(
                        $candidateHandle,
                        $quarantineDirectory,
                        $false
                    )
                    $quarantineInterpreter = Join-Path `
                        $quarantineDirectory `
                        "Scripts\python.exe"
                    $unsafeAfterRename = $false
                    foreach ($interpreter in @(
                        $candidateInterpreter,
                        $quarantineInterpreter
                    )) {
                        $active = Test-InterpreterActive -Interpreter $interpreter
                        if ($null -eq $active -or $active) {
                            $unsafeAfterRename = $true
                            break
                        }
                    }
                    if ($unsafeAfterRename) {
                        try {
                            [CodexRuntimeNative]::RenameByHandle(
                                $candidateHandle,
                                $candidate.FullName,
                                $false
                            )
                        }
                        catch {
                            # Keep the quarantined runtime intact when restoration is blocked.
                        }
                        [Console]::Error.WriteLine(
                            "${pluginName}: skipped an active or uninspectable old runtime"
                        )
                        continue
                    }
                    $quarantineGate = [CodexRuntimeNative]::OpenPruneGate(
                        $quarantineInterpreter
                    )
                    if ($quarantineGate.IsInvalid) {
                        $quarantineGate.Dispose()
                        $quarantineGate = $null
                        [CodexRuntimeNative]::RenameByHandle(
                            $candidateHandle,
                            $candidate.FullName,
                            $false
                        )
                        [Console]::Error.WriteLine(
                            "${pluginName}: skipped an active old runtime"
                        )
                        continue
                    }
                    if ([CodexRuntimeNative]::IsReparsePoint($quarantineGate)) {
                        $quarantineGate.Dispose()
                        $quarantineGate = $null
                        [CodexRuntimeNative]::RenameByHandle(
                            $candidateHandle,
                            $candidate.FullName,
                            $false
                        )
                        [Console]::Error.WriteLine(
                            "${pluginName}: skipped an old runtime that could not be pruned"
                        )
                        continue
                    }
                    $quarantinedInterpreter = Join-Path `
                        ([System.IO.Directory]::GetParent($quarantineInterpreter).FullName) `
                        (".prune-python-" + [Guid]::NewGuid().ToString("N") + ".exe")
                    [CodexRuntimeNative]::RenameByHandle(
                        $quarantineGate,
                        $quarantinedInterpreter,
                        $false
                    )
                    [CodexRuntimeNative]::DeleteByHandle($quarantineGate)
                    $quarantineGate.Dispose()
                    $quarantineGate = $null
                }
                finally {
                    $candidateHandle.Dispose()
                }
                if (-not (Remove-RuntimeTreeByHandle -Path $quarantineDirectory)) {
                    throw [System.IO.IOException]::new("quarantined runtime could not be removed")
                }
            }
            catch {
                [Console]::Error.WriteLine(
                    "${pluginName}: skipped an old runtime that could not be pruned"
                )
            }
            finally {
                if ($null -ne $quarantineGate) {
                    $quarantineGate.Dispose()
                }
            }
        }
    }
    catch {
        [Console]::Error.WriteLine(
            "${pluginName}: old runtime pruning could not be completed"
        )
    }
}

try {
    Initialize-NativeMethods
    $userProfile = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::UserProfile
    )
    if ([String]::IsNullOrWhiteSpace($userProfile)) {
        Stop-SafeFailure -Message "Windows user profile could not be resolved"
    }
    $userProfile = [System.IO.Path]::GetFullPath($userProfile)
    Assert-NoReparsePoint -Path $userProfile -Description "Windows user profile"
    $python = Get-FullExistingPath `
        -Path $PythonPath `
        -Description "PythonPath" `
        -PathType "Leaf"
    Lock-DirectoryChain `
        -Path ([System.IO.Directory]::GetParent($python).FullName) `
        -Locks $pathLocks `
        -Description "PythonPath" `
        -TrustedRoot $userProfile
    Lock-FileAgainstReplacement `
        -Path $python `
        -Locks $pathLocks `
        -Description "PythonPath"
    $pluginData = Get-PluginDataDirectory `
        -ExplicitPath $PluginDataPath `
        -ExplicitCodexHome $CodexHome `
        -UserProfile $userProfile
    Lock-DirectoryChain `
        -Path $pluginData `
        -Locks $pathLocks `
        -Description "PluginDataPath" `
        -TrustedRoot $userProfile
    $manifestPath = Join-Path $pluginData "runtime.json"
    Assert-ManifestTargetSafe -PluginData $pluginData -ManifestPath $manifestPath
    Assert-NoReparsePoint -Path $python -Description "PythonPath"
    $pythonVersion = Get-PythonVersion -Interpreter $python
    $runtimeRoot = Join-Path $userProfile ".codex\runtimes\$pluginName"
    $versionsRoot = Join-Path $runtimeRoot "versions"
    Assert-NoReparsePoint -Path $runtimeRoot -Description "Runtime root"
    [System.IO.Directory]::CreateDirectory($versionsRoot) | Out-Null
    Assert-NoReparsePoint -Path $versionsRoot -Description "Runtime root"
    Lock-DirectoryChain `
        -Path $versionsRoot `
        -Locks $pathLocks `
        -Description "Runtime root" `
        -TrustedRoot $userProfile

    $runtimeId = Get-RuntimeId -Interpreter $python -Version $pythonVersion
    $versionDirectory = Join-Path $versionsRoot $runtimeId
    $runtimeInterpreter = Join-Path $versionDirectory "Scripts\python.exe"
    $runtimeVersionLocked = $false

    if (Test-Path -LiteralPath $versionDirectory) {
        Assert-NoReparsePoint `
            -Path $versionDirectory `
            -Description "Runtime version"
        if (-not (Test-Path -LiteralPath $versionDirectory -PathType Container)) {
            Stop-SafeFailure -Message "Runtime version must be a directory"
        }
        Lock-DirectoryChain `
            -Path $versionDirectory `
            -Locks $pathLocks `
            -Description "Runtime version" `
            -TrustedRoot $userProfile
        Lock-FileAgainstReplacement `
            -Path $runtimeInterpreter `
            -Locks $pathLocks `
            -Description "Runtime interpreter"
        $runtimeVersionLocked = $true
    }
    if (-not (Test-RuntimeInterpreter -Interpreter $runtimeInterpreter)) {
        $stagingDirectory = Join-Path $versionsRoot (
            ".staging-" + [Guid]::NewGuid().ToString("N")
        )
        Assert-NoReparsePoint -Path $python -Description "PythonPath"
        & $python -I -S -m venv $stagingDirectory *> $null
        if ($LASTEXITCODE -ne 0) {
            Stop-SafeFailure -Message "Python 3.12 failed to create the dedicated runtime"
        }
        $stagingInterpreter = Join-Path $stagingDirectory "Scripts\python.exe"
        if (-not (Test-RuntimeInterpreter -Interpreter $stagingInterpreter)) {
            Stop-SafeFailure -Message "The dedicated runtime failed its Python 3.12 smoke test"
        }
        if (Test-Path -LiteralPath $versionDirectory) {
            Stop-SafeFailure -Message "The selected runtime version already exists but is not usable"
        }
        Assert-NoReparsePoint -Path $versionsRoot -Description "Runtime root"
        Assert-NoReparsePoint -Path $versionDirectory -Description "Runtime version"
        [System.IO.Directory]::Move($stagingDirectory, $versionDirectory)
        $stagingDirectory = $null
    }
    if (-not $runtimeVersionLocked) {
        Lock-DirectoryChain `
            -Path $versionDirectory `
            -Locks $pathLocks `
            -Description "Runtime version" `
            -TrustedRoot $userProfile
        Lock-FileAgainstReplacement `
            -Path $runtimeInterpreter `
            -Locks $pathLocks `
            -Description "Runtime interpreter"
    }
    Assert-NoReparsePoint -Path $versionDirectory -Description "Runtime version"
    if (-not (Test-RuntimeInterpreter -Interpreter $runtimeInterpreter)) {
        Stop-SafeFailure -Message "The dedicated runtime failed its Python 3.12 smoke test"
    }

    $manifest = [ordered]@{
        schema_version = 1
        interpreter = $runtimeInterpreter
        python_version = $pythonVersion
        runtime_root = $runtimeRoot
        configured_at = [DateTime]::UtcNow.ToString("o")
    }
    $manifestJson = $manifest | ConvertTo-Json
    $temporaryManifest = Join-Path $pluginData (
        ".runtime-" + [Guid]::NewGuid().ToString("N") + ".tmp"
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    Assert-ManifestTargetSafe -PluginData $pluginData -ManifestPath $manifestPath
    [System.IO.File]::WriteAllText($temporaryManifest, $manifestJson + "`n", $utf8NoBom)
    Assert-NoReparsePoint -Path $temporaryManifest -Description "Temporary runtime manifest"
    Assert-ManifestTargetSafe -PluginData $pluginData -ManifestPath $manifestPath
    $temporaryManifestHandle = [CodexRuntimeNative]::OpenFileForRename(
        $temporaryManifest
    )
    if ($temporaryManifestHandle.IsInvalid) {
        $temporaryManifestHandle.Dispose()
        Stop-SafeFailure -Message "Temporary runtime manifest could not be published safely"
    }
    try {
        if ([CodexRuntimeNative]::IsReparsePoint($temporaryManifestHandle)) {
            Stop-SafeFailure -Message "Temporary runtime manifest contains a reparse point"
        }
        Assert-ManifestTargetSafe -PluginData $pluginData -ManifestPath $manifestPath
        [CodexRuntimeNative]::RenameByHandle(
            $temporaryManifestHandle,
            $manifestPath,
            $true
        )
    }
    finally {
        $temporaryManifestHandle.Dispose()
    }
    $temporaryManifest = $null
    if ($PruneOldRuntime) {
        Remove-OldRuntimes `
            -VersionsRoot $versionsRoot `
            -CurrentInterpreter $runtimeInterpreter `
            -KeepCount $Keep
    }
    Close-PathLocks -Locks $pathLocks
    [Console]::Error.WriteLine("${pluginName}: Python 3.12 runtime configured")
    exit 0
}
catch {
    if ($null -ne $stagingDirectory -and (Test-Path -LiteralPath $stagingDirectory)) {
        Remove-Item -LiteralPath $stagingDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $temporaryManifest -and (Test-Path -LiteralPath $temporaryManifest)) {
        Remove-Item -LiteralPath $temporaryManifest -Force -ErrorAction SilentlyContinue
    }
    Close-PathLocks -Locks $pathLocks
    if ($_.Exception -is [System.InvalidOperationException]) {
        Write-Failure -Message $_.Exception.Message
    }
    else {
        Write-Failure -Message "runtime setup failed"
    }
    exit 1
}
