$ErrorActionPreference = "Stop"

$packagedScript = [System.IO.Path]::GetFullPath(
    (Join-Path `
        $PSScriptRoot `
        "..\plugins\codex-control-plane-hooks\scripts\setup_runtime.ps1")
)

if (-not (Test-Path -LiteralPath $packagedScript -PathType Leaf)) {
    [Console]::Error.WriteLine(
        "codex-control-plane-hooks: packaged runtime setup script is missing"
    )
    exit 1
}

& $packagedScript @args
exit $LASTEXITCODE
