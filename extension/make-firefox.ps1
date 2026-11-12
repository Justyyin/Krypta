# Builds the Firefox variant of the extension into artifacts/extension-firefox.
# Load it in Firefox through about:debugging -> This Firefox -> Load Temporary Add-on.
$source = $PSScriptRoot
$target = Join-Path (Split-Path $source -Parent) "artifacts/extension-firefox"
Remove-Item $target -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item $source $target -Recurse
Move-Item (Join-Path $target "manifest.firefox.json") (Join-Path $target "manifest.json") -Force
Remove-Item (Join-Path $target "make-firefox.ps1")
Write-Host "Firefox extension written to $target"
