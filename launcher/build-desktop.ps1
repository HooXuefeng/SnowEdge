$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$sdk = Join-Path $PSScriptRoot 'webview2/sdk'
Copy-Item -LiteralPath (Join-Path $sdk 'lib/net462/Microsoft.Web.WebView2.Core.dll') -Destination $projectRoot
Copy-Item -LiteralPath (Join-Path $sdk 'lib/net462/Microsoft.Web.WebView2.WinForms.dll') -Destination $projectRoot
Copy-Item -LiteralPath (Join-Path $sdk 'runtimes/win-x64/native/WebView2Loader.dll') -Destination $projectRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$sourceFile = Join-Path $PSScriptRoot 'Desktop.cs'
$outputFile = Join-Path $projectRoot 'SnowEdge.exe'
$coreLibrary = Join-Path $projectRoot 'Microsoft.Web.WebView2.Core.dll'
$formsLibrary = Join-Path $projectRoot 'Microsoft.Web.WebView2.WinForms.dll'
$appIcon = Join-Path $projectRoot 'app/static/brand/snowedge.ico'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ "/win32icon:$appIcon" "/out:$outputFile" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Net.Http.dll "/reference:$coreLibrary" "/reference:$formsLibrary" $sourceFile
if ($LASTEXITCODE -ne 0) { throw 'Desktop compilation failed' }
