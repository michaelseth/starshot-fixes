param([string]$Compiler='clang')
$ErrorActionPreference='Stop'
$build=Join-Path $PSScriptRoot 'build'
New-Item -ItemType Directory -Path $build -Force|Out-Null
& $Compiler --target=i686-w64-mingw32 -shared -O2 (Join-Path $PSScriptRoot 'source/starshot_camera.c') -o (Join-Path $build 'StarshotCamera.dll') -luser32
if($LASTEXITCODE -ne 0){throw 'Helper build failed'}
& $Compiler --target=i686-w64-mingw32 -O2 (Join-Path $PSScriptRoot 'source/test-starshot-camera.c') -o (Join-Path $build 'camera-tests.exe') -luser32
if($LASTEXITCODE -ne 0){throw 'Test build failed'}
& (Join-Path $build 'camera-tests.exe') (Join-Path $build 'StarshotCamera.dll')
if($LASTEXITCODE -ne 0){throw 'Helper tests failed'}
Write-Host "Built helper and passed input tests in $build"
