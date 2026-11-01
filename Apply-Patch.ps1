param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference='Stop'
function Hash([byte[]]$Bytes) {
 $sha=[Security.Cryptography.SHA256]::Create()
 try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally {$sha.Dispose()}
}
function Contained([string]$Root,[string]$Relative) {
 $base=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
 $full=[IO.Path]::GetFullPath([IO.Path]::Combine($base,$Relative))
 if(-not $full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)){throw 'Invalid manifest path'}
 return $full
}
$Source=(Resolve-Path -LiteralPath $Source).Path
$Destination=[IO.Path]::GetFullPath($Destination).TrimEnd('\')
if(Test-Path -LiteralPath $Destination){throw 'Destination must not exist. Existing files are preserved.'}
if($Destination.StartsWith($Source.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Choose an output folder outside the source installation.'}
if(-not (Test-Path -LiteralPath (Split-Path $Destination -Parent) -PathType Container)){throw 'Destination parent must exist.'}
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'patch-manifest.json') -Raw | ConvertFrom-Json
if($manifest.format -ne 1){throw 'Unsupported manifest'}
$results=@{}
foreach($file in $manifest.files){
 $bytes=[IO.File]::ReadAllBytes((Contained $Source $file.path))
 if($bytes.Length -ne $file.original_size -or (Hash $bytes) -ne $file.original_sha256){throw "Unsupported or already patched file: $($file.path). Supply the exact supported baseline."}
 if($file.result_size -lt $bytes.Length -or $file.result_size -gt 16777216){throw 'Invalid result size'}
 $patched=New-Object byte[] ([int]$file.result_size)
 [Array]::Copy($bytes,$patched,$bytes.Length)
 foreach($change in $file.changes){
  $replacement=[Convert]::FromBase64String($change.bytes)
  $offset=[long]$change.offset
  if($offset -lt 0 -or $offset+$replacement.Length -gt $patched.Length){throw 'Invalid patch range'}
  [Array]::Copy($replacement,0,$patched,$offset,$replacement.Length)
 }
 if((Hash $patched) -ne $file.result_sha256){throw 'Result hash mismatch. No output created.'}
 $results[$file.path]=$patched
}
foreach($file in $manifest.payload){
 $bytes=[IO.File]::ReadAllBytes((Contained (Join-Path $PSScriptRoot 'payload') $file.path))
 if((Hash $bytes) -ne $file.sha256){throw "Missing or damaged payload: $($file.path)"}
 if($results.ContainsKey($file.path)){throw 'Duplicate manifest output'}
 $results[$file.path]=$bytes
}
# All hashes pass before creating output. Partial output is retained on I/O failure.
$stage=$Destination+'.building-'+[Guid]::NewGuid().ToString('N')
[IO.Directory]::CreateDirectory($stage)|Out-Null
foreach($name in $results.Keys){
 $target=Contained $stage $name
 [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))|Out-Null
 [IO.File]::WriteAllBytes($target,$results[$name])
 if((Hash ([IO.File]::ReadAllBytes($target))) -ne (Hash $results[$name])){throw "Output verification failed. Partial output retained at $stage"}
}
[IO.Directory]::Move($stage,$Destination)
Write-Host "Verified patch files created at $Destination. Source installation unchanged."
Write-Host 'Close the game and back up the matching installed files before copying these files into the game folder.'
