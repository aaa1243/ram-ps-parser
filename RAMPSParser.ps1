<#
    RAMPSParser.ps1
    ---------------
    Parses a full RAM dump (e.g. ram.raw from WinPmem) and pulls out
    PowerShell commands, with a focus on reverse shells and other abuse.

    How it works
      - Streams the dump in chunks (works on 8-32 GB dumps without loading it all).
      - Extracts every ASCII and UTF-16 string (PowerShell keeps most text as UTF-16).
      - Sorts PowerShell-looking strings into:
          suspicious  -> reverse shell, download + execute, IEX, encoded/hidden,
                         in-memory loading, Defender tampering, anti-forensics, tasks
          commands    -> every other PowerShell command it found (cmdlets, powershell.exe
                         command lines, [Class]::Method calls), counted and deduplicated
      - Decodes -EncodedCommand / FromBase64String payloads.
      - Lists IPs, ports and URLs found inside suspicious strings.

    Usage (CMD or PowerShell; admin is only needed for WinPmem, not for parsing):
        winpmem_mini_x64.exe ram.raw
        powershell -ExecutionPolicy Bypass -File .\RAMPSParser.ps1 -Path .\ram.raw

    Output folder: C:\SSTools\RAMPS\  (Cleanup in SS Tools Downloader deletes it)
      report.txt         readable summary (open this first)
      suspicious.csv     every flagged string with offset, count and categories
      all_commands.txt   every PowerShell command found, most frequent first

    A RAM dump has no process names, so treat hits as leads. Antivirus engines
    (MsMpEng) keep malware signatures in memory, which can look like reverse
    shells. Check timing and link hits to other traces before banning.
#>
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$OutDir = 'C:\SSTools\RAMPS',
    [int]$MinLength = 8,
    [int]$ChunkMB = 64,
    [int]$ChunkBytes = 0,           # testing only: overrides ChunkMB
    [switch]$NoOpen                 # don't open the report in Notepad when done
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Path)) { Write-Host "File not found: $Path" -ForegroundColor Red; return }
$Path = (Resolve-Path -LiteralPath $Path).Path

# =============================================================================
#  PATTERNS
# =============================================================================
# Suspicious categories (any match goes to the suspicious list)
$Indicators = [ordered]@{
    'Reverse shell'      = 'Net\.Sockets\.TCPClient|Net\.Sockets\.TcpListener|Net\.Sockets\.UDPClient|\.GetStream\(\)|\$sendback|\$sendbyte|\(pwd\)\.Path\s*\+|New-Object\s+IO\.StreamReader|Invoke-PowerShellTcp|powercat|nc(\.exe)?\s+-e\s'
    'Download + execute' = 'DownloadString|DownloadFile|DownloadData|Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod|\biwr\s+-?\S*http|\birm\s+-?\S*http|Start-BitsTransfer|bitsadmin\s+/transfer|certutil.+-urlcache'
    'Invoke / IEX'       = 'Invoke-Expression|\biex\s*[\(\$\x27"]|\|\s*iex\b|\[ScriptBlock\]::Create|\.InvokeScript\('
    'Encoded / hidden'   = 'FromBase64String|\s-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/]{20,}={0,2}|\s-nop\b|\s-noni\b|-w(indowstyle)?\s+hidden|-ep\s+bypass|-ExecutionPolicy\s+Bypass'
    'In-memory loading'  = '\[Reflection\.Assembly\]::Load|Assembly\]::Load\(|VirtualAlloc|CreateThread|WriteProcessMemory|Add-Type\s+-TypeDefinition|Invoke-ReflectivePEInjection|Invoke-Shellcode'
    'Defender tampering' = 'Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|-ExclusionPath|-ExclusionProcess'
    'Anti-forensics'     = 'fsutil\s+usn\s+deletejournal|wevtutil\s+cl|Clear-EventLog|Remove-EventLog|vssadmin\s+delete|Remove-Item.+Prefetch|reg\s+delete|Clear-History|ConsoleHost_history|Set-PSReadLineOption.+HistorySaveStyle'
    'Services / tasks'   = 'Stop-Service|Set-Service.+Disabled|sc(\.exe)?\s+(stop|config)|schtasks\s+/create|Register-ScheduledTask|New-ScheduledTask'
}
$SusPattern = ($Indicators.Values | ForEach-Object { "(?:$_)" }) -join '|'

# What counts as "a PowerShell command"
$CmdPattern = '\b(?:powershell(?:_ise)?(?:\.exe)?|pwsh(?:\.exe)?)\s+[-/]|' +
              '\b(?:Get|Set|New|Remove|Invoke|Start|Stop|Add|Clear|Import|Export|Out|Write|Register|Unregister|Enable|Disable|Test|ConvertTo|ConvertFrom|Select|Where|ForEach|Copy|Move|Rename|Restart|Resolve|Expand|Compress|Mount|Dismount|Format|Update|Install|Uninstall|Join|Split|Measure|Sort|Group|Wait|Receive|Send|Enter|Exit|Push|Pop|Read)-[A-Z][A-Za-z]{2,}\b|' +
              '\biex\b|\[(?:System\.)?[A-Za-z]+(?:\.[A-Za-z]+)*\]::[A-Za-z]+\('

# Noise in the "all commands" list (PowerShell's own module source, help text, XML)
$NoisePattern = 'ExternalHelp|HelpUri|HelpMessage|\[Parameter\(|ValueFromPipeline|CmdletBinding|\.psd1|\.psm1|<maml:|<command:|<dev:|xmlns|\.SYNOPSIS|\.DESCRIPTION|\.EXAMPLE|^\s*#'

function Get-Categories([string]$Text) {
    $cats = @()
    foreach ($k in $Indicators.Keys) { if ($Text -match "(?i)$($Indicators[$k])") { $cats += $k } }
    return ($cats -join ', ')
}

function Get-DecodedBlobs([string]$Text) {
    $out = @()
    foreach ($p in @('\s-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/]{20,}={0,2})', 'FromBase64String\(\s*[\x27"]([A-Za-z0-9+/]{20,}={0,2})')) {
        foreach ($m in [regex]::Matches($Text, $p, 'IgnoreCase')) {
            try {
                $bytes = [Convert]::FromBase64String($m.Groups[1].Value)
                $txt = [Text.Encoding]::Unicode.GetString($bytes)
                if ($txt -notmatch '^[\x09\x0A\x0D\x20-\x7E]+$') { $txt = [Text.Encoding]::UTF8.GetString($bytes) }
                if ($txt -match '[\x20-\x7E]{6,}') { $out += ($txt -replace '\s+', ' ').Trim() }
            } catch { }
        }
    }
    return $out
}

# =============================================================================
#  STREAMING STRING EXTRACTOR  (C#)
# =============================================================================
if (-not ('RamPS.Scanner' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace RamPS {
    public class Hit {
        public string Text;
        public long Offset;
        public int Count;
        public bool Wide;
    }

    public class Scanner {
        Regex sus, cmd, noise;
        int minLen;
        const int MaxLen = 4096;
        public int MaxCommands = 300000;
        public int MaxSuspicious = 50000;
        public Dictionary<string, Hit> Suspicious = new Dictionary<string, Hit>();
        public Dictionary<string, Hit> Commands = new Dictionary<string, Hit>();
        public long StringsSeen;

        StringBuilder a = new StringBuilder();
        long aStart;
        StringBuilder[] w = new StringBuilder[] { new StringBuilder(), new StringBuilder() };
        long[] wStart = new long[2];
        int pendingLow = -1;      // last byte of the previous chunk (low byte of a UTF-16 pair)
        long pendingAbs;

        public Scanner(string susPattern, string cmdPattern, string noisePattern, int minLength) {
            var o = RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant;
            sus = new Regex(susPattern, o);
            cmd = new Regex(cmdPattern, o);
            noise = new Regex(noisePattern, o);
            minLen = minLength;
        }

        static bool P(int c) { return (c >= 0x20 && c <= 0x7E) || c == 0x09; }

        public void Feed(byte[] buf, int len, long baseOff) {
            // ASCII strings
            for (int i = 0; i < len; i++) {
                byte b = buf[i];
                if (P(b)) {
                    if (a.Length == 0) aStart = baseOff + i;
                    if (a.Length < MaxLen) a.Append((char)b);
                } else Flush(a, aStart, false);
            }
            // UTF-16LE strings, both byte alignments
            if (pendingLow >= 0 && len > 0) { Pair(pendingLow, buf[0], pendingAbs); pendingLow = -1; }
            for (int i = 0; i < len; i++) {
                if (i + 1 < len) Pair(buf[i], buf[i + 1], baseOff + i);
                else { pendingLow = buf[i]; pendingAbs = baseOff + i; }
            }
        }

        void Pair(int lo, int hi, long abs) {
            int al = (int)(abs & 1);
            StringBuilder sb = w[al];
            if (hi == 0 && P(lo)) {
                if (sb.Length == 0) wStart[al] = abs;
                if (sb.Length < MaxLen) sb.Append((char)lo);
            } else Flush(sb, wStart[al], true);
        }

        public void Finish() {
            Flush(a, aStart, false);
            Flush(w[0], wStart[0], true);
            Flush(w[1], wStart[1], true);
        }

        void Flush(StringBuilder sb, long start, bool wide) {
            if (sb.Length >= minLen) {
                StringsSeen++;
                string s = sb.ToString();
                // cheap pre-filter before running the regexes
                if (s.IndexOf('-') >= 0 || s.IndexOf('/') >= 0 || s.IndexOf("::", StringComparison.Ordinal) >= 0 || s.IndexOf('$') >= 0 ||
                    s.IndexOf("iex", StringComparison.OrdinalIgnoreCase) >= 0) {
                    if (sus.IsMatch(s)) { if (Suspicious.Count < MaxSuspicious || Suspicious.ContainsKey(s.Trim())) Add(Suspicious, s, start, wide); }
                    else if (cmd.IsMatch(s) && !noise.IsMatch(s)) { if (Commands.Count < MaxCommands || Commands.ContainsKey(s.Trim())) Add(Commands, s, start, wide); }
                }
            }
            sb.Length = 0;
        }

        static void Add(Dictionary<string, Hit> d, string s, long off, bool wide) {
            string key = s.Trim();
            Hit h;
            if (d.TryGetValue(key, out h)) { h.Count++; return; }
            h = new Hit();
            h.Text = key; h.Offset = off; h.Count = 1; h.Wide = wide;
            d[key] = h;
        }
    }
}
"@
}

# =============================================================================
#  SCAN
# =============================================================================
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$scanner = New-Object RamPS.Scanner($SusPattern, $CmdPattern, $NoisePattern, $MinLength)

$chunk = $ChunkMB * 1MB
if ($ChunkBytes -gt 0) { $chunk = $ChunkBytes }
if ($chunk % 2) { $chunk++ }

$fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
$total = $fs.Length
$buf = New-Object byte[] $chunk
$pos = [long]0
$sw = [Diagnostics.Stopwatch]::StartNew()
Write-Host ("Parsing {0} ({1:N1} GB)..." -f $Path, ($total / 1GB)) -ForegroundColor Cyan
try {
    while ($true) {
        $read = $fs.Read($buf, 0, $chunk)
        if ($read -le 0) { break }
        $scanner.Feed($buf, $read, $pos)
        $pos += $read
        if ($total -gt 0) {
            $pct = [int](100 * $pos / $total)
            $eta = ''
            if ($pos -gt 0) { $eta = ' , ~{0:N0}s left' -f (($sw.Elapsed.TotalSeconds / $pos) * ($total - $pos)) }
            Write-Progress -Activity 'Parsing RAM dump' -Status ("{0}%  suspicious: {1}  commands: {2}{3}" -f $pct, $scanner.Suspicious.Count, $scanner.Commands.Count, $eta) -PercentComplete $pct
        }
    }
    $scanner.Finish()
}
finally { $fs.Close() }
Write-Progress -Activity 'Parsing RAM dump' -Completed

# =============================================================================
#  REPORTS
# =============================================================================
$report  = Join-Path $OutDir 'report.txt'
$susCsv  = Join-Path $OutDir 'suspicious.csv'
$allTxt  = Join-Path $OutDir 'all_commands.txt'
$lines   = New-Object System.Collections.ArrayList
function Add-Line([string]$s) { [void]$lines.Add($s) }

$susHits = @($scanner.Suspicious.Values | ForEach-Object {
        $decoded = @(Get-DecodedBlobs $_.Text)
        # Categories from the string itself plus anything hidden in a decoded payload
        $cats = @((Get-Categories $_.Text) -split ', ')
        foreach ($d in $decoded) { $cats += ((Get-Categories $d) -split ', ') }
        $cats = @($cats | Where-Object { $_ } | Select-Object -Unique)
        [pscustomobject]@{
            Offset     = ('0x{0:X}' -f $_.Offset)
            Count      = $_.Count
            Encoding   = $(if ($_.Wide) { 'UTF-16' } else { 'ASCII' })
            Categories = ($cats -join ', ')
            Text       = $_.Text
            Decoded    = ($decoded -join ' || ')
        }
    })
# Most categories first, then most repeated
$susHits = @($susHits | Sort-Object @{ Expression = { ($_.Categories -split ',').Count }; Descending = $true }, @{ Expression = 'Count'; Descending = $true })

Add-Line "RAM PowerShell parser report   $(Get-Date)"
Add-Line ("Dump: {0}  ({1:N1} GB, parsed in {2:N0}s, {3:N0} strings checked)" -f $Path, ($total / 1GB), $sw.Elapsed.TotalSeconds, $scanner.StringsSeen)
Add-Line ("Suspicious strings: {0}    Other PowerShell commands: {1}" -f $susHits.Count, $scanner.Commands.Count)
Add-Line 'No process names in a raw dump: hits are leads. AV engines keep malware signatures in RAM, so confirm with other traces.'
Add-Line ('=' * 100)

# Summary per category
Add-Line ''
Add-Line '### SUMMARY BY CATEGORY'
foreach ($k in $Indicators.Keys) {
    $n = @($susHits | Where-Object { $_.Categories -like "*$k*" }).Count
    Add-Line ("   {0,-20} {1}" -f $k, $n)
}

# Network indicators inside suspicious strings
$ips = @{}; $urls = @{}
foreach ($h in $susHits) {
    $hay = $h.Text + ' ' + $h.Decoded
    foreach ($m in [regex]::Matches($hay, '\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?:[\x27"]?\s*[,:]\s*(\d{2,5}))?')) {
        $ip = $m.Groups[1].Value
        if ($m.Groups[2].Success) { $ip += ':' + $m.Groups[2].Value }
        $ips[$ip] = $true
    }
    foreach ($m in [regex]::Matches($hay, 'https?://[^\s\x27"<>)\]]+')) { $urls[$m.Value] = $true }
}
Add-Line ''
Add-Line '### IPs / PORTS IN SUSPICIOUS STRINGS'
if ($ips.Count) { foreach ($k in ($ips.Keys | Sort-Object)) { Add-Line "   $k" } } else { Add-Line '   none' }
Add-Line ''
Add-Line '### URLs IN SUSPICIOUS STRINGS'
if ($urls.Count) { foreach ($k in ($urls.Keys | Sort-Object | Select-Object -First 200)) { Add-Line "   $k" } } else { Add-Line '   none' }

# Suspicious strings
Add-Line ''
Add-Line '### SUSPICIOUS STRINGS (most categories first)'
foreach ($h in ($susHits | Select-Object -First 1500)) {
    $t = $h.Text -replace '\s+', ' '
    if ($t.Length -gt 700) { $t = $t.Substring(0, 700) + ' ...' }
    Add-Line ''
    Add-Line ("[{0}]  offset {1}  x{2}  {3}" -f $h.Categories, $h.Offset, $h.Count, $h.Encoding)
    Add-Line ("   {0}" -f $t)
    if ($h.Decoded) { foreach ($d in ($h.Decoded -split ' \|\| ')) { Add-Line ("   decoded: {0}" -f $d) } }
}
if ($susHits.Count -gt 1500) { Add-Line ''; Add-Line ("... {0} more in suspicious.csv" -f ($susHits.Count - 1500)) }

$lines | Set-Content -LiteralPath $report -Encoding UTF8
$susHits | Export-Csv -LiteralPath $susCsv -NoTypeInformation -Encoding UTF8

# All PowerShell commands, most frequent first
$scanner.Commands.Values | Sort-Object Count -Descending | ForEach-Object {
    '{0,6}x  0x{1:X}  {2}' -f $_.Count, $_.Offset, ($_.Text -replace '\s+', ' ')
} | Set-Content -LiteralPath $allTxt -Encoding UTF8

Write-Host ''
Write-Host ("Done in {0:N0}s. Suspicious: {1}  Commands: {2}" -f $sw.Elapsed.TotalSeconds, $susHits.Count, $scanner.Commands.Count) -ForegroundColor Green
Write-Host "Report:      $report"
Write-Host "CSV:         $susCsv"
Write-Host "All cmds:    $allTxt"
if (-not $NoOpen -and $env:OS -eq 'Windows_NT') { Start-Process notepad.exe -ArgumentList "`"$report`"" }
