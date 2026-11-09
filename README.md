# RAM PowerShell Parser

Finds PowerShell commands in a Windows RAM dump, with a focus on reverse shells and other PowerShell abuse. Made for Minecraft screensharing, but it works on any raw memory dump.

PowerShell bypasses are fileless, so they often leave no exe, no Prefetch and no file on disk. The commands still sit in RAM though, and this tool digs them out.

## What it finds

Every string in the dump is checked, in both ASCII and UTF-16 (PowerShell stores most of its text as UTF-16, which a lot of string tools miss).

**Suspicious** (flagged and sorted to the top):

| Category | Examples |
| --- | --- |
| Reverse shell | `Net.Sockets.TCPClient`, `.GetStream()`, `$sendback`, powercat |
| Download + execute | `DownloadString`, `Net.WebClient`, `Invoke-WebRequest`, `certutil -urlcache` |
| Invoke / IEX | `Invoke-Expression`, `iex (...)`, `[ScriptBlock]::Create` |
| Encoded / hidden | `-enc <base64>`, `FromBase64String`, `-nop`, `-w hidden`, `-ep bypass` |
| In-memory loading | `[Reflection.Assembly]::Load`, `VirtualAlloc`, `Add-Type -TypeDefinition` |
| Defender tampering | `Add-MpPreference -ExclusionPath`, `DisableRealtimeMonitoring` |
| Anti-forensics | `fsutil usn deletejournal`, `wevtutil cl`, `vssadmin delete`, `Clear-History` |
| Services / tasks | `Stop-Service`, `sc stop`, `schtasks /create`, `Register-ScheduledTask` |

It also:
- **decodes** `-EncodedCommand` and `FromBase64String` payloads, and flags whatever is hidden inside them
- **pulls out IPs, ports and URLs** from suspicious strings (for a reverse shell, that's where it was connecting to)
- **lists every other PowerShell command** it found, most frequent first, with PowerShell's own module text filtered out

## How to use

1. Dump the RAM with [WinPmem](https://github.com/Velocidex/WinPmem/releases) (run as admin, needs free disk space about the size of the PC's RAM):
   ```
   winpmem_mini_x64.exe ram.raw
   ```
2. Run the parser on the dump. With the exe:
   ```
   RAMPSParser.exe -Path .\ram.raw
   ```
   Or with the script:
   ```
   powershell -ExecutionPolicy Bypass -File .\RAMPSParser.ps1 -Path .\ram.raw
   ```
3. Wait for the progress bar (roughly 10 to 20 minutes for a 16 GB dump). The report opens in Notepad when it's done.

### Output (in `C:\SSTools\RAMPS\`)

| File | What's in it |
| --- | --- |
| `report.txt` | Summary per category, IPs/URLs, then every suspicious string with its offset, count and decoded payload. Open this first. |
| `suspicious.csv` | Same hits as a table, for Timeline Explorer or Excel |
| `all_commands.txt` | Every PowerShell command found, most frequent first |

### Options

| Option | Default | What it does |
| --- | --- | --- |
| `-Path` | (required) | The RAM dump to parse |
| `-OutDir` | `C:\SSTools\RAMPS` | Where to save results |
| `-MinLength` | `8` | Shortest string to check |
| `-ChunkMB` | `64` | How much of the dump to read at a time |
| `-NoOpen` | off | Don't open the report when finished |

## Testing it

You can check it works without dumping a real PC:
```
.\tests\New-TestDump.ps1 -Path .\test.raw
.\RAMPSParser.ps1 -Path .\test.raw
```
You should get 4 suspicious hits (a reverse shell, an encoded download cradle, a Defender exclusion and a USN journal deletion) and 1 normal command. The same test runs automatically on every push before the exe gets built.

## Things to keep in mind

- **A raw dump has no process names**, so the tool can't tell which program a string came from. Treat hits as leads.
- **Antivirus engines keep malware signatures in RAM.** Windows Defender (MsMpEng) can make a reverse shell string show up even if nobody ran one. Back up hits with other evidence (PowerShell event 400/4104, PSReadLine history, Prefetch, timing) before banning.
- **Never upload RAM dumps.** They contain passwords, tokens and private data from the PC. The `.gitignore` blocks them from being committed.

## Building the exe

Every push to `main` runs the test and builds `RAMPSParser.exe` with [ps2exe](https://github.com/MScholtes/PS2EXE) through GitHub Actions. Download it from the **Actions** tab under Artifacts, or push a tag like `v1.0.0` to attach it to a release.

## License

MIT
