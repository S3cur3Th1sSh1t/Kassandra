# Kassandra

Original publication was [here](https://github.com/threathunters-io/kassandra_x33fcon_2026/tree/main/tool) but without any source code. So I asked my friend Claude to generate some source code for it so that people can better understand/analyse it.

Real-time Windows threat detection via ETW (Event Tracing for Windows). Monitors running processes for suspicious behavioral patterns — network tunneling, dynamic code injection, DLL ballooning, and service-port accumulation — and assigns severity levels based on tag combinations.

Single-file C implementation (~1600 LOC, ~160KB binary). No dependencies beyond the Windows SDK.

## Detection Tags

Each process accumulates tags as suspicious behaviors are observed:

| Tag | Description |
|-----|-------------|
| `net_public` | Process connected to a public IP address |
| `net_private` | Process connected to a private (RFC 1918) IP address |
| `net_tunnel` | Process has both public and private connections (tunneling indicator) |
| `dynamic_code` | Process allocated executable memory via VirtualAlloc outside known modules |
| `dynamic_code_nested` | Reflective DLL loading detected via call-stack analysis (requires StackWalk) |
| `sleep_tp_callback` | Thread pool callback resolves to a sleep/wait API (evasion technique) |
| `proxy_tp_callback` | Thread pool callback resolves to a proxy/injection API |
| `module_balloon` | Process loaded 6+ of 28 security-related DLLs (credential harvesting indicator) |
| `high_num_of_service_ports` | Process connected to 5+ common Windows service ports (lateral movement indicator) |

## Severity Levels

Tags are combined into severity levels using a two-phase algorithm:

- **NONE** — Single tags or non-suspicious combinations. No alert emitted.
- **INFO** — Two-tag pairs like `module_balloon + dynamic_code`. Logged to console only.
- **LOW** — Network + dynamic code pairs, or high service port combinations. Logged to console and file.
- **MEDIUM** — Four-tag combinations or TP callback escalation. Logged to console and file.
- **HIGH** — Maximum severity. TP callback + dynamic code + nested, or escalation from lower base levels. Logged to console and file.

## Monitored DLLs (Balloon Detection)

A process loading 6 or more of these DLLs triggers the `module_balloon` tag:

```
samcli.dll    dsrole.dll    logoncli.dll  activeds.dll
adsldpc.dll   wldap32.dll   srvcli.dll    dbghelp.dll
dbgcore.dll   vaultcli.dll  samlib.dll    dpapi.dll
cryptdll.dll  taskschd.dll  wtsapi32.dll  winsta.dll
wbemcomn.dll  wbemsvc.dll   fastprox.dll  kerberos.dll
msv1_0.dll    tspkg.dll     wdigest.dll   cloudap.dll
gpapi.dll     authz.dll     ntdsapi.dll   dsparse.dll
```

## Service Ports (Lateral Movement Detection)

Connections to 5+ of these ports trigger `high_num_of_service_ports`:

```
88 (Kerberos), 135 (RPC), 139 (NetBIOS), 389 (LDAP), 445 (SMB),
636 (LDAPS), 3268/3269 (Global Catalog), 3389 (RDP), 5985/5986 (WinRM)
```

## Usage

```
kassandra.exe [options]

Options:
  -v, --verbose       Show live telemetry banner (uptime, event counters)
  -o, --output FILE   Write LOW+ findings to FILE (default: kassandra_findings.log)
  -h, --help          Print help text
```

Requires **administrator privileges** (ETW kernel tracing needs `SeSystemProfilePrivilege`).

### Examples

```powershell
# Basic monitoring, findings logged to default file
.\kassandra.exe

# Verbose mode with custom log path
.\kassandra.exe -v -o C:\logs\kassandra_scan.log

# Quick scan — run for a few minutes, then Ctrl+C for summary
.\kassandra.exe -o findings.log
```

### Output

During operation, kassandra prints per-tag info messages and severity alerts:

```
[info] firefox.exe:7828 public network tag added
[info] firefox.exe:7828 Dynamic code tag added
[LOW] pid=7828 image=firefox.exe level=LOW tags=[net_public | dynamic_code]
```

On Ctrl+C, a sorted summary of all LOW+ findings is printed:

```
==================================================================
  KASSANDRA - FINDINGS SUMMARY  (3 processes flagged)
==================================================================
  LEVEL      PID      IMAGE                          TAGS
  ---------- -------- ------------------------------ -------------
  HIGH       1234     malware.exe                    net_public | dynamic_code | module_balloon
  LOW        7828     firefox.exe                    net_public | dynamic_code
  LOW        5544     svchost.exe                    net_public | net_private | net_tunnel
  ---------- -------- ------------------------------ -------------

  Findings logged to: kassandra_findings.log
```

The log file contains timestamped entries for all LOW+ alerts plus the final summary.

## Building

### Windows (MSVC)

Requires Visual Studio 2019+ or the Build Tools with the C++ workload.

```powershell
# From a Developer Command Prompt (or after running vcvarsall.bat x64):
cl /O2 /W3 kassandra.c /Fe:kassandra.exe /link advapi32.lib tdh.lib ws2_32.lib ntdll.lib ole32.lib

# If vcvarsall.bat is not in PATH:
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /O2 /W3 kassandra.c /Fe:kassandra.exe /link advapi32.lib tdh.lib ws2_32.lib ntdll.lib ole32.lib
```

### Windows (MinGW-w64)

```bash
x86_64-w64-mingw32-gcc -O2 -Wall kassandra.c -o kassandra.exe \
    -ladvapi32 -ltdh -lws2_32 -lntdll -lole32
```

### Cross-compile from Linux (MinGW-w64)

```bash
# Install the cross-compiler
sudo apt install gcc-mingw-w64-x86-64    # Debian/Ubuntu
sudo dnf install mingw64-gcc             # Fedora

# Build
x86_64-w64-mingw32-gcc -O2 -Wall kassandra.c -o kassandra.exe \
    -ladvapi32 -ltdh -lws2_32 -lntdll -lole32
```

> **Note**: kassandra is a Windows-only tool. It uses ETW, the Windows kernel trace infrastructure, and Win32 APIs (`CreateToolhelp32Snapshot`, `GetModuleHandle`, etc.) that have no Linux equivalent. Cross-compilation from Linux produces a Windows PE executable — it does not run natively on Linux.

## Architecture

```
                    ┌─────────────────────┐
                    │   NT Kernel Logger   │
                    │  (kernel ETW trace)  │
                    └────────┬────────────┘
                             │ Process, Thread, Image,
                             │ TcpIp, VirtualAlloc events
                             ▼
┌──────────┐        ┌─────────────────────┐        ┌──────────────┐
│ Toolhelp │───────▶│   Event Dispatcher  │───────▶│ Process Table│
│ Rundown  │ init   │                     │ update │  (hash map)  │
└──────────┘        └────────┬────────────┘        └──────┬───────┘
                             │                            │
                    ┌────────┴────────────┐        ┌──────┴───────┐
                    │  User-mode Session  │        │ Tag + Level  │
                    │ (Kernel-Process,    │        │  Evaluation  │
                    │  TCPIP providers)   │        └──────┬───────┘
                    └─────────────────────┘               │
                                                   ┌──────┴───────┐
                                                   │Console + File│
                                                   │   Output     │
                                                   └──────────────┘
```

**Startup**: Toolhelp32 snapshot enumerates existing processes and their loaded modules. Tags are computed but alerts are suppressed during this baseline phase.

**Runtime**: Three ETW event streams feed into the process table — kernel trace (process/thread/image/network/virtualalloc), user-mode Kernel-Process provider, and user-mode TCPIP provider. Each event may add tags; when a process's severity level increases, an alert is emitted.

**Shutdown**: All processes with severity LOW or above are collected, sorted by risk (highest first), and printed as a summary table. The same summary is written to the log file.

## Files

| File | Description |
|------|-------------|
| `kassandra.c` | Complete source (~1600 LOC) |
| `kassandra.exe` | Compiled binary |
| `kassandra_findings.log` | Default output log (created at runtime) |
