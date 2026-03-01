# TSBCC FFlag Scanner

A cross-platform desktop tool for detecting FFlag abuse in competitive Roblox tournaments. Built with Rust + Tauri and React + TypeScript.

Tournament players run this scanner before matches. Staff review the generated report to verify the player's system is clean — similar to how Echo works for Minecraft screenshares, but purpose-built for Roblox FFlag detection.

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS-lightgrey)
![Built with](https://img.shields.io/badge/built%20with-Tauri%20v2-orange)

---

## Why this exists

Roblox's September 2025 FFlag allowlist blocks file-based FFlag modifications, but players bypass it using memory injectors and offset-based tools that write FFlag values directly into Roblox's `.data` segment at runtime. Modified Fast Flags remain the single largest integrity threat to competitive Roblox — desync, physics manipulation, visual exploits, and animation hiding all stem from FFlag abuse.

The Strongest Battlegrounds currently lacks any visible anti-cheat system, and no dedicated FFlag scanner exists in the Roblox competitive ecosystem. This tool fills that gap.

---

## What it scans

### Process Scanner
Enumerates all running processes and flags known cheat/injection tools — Voidstrap, CheatEngine, x64dbg, ProcessHacker, ReClass, HxD, Extreme Injector, and 25+ others. If Roblox is running alongside a flagged tool, severity is elevated.

### File Scanner
Searches the filesystem for tool artifacts in common locations (Downloads, Desktop, AppData, Application Support). Detects known tool directories and executables by name, including FFlagToolkit, AppleBlox, Fishstrap, and Bloxstrap variants.

### Client Settings Scanner
Parses Roblox's `ClientAppSettings.json` and bootstrapper configs:
- **Windows**: Checks `%LocalAppData%\Roblox\Versions\*\ClientSettings\` plus Bloxstrap/Voidstrap/Fishstrap modification directories
- **macOS**: Checks `~/Library/Roblox/ClientSettings/` plus AppleBlox configs and profiles

Every detected FFlag is classified against three databases:
- **Allowlist** (17 officially permitted flags) — skipped as clean
- **Critical flags** (desync, physics manipulation) — flagged immediately
- **Suspicious flags** (visual advantages, FPS unlock, animation LOD) — reported as suspicious
- **Unknown non-allowlisted flags** — reported for staff review

### Prefetch Scanner (Windows)
Reads `C:\Windows\Prefetch\*.pf` to detect execution history of known tools — catches players who uninstall tools before running the scanner.

### Memory Scanner
Reads Roblox's process memory to detect runtime FFlag injections that bypass the file-based allowlist entirely:
- **Windows**: Uses `ReadProcessMemory` / `VirtualQueryEx` to scan committed memory regions
- **macOS**: Uses `mach_vm_read` / `mach_vm_region` via Mach kernel APIs

Searches up to 4GB of readable memory for known suspicious FFlag strings. This is the only way to detect active memory-injected FFlag modifications.

---

## Report system

Each scan generates a tamper-resistant JSON report:
- **HMAC-SHA256 signed** — players can't edit results
- **Machine ID** — SHA256-hashed hardware identifier prevents report sharing
- **Timestamped** — prevents re-using old clean reports
- **Three-tier verdict**: `CLEAN` / `SUSPICIOUS` / `FLAGGED`

Reports are saved to the desktop as `FlagCheck_Report_{timestamp}.json`.

---

## Building from source

### Prerequisites
- [Rust](https://rustup.rs/) (1.70+)
- [Node.js](https://nodejs.org/) (18+)
- Platform-specific Tauri dependencies: [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)

### Development
```bash
npm install
npm run tauri dev
```

### Production build
```bash
npm run tauri build
```

**macOS output:**
```
src-tauri/target/release/bundle/macos/TSBCC FFlag Scanner.app
src-tauri/target/release/bundle/dmg/TSBCC FFlag Scanner_0.1.0_aarch64.dmg
```

**Windows output:**
```
src-tauri/target/release/bundle/msi/TSBCC FFlag Scanner_0.1.0_x64.msi
src-tauri/target/release/bundle/nsis/TSBCC FFlag Scanner_0.1.0_x64-setup.exe
```

---

## Project structure

```
fflag-check/
├── src/                          # React + TypeScript frontend
│   ├── App.tsx                   # Main app layout
│   ├── App.css                   # Dark theme styles
│   ├── components/
│   │   ├── ScanButton.tsx        # Scan trigger button
│   │   ├── ScanProgress.tsx      # Animated progress indicator
│   │   ├── ResultsPanel.tsx      # Scan results display
│   │   └── ReportView.tsx        # Report metadata & export
│   ├── hooks/
│   │   └── useScan.ts            # Scan lifecycle hook
│   └── types/
│       └── index.ts              # TypeScript type definitions
├── src-tauri/                    # Rust backend
│   ├── src/
│   │   ├── lib.rs                # Tauri app entry point
│   │   ├── commands.rs           # Tauri command handlers
│   │   ├── models/
│   │   │   ├── scan_result.rs    # ScanVerdict, ScanFinding
│   │   │   └── scan_report.rs    # ScanReport with HMAC signing
│   │   ├── scanners/
│   │   │   ├── process_scanner.rs
│   │   │   ├── file_scanner.rs
│   │   │   ├── client_settings_scanner.rs
│   │   │   ├── prefetch_scanner.rs
│   │   │   └── memory_scanner.rs
│   │   ├── reports/
│   │   │   └── report_generator.rs
│   │   └── data/
│   │       ├── known_tools.rs    # 30+ known tool signatures
│   │       ├── flag_allowlist.rs # 17 official Roblox allowed flags
│   │       └── suspicious_flags.rs
│   └── Cargo.toml
├── package.json
└── vite.config.ts
```

---

## Known limitations

- **Memory-only FFlag changes are invisible** if the injection tool is closed before scanning — no file or process artifacts remain. The memory scanner catches active injections but not historical ones.
- **Memory scanner requires elevated privileges** on macOS (`task_for_pid` needs root or SIP disabled) and may trigger Hyperion on Windows.
- **Players can use VMs or alt machines** to bypass PC scanning entirely.
- **Tool signature lists require ongoing maintenance** as new bypass tools emerge.
- **The HMAC key is embedded in the binary** — a determined reverse engineer can extract it. For tournament-level use this is acceptable; higher security would need server-side verification.

These are the same fundamental limitations Echo faces. The tool raises the bar significantly for casual cheaters while acknowledging that truly determined actors require additional measures (manual screenshare, server-side detection, etc.).

---

## License

MIT
