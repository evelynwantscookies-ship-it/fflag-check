use sysinfo::System;

use crate::data::known_tools::{KNOWN_PROCESS_NAMES, KNOWN_TOOL_FILENAMES};
use crate::models::{ScanFinding, ScanVerdict};

/// Scan running processes for known cheat/injection tools.
pub async fn scan() -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    let mut sys = System::new_all();
    sys.refresh_all();

    // Check if Roblox is running (higher severity if so)
    let roblox_running = sys.processes().values().any(|p| {
        let name = p.name().to_string_lossy().to_lowercase();
        name.contains("roblox")
    });

    for (_pid, process) in sys.processes() {
        let proc_name = process.name().to_string_lossy().to_lowercase();
        let exe_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let exe_filename = process
            .exe()
            .and_then(|p| p.file_name())
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        // Check process name against known tool names (substring match)
        for &known_name in KNOWN_PROCESS_NAMES {
            if proc_name.contains(known_name) {
                let verdict = if roblox_running {
                    ScanVerdict::Flagged
                } else {
                    ScanVerdict::Suspicious
                };

                findings.push(ScanFinding::new(
                    "process_scanner",
                    verdict,
                    format!(
                        "Known tool process detected: \"{}\" (matched: \"{}\")",
                        process.name().to_string_lossy(),
                        known_name
                    ),
                    Some(format!("PID: {}, Path: {}", _pid, exe_path)),
                ));
                break; // Only report once per process
            }
        }

        // Check exe filename against known tool filenames (case-insensitive)
        if !exe_filename.is_empty() {
            for &known_file in KNOWN_TOOL_FILENAMES {
                if exe_filename.eq_ignore_ascii_case(known_file) {
                    let verdict = if roblox_running {
                        ScanVerdict::Flagged
                    } else {
                        ScanVerdict::Suspicious
                    };

                    findings.push(ScanFinding::new(
                        "process_scanner",
                        verdict,
                        format!(
                            "Known tool executable running: \"{}\"",
                            exe_filename
                        ),
                        Some(format!("PID: {}, Path: {}", _pid, exe_path)),
                    ));
                    break;
                }
            }
        }
    }

    if findings.is_empty() {
        findings.push(ScanFinding::new(
            "process_scanner",
            ScanVerdict::Clean,
            "No known cheat or injection tools detected in running processes",
            Some(format!("Scanned {} running processes", sys.processes().len())),
        ));
    }

    findings
}
