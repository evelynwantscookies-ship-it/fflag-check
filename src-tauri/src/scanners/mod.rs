pub mod process_scanner;
pub mod file_scanner;
pub mod client_settings_scanner;
pub mod prefetch_scanner;
pub mod memory_scanner;

use crate::models::ScanFinding;

/// Run all scanners and collect findings.
pub async fn run_all_scans() -> Vec<ScanFinding> {
    let mut all_findings = Vec::new();

    // Run all scanners concurrently
    let (process_results, file_results, client_results, prefetch_results, memory_results) =
        tokio::join!(
            process_scanner::scan(),
            file_scanner::scan(),
            client_settings_scanner::scan(),
            prefetch_scanner::scan(),
            memory_scanner::scan(),
        );

    all_findings.extend(process_results);
    all_findings.extend(file_results);
    all_findings.extend(client_results);
    all_findings.extend(prefetch_results);
    all_findings.extend(memory_results);

    all_findings
}
