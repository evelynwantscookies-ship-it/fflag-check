use crate::models::ScanReport;
use crate::reports::report_generator;
use crate::scanners;

/// Run all scanners and generate a signed scan report.
#[tauri::command]
pub async fn run_scan() -> Result<ScanReport, String> {
    let findings = scanners::run_all_scans().await;
    let report = report_generator::generate_report(findings);
    Ok(report)
}

/// Save a scan report to the user's desktop as a JSON file.
/// Returns the file path where the report was saved.
#[tauri::command]
pub async fn save_report(report: ScanReport) -> Result<String, String> {
    report_generator::save_report(&report)
}

/// Validate a report's HMAC signature from its JSON string.
#[tauri::command]
pub async fn validate_report(json: String) -> Result<bool, String> {
    report_generator::validate_report(&json)
}
