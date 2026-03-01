use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Verdict indicating the severity of a scan finding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ScanVerdict {
    Clean,
    Suspicious,
    Flagged,
}

/// A single finding from a scanner module.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanFinding {
    /// Which scanner module produced this finding.
    pub module: String,
    /// The severity verdict.
    pub verdict: ScanVerdict,
    /// Human-readable description of what was found.
    pub description: String,
    /// Optional extra details (e.g., file path, memory address).
    pub details: Option<String>,
    /// When the finding was recorded.
    pub timestamp: DateTime<Utc>,
}

impl ScanFinding {
    pub fn new(
        module: impl Into<String>,
        verdict: ScanVerdict,
        description: impl Into<String>,
        details: Option<String>,
    ) -> Self {
        Self {
            module: module.into(),
            verdict,
            description: description.into(),
            details,
            timestamp: Utc::now(),
        }
    }
}
