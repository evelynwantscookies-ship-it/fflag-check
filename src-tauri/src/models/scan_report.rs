use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::process::Command;

use super::scan_result::{ScanFinding, ScanVerdict};

type HmacSha256 = Hmac<Sha256>;

const HMAC_KEY: &[u8] = b"tsbcc-fflag-scanner-2025";

/// A full scan report containing all findings, machine identification, and an HMAC signature.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanReport {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub machine_id: String,
    pub os_info: String,
    pub overall_verdict: ScanVerdict,
    pub findings: Vec<ScanFinding>,
    pub hmac_signature: String,
}

impl ScanReport {
    /// Create a new empty report with machine_id and timestamp populated.
    pub fn new() -> Self {
        let scan_id = generate_scan_id();
        let machine_id = get_machine_id();
        let os_info = get_os_info();

        Self {
            scan_id,
            timestamp: Utc::now(),
            machine_id,
            os_info,
            overall_verdict: ScanVerdict::Clean,
            findings: Vec::new(),
            hmac_signature: String::new(),
        }
    }

    /// Add a finding to the report and update the overall verdict.
    pub fn add_finding(&mut self, finding: ScanFinding) {
        self.findings.push(finding);
        self.overall_verdict = self.compute_verdict();
    }

    /// Compute the overall verdict from all findings.
    /// If any Flagged -> Flagged, if any Suspicious -> Suspicious, else Clean.
    pub fn compute_verdict(&self) -> ScanVerdict {
        let mut has_suspicious = false;
        for f in &self.findings {
            match f.verdict {
                ScanVerdict::Flagged => return ScanVerdict::Flagged,
                ScanVerdict::Suspicious => has_suspicious = true,
                ScanVerdict::Clean => {}
            }
        }
        if has_suspicious {
            ScanVerdict::Suspicious
        } else {
            ScanVerdict::Clean
        }
    }

    /// Compute HMAC-SHA256 of the JSON content (excluding hmac_signature field)
    /// and set hmac_signature.
    pub fn sign(&mut self) {
        let content = self.signable_content();
        let mut mac =
            HmacSha256::new_from_slice(HMAC_KEY).expect("HMAC can take key of any size");
        mac.update(content.as_bytes());
        let result = mac.finalize();
        self.hmac_signature = hex::encode(result.into_bytes());
    }

    /// Verify the HMAC signature.
    pub fn verify(&self) -> bool {
        if self.hmac_signature.is_empty() {
            return false;
        }
        let content = self.signable_content();
        let mut mac =
            HmacSha256::new_from_slice(HMAC_KEY).expect("HMAC can take key of any size");
        mac.update(content.as_bytes());

        match hex::decode(&self.hmac_signature) {
            Ok(sig_bytes) => mac.verify_slice(&sig_bytes).is_ok(),
            Err(_) => false,
        }
    }

    /// Serialize the report to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Produce the JSON content used for signing (hmac_signature is set to empty string).
    fn signable_content(&self) -> String {
        let mut clone = self.clone();
        clone.hmac_signature = String::new();
        serde_json::to_string(&clone).unwrap_or_default()
    }
}

/// Generate a random hex scan ID (UUID-like).
fn generate_scan_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let s = RandomState::new();
    let mut hasher = s.build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    let a = hasher.finish();

    let s2 = RandomState::new();
    let mut hasher2 = s2.build_hasher();
    hasher2.write_u64(a);
    hasher2.write_usize(std::process::id() as usize);
    let b = hasher2.finish();

    format!("{:016x}{:016x}", a, b)
}

/// Get the machine ID, hashed with SHA256.
fn get_machine_id() -> String {
    use sha2::Digest;
    let raw = get_raw_machine_id();
    let hash = Sha256::digest(raw.as_bytes());
    hex::encode(hash)
}

/// Platform-specific raw machine ID retrieval.
#[cfg(target_os = "macos")]
fn get_raw_machine_id() -> String {
    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Parse the IOPlatformUUID from the output
            for line in stdout.lines() {
                if line.contains("IOPlatformUUID") {
                    // Format: "IOPlatformUUID" = "XXXXXXXX-XXXX-..."
                    if let Some(uuid_start) = line.rfind('"') {
                        let trimmed = &line[..uuid_start];
                        if let Some(uuid_begin) = trimmed.rfind('"') {
                            return trimmed[uuid_begin + 1..].to_string();
                        }
                    }
                }
            }
            "unknown-macos".to_string()
        }
        Err(_) => "unknown-macos".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn get_raw_machine_id() -> String {
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Parse the MachineGuid value from reg query output
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.contains("MachineGuid") {
                    // Format: MachineGuid    REG_SZ    <guid>
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if let Some(guid) = parts.last() {
                        return guid.to_string();
                    }
                }
            }
            "unknown-windows".to_string()
        }
        Err(_) => "unknown-windows".to_string(),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn get_raw_machine_id() -> String {
    "unknown-platform".to_string()
}

/// Get a human-readable OS info string.
fn get_os_info() -> String {
    let _info = sysinfo::System::new_all();
    let name = sysinfo::System::name().unwrap_or_else(|| "Unknown".to_string());
    let version = sysinfo::System::os_version().unwrap_or_else(|| "Unknown".to_string());
    let arch = {
        let a = sysinfo::System::cpu_arch();
        if a.is_empty() { "Unknown".to_string() } else { a }
    };
    format!("{} {} ({})", name, version, arch)
}
