export type ScanVerdict = "Clean" | "Suspicious" | "Flagged";

export interface ScanFinding {
  module: string;
  verdict: ScanVerdict;
  description: string;
  details: string | null;
  timestamp: string; // ISO 8601
}

export interface ScanReport {
  scan_id: string;
  timestamp: string;
  machine_id: string;
  os_info: string;
  overall_verdict: ScanVerdict;
  findings: ScanFinding[];
  hmac_signature: string;
}

// UI state types
export type ScanPhase =
  | "idle"
  | "scanning"
  | "complete"
  | "error";
