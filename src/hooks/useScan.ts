import { useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ScanPhase, ScanReport } from "../types";

interface UseScanReturn {
  phase: ScanPhase;
  report: ScanReport | null;
  error: string | null;
  startScan: () => Promise<void>;
  saveReport: () => Promise<string | null>;
}

export function useScan(): UseScanReturn {
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const startScan = useCallback(async () => {
    setPhase("scanning");
    setError(null);
    setReport(null);

    try {
      const result = await invoke<ScanReport>("run_scan");
      setReport(result);
      setPhase("complete");
    } catch (err) {
      const message =
        err instanceof Error ? err.message : String(err);
      setError(message);
      setPhase("error");
    }
  }, []);

  const saveReport = useCallback(async (): Promise<string | null> => {
    if (!report) return null;

    try {
      const path = await invoke<string>("save_report", { report });
      return path;
    } catch (err) {
      const message =
        err instanceof Error ? err.message : String(err);
      setError(message);
      return null;
    }
  }, [report]);

  return { phase, report, error, startScan, saveReport };
}
