import { useState } from "react";
import type { ScanReport } from "../types";

interface ReportViewProps {
  report: ScanReport;
  onSave: () => Promise<string | null>;
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + "\u2026";
}

function formatTimestamp(iso: string): string {
  try {
    const date = new Date(iso);
    return date.toLocaleString();
  } catch {
    return iso;
  }
}

function ReportView({ report, onSave }: ReportViewProps) {
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      const path = await onSave();
      if (path) {
        setSavedPath(path);
      }
    } finally {
      setSaving(false);
    }
  };

  const handleCopy = async () => {
    try {
      const json = JSON.stringify(report, null, 2);
      await navigator.clipboard.writeText(json);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may fail in some contexts; silently ignore.
    }
  };

  return (
    <div className="report-view">
      <h2 className="report-view__title">Report Details</h2>

      <div className="report-view__meta">
        <div className="report-view__field">
          <span className="report-view__label">Scan ID</span>
          <span className="report-view__value">{report.scan_id}</span>
        </div>
        <div className="report-view__field">
          <span className="report-view__label">Timestamp</span>
          <span className="report-view__value">
            {formatTimestamp(report.timestamp)}
          </span>
        </div>
        <div className="report-view__field">
          <span className="report-view__label">Machine ID</span>
          <span className="report-view__value">
            {truncate(report.machine_id, 16)}
          </span>
        </div>
        <div className="report-view__field">
          <span className="report-view__label">OS</span>
          <span className="report-view__value">{report.os_info}</span>
        </div>
      </div>

      <div className="report-view__actions">
        <button
          className="report-view__btn report-view__btn--save"
          onClick={handleSave}
          disabled={saving}
          type="button"
        >
          {saving ? "Saving\u2026" : "Save Report"}
        </button>

        <button
          className="report-view__btn report-view__btn--copy"
          onClick={handleCopy}
          type="button"
        >
          {copied ? "Copied!" : "Copy to Clipboard"}
        </button>
      </div>

      {savedPath && (
        <div className="report-view__saved">
          Saved to: <code>{savedPath}</code>
        </div>
      )}
    </div>
  );
}

export default ReportView;
