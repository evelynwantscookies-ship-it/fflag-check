import { useState } from "react";
import type { ScanReport, ScanFinding, ScanVerdict } from "../types";

interface ResultsPanelProps {
  report: ScanReport;
}

function verdictClass(verdict: ScanVerdict): string {
  switch (verdict) {
    case "Clean":
      return "verdict--clean";
    case "Suspicious":
      return "verdict--suspicious";
    case "Flagged":
      return "verdict--flagged";
  }
}

function verdictLabel(verdict: ScanVerdict): string {
  return verdict.toUpperCase();
}

function formatTimestamp(iso: string): string {
  try {
    const date = new Date(iso);
    return date.toLocaleString();
  } catch {
    return iso;
  }
}

const MODULE_DISPLAY_NAMES: Record<string, string> = {
  process_scanner: "Process Scanner",
  file_scanner: "File Scanner",
  client_settings_scanner: "Client Settings Scanner",
  prefetch_scanner: "Prefetch Scanner",
  memory_scanner: "Memory Scanner",
};

function displayModuleName(module: string): string {
  return MODULE_DISPLAY_NAMES[module] ?? module;
}

/** Group findings by module name. */
function groupByModule(findings: ScanFinding[]): Map<string, ScanFinding[]> {
  const grouped = new Map<string, ScanFinding[]>();
  for (const finding of findings) {
    const existing = grouped.get(finding.module);
    if (existing) {
      existing.push(finding);
    } else {
      grouped.set(finding.module, [finding]);
    }
  }
  return grouped;
}

function FindingCard({ finding }: { finding: ScanFinding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`finding-card ${verdictClass(finding.verdict)}`}>
      <div className="finding-card__header">
        <span className={`verdict-badge ${verdictClass(finding.verdict)}`}>
          {verdictLabel(finding.verdict)}
        </span>
        <span className="finding-card__description">
          {finding.description}
        </span>
      </div>

      <div className="finding-card__meta">
        <span className="finding-card__timestamp">
          {formatTimestamp(finding.timestamp)}
        </span>
      </div>

      {finding.details && (
        <div className="finding-card__details-section">
          <button
            className="finding-card__toggle"
            onClick={() => setExpanded(!expanded)}
            type="button"
          >
            {expanded ? "\u25BC" : "\u25B6"} Details
          </button>
          {expanded && (
            <pre className="finding-card__details">{finding.details}</pre>
          )}
        </div>
      )}
    </div>
  );
}

function ResultsPanel({ report }: ResultsPanelProps) {
  const grouped = groupByModule(report.findings);

  return (
    <div className="results-panel">
      <div className={`overall-verdict ${verdictClass(report.overall_verdict)}`}>
        <span className="overall-verdict__label">Overall Verdict</span>
        <span className={`overall-verdict__badge ${verdictClass(report.overall_verdict)}`}>
          {verdictLabel(report.overall_verdict)}
        </span>
      </div>

      <div className="results-panel__findings">
        {report.findings.length === 0 ? (
          <div className="results-panel__empty">
            <span className="results-panel__empty-icon">&#x2714;</span>
            <p>No issues detected</p>
          </div>
        ) : (
          Array.from(grouped.entries()).map(([moduleName, findings]) => (
            <div className="module-group" key={moduleName}>
              <h3 className="module-group__title">{displayModuleName(moduleName)}</h3>
              <div className="module-group__list">
                {findings.map((finding, idx) => (
                  <FindingCard key={`${moduleName}-${idx}`} finding={finding} />
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default ResultsPanel;
