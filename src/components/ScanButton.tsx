import type { ScanPhase } from "../types";

interface ScanButtonProps {
  phase: ScanPhase;
  onStartScan: () => void;
}

function ScanButton({ phase, onStartScan }: ScanButtonProps) {
  const isScanning = phase === "scanning";

  const label = (() => {
    switch (phase) {
      case "idle":
        return "Start Scan";
      case "scanning":
        return "Scanning\u2026";
      case "complete":
        return "Scan Again";
      case "error":
        return "Retry Scan";
    }
  })();

  return (
    <button
      className={`scan-button scan-button--${phase}`}
      onClick={onStartScan}
      disabled={isScanning}
      type="button"
    >
      <span className="scan-button__icon">
        {isScanning ? (
          <span className="spinner" aria-hidden="true" />
        ) : (
          <span className="shield-icon" aria-hidden="true">
            &#x1F6E1;
          </span>
        )}
      </span>
      <span className="scan-button__label">{label}</span>
    </button>
  );
}

export default ScanButton;
