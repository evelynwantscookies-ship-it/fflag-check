import "./App.css";
import { useScan } from "./hooks/useScan";
import ScanButton from "./components/ScanButton";
import ScanProgress from "./components/ScanProgress";
import ResultsPanel from "./components/ResultsPanel";
import ReportView from "./components/ReportView";

function App() {
  const { phase, report, error, startScan, saveReport } = useScan();

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-header__brand">
          <span className="app-header__icon" aria-hidden="true">
            &#x1F6E1;
          </span>
          <h1 className="app-header__title">TSBCC FFlag Scanner</h1>
        </div>
        <span className="app-header__subtitle">
          Tournament Anti-Cheat Scanner
        </span>
      </header>

      <main className="app-main">
        <div
          className={`scan-section ${
            phase === "idle" || phase === "error"
              ? "scan-section--centered"
              : ""
          }`}
        >
          <ScanButton phase={phase} onStartScan={startScan} />
        </div>

        {phase === "scanning" && (
          <section className="progress-section fade-in">
            <ScanProgress />
          </section>
        )}

        {error && (
          <section className="error-section fade-in">
            <div className="error-card">
              <span className="error-card__icon" aria-hidden="true">
                &#x26A0;
              </span>
              <p className="error-card__message">{error}</p>
            </div>
          </section>
        )}

        {phase === "complete" && report && (
          <section className="results-section fade-in">
            <ResultsPanel report={report} />
            <ReportView report={report} onSave={saveReport} />
          </section>
        )}
      </main>

      <footer className="app-footer">
        <span>TSBCC FFlag Scanner v0.1.0</span>
      </footer>
    </div>
  );
}

export default App;
