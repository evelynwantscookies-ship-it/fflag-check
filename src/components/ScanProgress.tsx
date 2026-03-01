function ScanProgress() {
  return (
    <div className="scan-progress">
      <div className="scan-progress__bar">
        <div className="scan-progress__fill" />
      </div>
      <p className="scan-progress__text">Analyzing system&hellip;</p>
      <div className="scan-progress__dots">
        <span className="scan-progress__dot" />
        <span className="scan-progress__dot" />
        <span className="scan-progress__dot" />
      </div>
    </div>
  );
}

export default ScanProgress;
