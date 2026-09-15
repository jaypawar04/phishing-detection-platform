import { useEffect, useMemo, useState } from "react";
import jsPDF from "jspdf";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [scans, setScans] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [socStats, setSocStats] = useState({
    total_alerts: 0,
    open_alerts: 0,
    critical_alerts: 0,
    high_alerts: 0,
    medium_alerts: 0,
    low_alerts: 0,
  });

  const [selectedScan, setSelectedScan] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);

  const [error, setError] = useState("");
  const [historyError, setHistoryError] = useState("");
  const [detailsError, setDetailsError] = useState("");
  const [socError, setSocError] = useState("");

  const [loading, setLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [socLoading, setSocLoading] = useState(false);
  const [detailsLoading, setDetailsLoading] = useState(false);

  const [searchTerm, setSearchTerm] = useState("");
  const [filterVerdict, setFilterVerdict] = useState("all");
  const [alertFilter, setAlertFilter] = useState("all");

  // -----------------------------
  // HELPERS
  // -----------------------------

  const formatVerdict = (verdict = "") => {
    return verdict.replaceAll("_", " ").toUpperCase();
  };

  const getRiskClass = (score) => {
    if (score >= 80) return "critical";
    if (score >= 50) return "high";
    if (score >= 20) return "medium";
    return "low";
  };

  const normalizeReasons = (reasons) => {
    if (!reasons) return [];

    if (Array.isArray(reasons)) {
      return reasons;
    }

    if (typeof reasons === "string") {
      try {
        const parsed = JSON.parse(reasons);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }

    return [];
  };

  const renderReasons = (reasons) => {
    const normalizedReasons = normalizeReasons(reasons);

    if (normalizedReasons.length === 0) {
      return (
        <div className="no-threats">
          <span className="check-mark">OK</span>
          <span>No suspicious indicators detected.</span>
        </div>
      );
    }

    return (
      <div className="reason-list">
        {normalizedReasons.map((reason, index) => (
          <div className="reason-item" key={index}>
            <div className="reason-main">
              <span
                className={`severity-dot ${
                  reason.severity || "medium"
                }`}
              />

              <strong>{reason.indicator}</strong>
            </div>

            <div className="reason-meta">
              {reason.points !== undefined && (
                <span className="points">
                  +{reason.points}
                </span>
              )}

              {Array.isArray(reason.keywords) &&
                reason.keywords.length > 0 && (
                  <span className="keywords">
                    Keywords: {reason.keywords.join(", ")}
                  </span>
                )}
            </div>
          </div>
        ))}
      </div>
    );
  };

  // -----------------------------
  // FETCH SCANS
  // -----------------------------

  const fetchScans = async () => {
    setHistoryLoading(true);
    setHistoryError("");

    try {
      const response = await fetch(
        `${API_URL}/api/v1/scans`
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Unable to load scan history."
        );
      }

      setScans(Array.isArray(data) ? data : []);
    } catch (err) {
      setHistoryError(err.message);
    } finally {
      setHistoryLoading(false);
    }
  };

  // -----------------------------
  // FETCH SOC DATA
  // -----------------------------

  const fetchSocData = async () => {
    setSocLoading(true);
    setSocError("");

    try {
      const [alertsResponse, statsResponse] =
        await Promise.all([
          fetch(`${API_URL}/api/v1/alerts`),
          fetch(`${API_URL}/api/v1/soc/stats`),
        ]);

      const alertsData = await alertsResponse.json();
      const statsData = await statsResponse.json();

      if (!alertsResponse.ok) {
        throw new Error(
          alertsData.detail ||
            "Unable to load SOC alerts."
        );
      }

      if (!statsResponse.ok) {
        throw new Error(
          statsData.detail ||
            "Unable to load SOC statistics."
        );
      }

      setAlerts(
        Array.isArray(alertsData)
          ? alertsData
          : []
      );

      setSocStats({
        total_alerts: Number(statsData.total_alerts || 0),
        open_alerts: Number(statsData.open_alerts || 0),
        critical_alerts: Number(statsData.critical_alerts || 0),
        high_alerts: Number(statsData.high_alerts || 0),
        medium_alerts: Number(statsData.medium_alerts || 0),
        low_alerts: Number(statsData.low_alerts || 0),
      });
    } catch (err) {
      setSocError(err.message);
    } finally {
      setSocLoading(false);
    }
  };

  // -----------------------------
  // REFRESH EVERYTHING
  // -----------------------------

  const refreshDashboard = async () => {
    await Promise.all([
      fetchScans(),
      fetchSocData(),
    ]);
  };

  useEffect(() => {
    refreshDashboard();
  }, []);

  // -----------------------------
  // SCAN URL
  // -----------------------------

  const scanUrl = async () => {
    setError("");
    setResult(null);
    setSelectedScan(null);
    setSelectedAlert(null);

    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(
        `${API_URL}/api/v1/scan`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            url: url.trim(),
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail?.[0]?.msg ||
            data.detail ||
            "Unable to scan URL."
        );
      }

      setResult(data);

      await Promise.all([
        fetchScans(),
        fetchSocData(),
      ]);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // -----------------------------
  // DELETE SCAN
  // -----------------------------

  const deleteScan = async (scanId) => {
    const confirmed = window.confirm(
      `Are you sure you want to delete Scan #${scanId}?`
    );

    if (!confirmed) return;

    try {
      const response = await fetch(
        `${API_URL}/api/v1/scans/${scanId}`,
        {
          method: "DELETE",
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Unable to delete scan."
        );
      }

      setScans((currentScans) =>
        currentScans.filter((scan) => scan.id !== scanId)
      );

      if (selectedScan?.id === scanId) {
        setSelectedScan(null);
      }

      if (result?.id === scanId) {
        setResult(null);
      }

      await fetchSocData();

      alert("Scan deleted successfully.");
    } catch (err) {
      alert(err.message);
    }
  };

  // -----------------------------
  // SCAN DETAILS
  // -----------------------------

  const fetchScanDetails = async (scanId) => {
    setDetailsLoading(true);
    setDetailsError("");
    setSelectedScan(null);
    setSelectedAlert(null);

    try {
      const response = await fetch(
        `${API_URL}/api/v1/scans/${scanId}`
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Unable to load scan details."
        );
      }

      setSelectedScan(data);

      window.scrollTo({
        top: 0,
        behavior: "smooth",
      });
    } catch (err) {
      setDetailsError(err.message);
    } finally {
      setDetailsLoading(false);
    }
  };

  // -----------------------------
  // FILTER SCANS
  // -----------------------------

  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      const matchesSearch = String(
        scan.url || ""
      )
        .toLowerCase()
        .includes(searchTerm.toLowerCase());

      const matchesFilter =
        filterVerdict === "all" ||
        scan.verdict === filterVerdict;

      return matchesSearch && matchesFilter;
    });
  }, [scans, searchTerm, filterVerdict]);

  // -----------------------------
  // FILTER ALERTS
  // -----------------------------

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      return (
        alertFilter === "all" ||
        alert.severity === alertFilter
      );
    });
  }, [alerts, alertFilter]);

  // -----------------------------
  // SCAN STATISTICS
  // -----------------------------

  const totalScans = scans.length;

  const legitimateScans = scans.filter(
    (scan) => scan.verdict === "legitimate"
  ).length;

  const suspiciousScans = scans.filter(
    (scan) => scan.verdict === "suspicious"
  ).length;

  const highRiskScans = scans.filter(
    (scan) => scan.verdict === "high_risk"
  ).length;

  const phishingScans = scans.filter(
    (scan) => scan.verdict === "phishing"
  ).length;

  const averageRisk =
    totalScans > 0
      ? Math.round(
          scans.reduce(
            (total, scan) =>
              total + Number(scan.risk_score || 0),
            0
          ) / totalScans
        )
      : 0;

  // -----------------------------
  // UI
  // -----------------------------

  return (
    <div className="app">

      {/* HEADER */}
      <header className="header">
        <div className="header-inner">

          <div className="brand">
            <div className="brand-shield">
              PD
            </div>

            <div>
              <h1>
                Phishing Detection Platform
              </h1>

              <p>
                Security Operations &
                URL Intelligence
              </p>
            </div>
          </div>

          <div className="system-status">
            <span className="status-dot" />
            SYSTEM ONLINE
          </div>

        </div>
      </header>

      <aside className="sidebar">
        <div className="sidebar-title">SECURITY OPERATIONS</div>
        <nav className="sidebar-nav">
          <a href="#dashboard" className="sidebar-link active"><span>▣</span><span>Dashboard</span></a>
          <a href="#scanner" className="sidebar-link"><span>⌕</span><span>URL Scanner</span></a>
          <a href="#alerts" className="sidebar-link"><span>⚠</span><span>SOC Alerts</span></a>
          <a href="#history" className="sidebar-link"><span>◉</span><span>Scan History</span></a>
          <a href="#reports" className="sidebar-link"><span>▤</span><span>Reports</span></a>
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-divider"></div>
          <a href="#settings" className="sidebar-link"><span>⚙</span><span>Settings</span></a>
          <div className="sidebar-system"><span className="status-dot"></span><span>System Operational</span></div>
        </div>
      </aside>

      <main className="container">

        {/* =================================
            SECURITY OVERVIEW
        ================================= */}

        <section id="dashboard" className="dashboard-section">

          <div className="section-heading">

            <div>
              <span className="eyebrow">
                SECURITY OPERATIONS CENTER
              </span>

              <h2>
                Security Overview
              </h2>

              <p>
                Real-time phishing detection
                and SOC alert monitoring.
              </p>
            </div>

            <button
              className="refresh-button"
              onClick={refreshDashboard}
              disabled={
                historyLoading || socLoading
              }
            >
              {historyLoading || socLoading
                ? "Refreshing..."
                : "Refresh Data"}
            </button>

          </div>

          {/* SCAN STATISTICS */}

          <div className="stats-grid">

            <div className="stat-card">
              <div className="stat-icon blue">
                SCAN
              </div>

              <span className="stat-label">
                Total Scans
              </span>

              <strong className="stat-value">
                {totalScans}
              </strong>
            </div>

            <div className="stat-card">
              <div className="stat-icon green">
                OK
              </div>

              <span className="stat-label">
                Legitimate
              </span>

              <strong className="stat-value">
                {legitimateScans}
              </strong>
            </div>

            <div className="stat-card">
              <div className="stat-icon yellow">
                WARN
              </div>

              <span className="stat-label">
                Suspicious
              </span>

              <strong className="stat-value">
                {suspiciousScans}
              </strong>
            </div>

            <div className="stat-card">
              <div className="stat-icon orange">
                HIGH
              </div>

              <span className="stat-label">
                High Risk
              </span>

              <strong className="stat-value">
                {highRiskScans}
              </strong>
            </div>

            <div className="stat-card">
              <div className="stat-icon red">
                CRIT
              </div>

              <span className="stat-label">
                Phishing
              </span>

              <strong className="stat-value">
                {phishingScans}
              </strong>
            </div>

          </div>

          {/* SOC STATISTICS */}

          <div className="soc-alert-summary">

            <div className="soc-summary-card">
              <span className="stat-label">
                SOC ALERTS
              </span>

              <strong>
                {socStats.total_alerts}
              </strong>

              <small>
                Total generated alerts
              </small>
            </div>

            <div className="soc-summary-card">
              <span className="stat-label">
                OPEN
              </span>

              <strong>
                {socStats.open_alerts}
              </strong>

              <small>
                Require investigation
              </small>
            </div>

            <div className="soc-summary-card critical-border">
              <span className="stat-label">
                CRITICAL
              </span>

              <strong>
                {socStats.critical_alerts}
              </strong>

              <small>
                Immediate attention
              </small>
            </div>

            <div className="soc-summary-card high-border">
              <span className="stat-label">
                HIGH
              </span>

              <strong>
                {socStats.high_alerts}
              </strong>

              <small>
                High-priority threats
              </small>
            </div>

            <div className="soc-summary-card medium-border">
              <span className="stat-label">
                MEDIUM
              </span>

              <strong>
                {socStats.medium_alerts}
              </strong>

              <small>
                Suspicious activity
              </small>
            </div>

          </div>

          {socError && (
            <div className="error">
              <strong>
                SOC Error
              </strong>

              <span>
                {socError}
              </span>
            </div>
          )}

          {/* RISK SUMMARY */}

          <div className="risk-summary-grid">

            <div className="average-risk-card">

              <div className="card-top">

                <div>
                  <span className="stat-label">
                    Average Risk Score
                  </span>

                  <div className="average-score">
                    {averageRisk}
                    <small>/100</small>
                  </div>
                </div>

                <div
                  className={`risk-level ${getRiskClass(
                    averageRisk
                  )}`}
                >
                  {averageRisk >= 80
                    ? "CRITICAL"
                    : averageRisk >= 50
                    ? "HIGH"
                    : averageRisk >= 20
                    ? "MEDIUM"
                    : "LOW"}
                </div>

              </div>

              <div className="risk-bar">
                <div
                  className={`risk-bar-fill ${getRiskClass(
                    averageRisk
                  )}`}
                  style={{
                    width: `${averageRisk}%`,
                  }}
                />
              </div>

              <p>
                Average risk calculated
                across all recorded scans.
              </p>

            </div>

            {/* DISTRIBUTION */}

            <div className="distribution-card">

              <div className="card-heading">

                <div>
                  <span className="stat-label">
                    VERDICT DISTRIBUTION
                  </span>

                  <h3>
                    Detection Overview
                  </h3>
                </div>

              </div>

              {[
                [
                  "Legitimate",
                  legitimateScans,
                  "legitimate-fill",
                ],
                [
                  "Suspicious",
                  suspiciousScans,
                  "suspicious-fill",
                ],
                [
                  "High Risk",
                  highRiskScans,
                  "high-fill",
                ],
                [
                  "Phishing",
                  phishingScans,
                  "phishing-fill",
                ],
              ].map(
                ([label, count, fillClass]) => (

                  <div
                    className="distribution-row"
                    key={label}
                  >

                    <span>
                      {label}
                    </span>

                    <strong>
                      {count}
                    </strong>

                    <div className="distribution-track">

                      <div
                        className={`distribution-fill ${fillClass}`}
                        style={{
                          width: totalScans
                            ? `${(count / totalScans) * 100}%`
                            : "0%",
                        }}
                      />

                    </div>

                  </div>

                )
              )}

            </div>

          </div>

        </section>

        {/* =================================
            SOC ALERT QUEUE
        ================================= */}

        <section id="alerts" className="soc-alert-panel">

          <div className="history-header">

            <div>
              <span className="eyebrow">
                SOC ALERT QUEUE
              </span>

              <h2>
                Security Alerts
              </h2>

              <p>
                Investigate suspicious activity
                generated by the detection engine.
              </p>
            </div>

            <select
              className="alert-filter"
              value={alertFilter}
              onChange={(event) =>
                setAlertFilter(event.target.value)
              }
            >

              <option value="all">
                All Severities
              </option>

              <option value="critical">
                Critical
              </option>

              <option value="high">
                High
              </option>

              <option value="medium">
                Medium
              </option>

              <option value="low">
                Low
              </option>

            </select>

          </div>

          {filteredAlerts.length === 0 ? (

            <div className="empty-alerts">

              <span className="check-mark">
                OK
              </span>

              <div>
                <strong>
                  No alerts found
                </strong>

                <p>
                  No alerts match the
                  selected severity.
                </p>
              </div>

            </div>

          ) : (

            <div className="alert-list">

              {filteredAlerts.map(
                (alert) => (

                  <button
                    className="alert-row"
                    key={alert.id}
                    onClick={() => {
                      setSelectedAlert(alert);
                      setSelectedScan(null);
                    }}
                  >

                    <div
                      className={`alert-severity ${alert.severity}`}
                    >
                      {String(
                        alert.severity
                      ).toUpperCase()}
                    </div>

                    <div className="alert-content">

                      <strong>
                        {alert.title}
                      </strong>

                      <span>
                        {alert.description}
                      </span>

                    </div>

                    <div className="alert-meta">

                      <span>
                        SCAN #{alert.scan_id}
                      </span>

                      <span>
                        {new Date(
                          alert.created_at
                        ).toLocaleString()}
                      </span>

                    </div>

                    <div className="alert-status">
                      {String(
                        alert.status
                      ).toUpperCase()}
                    </div>

                  </button>

                )
              )}

            </div>

          )}

        </section>

        {/* =================================
            ALERT DETAILS
        ================================= */}

        {selectedAlert && (

          <section className="alert-detail-card">

            <div className="details-header">

              <div>
                <span className="eyebrow">
                  SECURITY INVESTIGATION
                </span>

                <h2>
                  Alert #{selectedAlert.id}
                </h2>

                <p>
                  {selectedAlert.title}
                </p>
              </div>

              <button
                className="back-button"
                onClick={() =>
                  setSelectedAlert(null)
                }
              >
                Close
              </button>

            </div>

            <div className="details-grid">

              <div className="detail-item">
                <span className="detail-label">
                  Alert ID
                </span>

                <strong>
                  #{selectedAlert.id}
                </strong>
              </div>

              <div className="detail-item">
                <span className="detail-label">
                  Scan ID
                </span>

                <strong>
                  #{selectedAlert.scan_id}
                </strong>
              </div>

              <div className="detail-item">
                <span className="detail-label">
                  Severity
                </span>

                <span
                  className={`alert-severity inline ${selectedAlert.severity}`}
                >
                  {String(
                    selectedAlert.severity
                  ).toUpperCase()}
                </span>
              </div>

              <div className="detail-item">
                <span className="detail-label">
                  Status
                </span>

                <strong>
                  {String(
                    selectedAlert.status
                  ).toUpperCase()}
                </strong>
              </div>

            </div>

            <div className="detail-url">

              <span className="detail-label">
                DESCRIPTION
              </span>

              <strong>
                {selectedAlert.description}
              </strong>

            </div>

          </section>

        )}

        {/* =================================
            URL SCANNER
        ================================= */}

        <section id="scanner" className="scanner-card">

          <div className="scanner-heading">

            <div>
              <span className="eyebrow">
                THREAT ANALYSIS
              </span>

              <h2>
                Analyze a URL
              </h2>

              <p>
                Enter a URL to evaluate phishing
                risk and generate SOC alerts.
              </p>
            </div>

            <div className="scanner-badge">
              URL SCANNER
            </div>

          </div>

          <div className="input-group">

            <input
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(event) =>
                setUrl(event.target.value)
              }
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  scanUrl();
                }
              }}
            />

            <button
              onClick={scanUrl}
              disabled={loading}
            >
              {loading
                ? "Analyzing..."
                : "Scan URL"}
            </button>

          </div>

          {loading && (

            <div className="scan-progress">
              <div className="spinner" />

              <span>
                Analyzing URL security
                indicators...
              </span>
            </div>

          )}

          {error && (

            <div className="error">

              <strong>
                Scan Error
              </strong>

              <span>
                {error}
              </span>

            </div>

          )}

        </section>

        {/* =================================
            SCAN RESULT
        ================================= */}

        {result &&
          !selectedScan &&
          !selectedAlert && (

            <section className="result-card">

              <div className="result-heading">

                <div>
                  <span className="eyebrow">
                    ANALYSIS COMPLETE
                  </span>

                  <h2>
                    Scan Result
                  </h2>
                </div>

                <div
                  className={`result-status ${result.verdict}`}
                >
                  {formatVerdict(
                    result.verdict
                  )}
                </div>

              </div>

              <div className="result-main">

                <div
                  className={`score-circle ${getRiskClass(
                    result.risk_score
                  )}`}
                >

                  <strong>
                    {result.risk_score}
                  </strong>

                  <span>/100</span>

                </div>

                <div className="result-summary">

                  <span className="stat-label">
                    RISK ASSESSMENT
                  </span>

                  <h3>
                    {result.risk_score >= 80
                      ? "Critical Threat"
                      : result.risk_score >= 50
                      ? "High Risk URL"
                      : result.risk_score >= 20
                      ? "Suspicious URL"
                      : result.risk_score > 0
                      ? "Low Risk Indicators"
                      : "No Threat Indicators"}
                  </h3>

                  <p>
                    The URL was analyzed using
                    the platform's phishing
                    detection rules.
                  </p>

                </div>

              </div>

              <div className="result-url">

                <span className="detail-label">
                  ANALYZED URL
                </span>

                <strong>
                  {result.url}
                </strong>

              </div>

              <div className="reasons">

                <div className="card-heading">

                  <div>
                    <span className="stat-label">
                      THREAT INTELLIGENCE
                    </span>

                    <h3>
                      Detection Reasons
                    </h3>
                  </div>

                </div>

                {renderReasons(
                  result.reasons
                )}

              </div>

            </section>

          )}

        {/* =================================
            SCAN DETAILS
        ================================= */}

        {selectedScan && (

          <section className="details-card">

            <div className="details-header">

              <div>
                <span className="eyebrow">
                  FORENSIC ANALYSIS
                </span>

                <h2>
                  Scan Details
                </h2>

                <p>
                  Detailed analysis for Scan #
                  {selectedScan.id}
                </p>
              </div>

              <button
                className="back-button"
                onClick={() =>
                  setSelectedScan(null)
                }
              >
                Back to Dashboard
              </button>

            </div>

            <div className="details-grid">

              <div className="detail-item">
                <span className="detail-label">
                  Scan ID
                </span>

                <strong>
                  #{selectedScan.id}
                </strong>
              </div>

              <div className="detail-item">
                <span className="detail-label">
                  Risk Score
                </span>

                <strong
                  className={`large-score ${getRiskClass(
                    selectedScan.risk_score
                  )}`}
                >
                  {selectedScan.risk_score}/100
                </strong>
              </div>

              <div className="detail-item">
                <span className="detail-label">
                  Verdict
                </span>

                <span
                  className={`history-verdict ${selectedScan.verdict}`}
                >
                  {formatVerdict(
                    selectedScan.verdict
                  )}
                </span>
              </div>

              <div className="detail-item">
                <span className="detail-label">
                  Scanned At
                </span>

                <strong>
                  {new Date(
                    selectedScan.scanned_at
                  ).toLocaleString()}
                </strong>
              </div>

            </div>

            <div className="detail-url">

              <span className="detail-label">
                ANALYZED URL
              </span>

              <strong>
                {selectedScan.url}
              </strong>

            </div>

            <div className="reasons">

              <div className="card-heading">

                <div>
                  <span className="stat-label">
                    THREAT INTELLIGENCE
                  </span>

                  <h3>
                    Detection Reasons
                  </h3>
                </div>

              </div>

              {renderReasons(
                selectedScan.reasons
              )}

            </div>

          </section>

        )}

        {detailsLoading && (

          <div className="loading-message">
            Loading scan details...
          </div>

        )}

        {detailsError && (

          <div className="error">

            <strong>
              Details Error
            </strong>

            <span>
              {detailsError}
            </span>

          </div>

        )}

        {/* =================================
            HISTORY
        ================================= */}

        <section id="history" className="history-card">

          <div className="history-header">

            <div>
              <span className="eyebrow">
                INVESTIGATION LOG
              </span>

              <h2>
                Recent Scans
              </h2>

              <p>
                Search and investigate
                previously analyzed URLs.
              </p>
            </div>

            <button
              className="refresh-button"
              onClick={fetchScans}
              disabled={historyLoading}
            >
              {historyLoading
                ? "Refreshing..."
                : "Refresh"}
            </button>

          </div>

          {historyError && (

            <div className="error">
              {historyError}
            </div>

          )}

          <div className="history-controls">

            <input
              type="text"
              placeholder="Search URL..."
              value={searchTerm}
              onChange={(event) =>
                setSearchTerm(event.target.value)
              }
            />

            <select
              value={filterVerdict}
              onChange={(event) =>
                setFilterVerdict(event.target.value)
              }
            >

              <option value="all">
                All Verdicts
              </option>

              <option value="legitimate">
                Legitimate
              </option>

              <option value="suspicious">
                Suspicious
              </option>

              <option value="high_risk">
                High Risk
              </option>

              <option value="phishing">
                Phishing
              </option>

            </select>

          </div>

          {!historyLoading &&
            !historyError &&
            filteredScans.length === 0 && (

              <div className="empty-history">
                No matching scans found.
              </div>

            )}

          {filteredScans.length > 0 && (

            <div className="table-wrapper">

              <table className="scan-table">

                <thead>
                  <tr>
                    <th>ID</th>
                    <th>URL</th>
                    <th>Risk</th>
                    <th>Verdict</th>
                    <th>Scanned At</th>
                    <th>Actions</th>
                  </tr>
                </thead>

                <tbody>

                  {filteredScans.map(
                    (scan) => (

                      <tr key={scan.id}>

                        <td>
                          <button
                            className="scan-id-button"
                            onClick={() =>
                              fetchScanDetails(
                                scan.id
                              )
                            }
                          >
                            #{scan.id}
                          </button>
                        </td>

                        <td className="url-cell">
                          {scan.url}
                        </td>

                        <td>

                          <div className="table-risk">

                            <strong>
                              {scan.risk_score}
                            </strong>

                            <span>
                              /100
                            </span>

                          </div>

                        </td>

                        <td>

                          <span
                            className={`history-verdict ${scan.verdict}`}
                          >
                            {formatVerdict(
                              scan.verdict
                            )}
                          </span>

                        </td>

                        <td>
                          {new Date(
                            scan.scanned_at
                          ).toLocaleString()}
                        </td>

                        <td>
                          <button
                            className="delete-button"
                            onClick={() =>
                              deleteScan(scan.id)
                            }
                          >
                            Delete
                          </button>
                        </td>

                      </tr>

                    )
                  )}

                </tbody>

              </table>

            </div>

          )}

        </section>

      </main>

      {/* FOOTER */}

      <footer className="footer">

        <span>
          Phishing Detection Platform
        </span>

        <span>
          SOC Security Analysis Engine v2.0
        </span>

      </footer>

    </div>
  );
}

export default App;