import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  CheckCircle,
  AlertTriangle,
  Copy,
  ExternalLink,
  PlusCircle,
  FileCode,
  Shield,
  Layers,
  Flame,
  Globe,
  Radio,
} from 'lucide-react';
import api from '../api/api';
import SeverityBadge from '../components/SeverityBadge';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export const SecurityCheck = ({ timeWindow, onAlertIngested }) => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('mode-a');

  // --- MODE A STATE ---
  const [ipInput, setIpInput] = useState('203.0.113.11');
  const [targetFilterInput, setTargetFilterInput] = useState('');
  const [windowInput, setWindowInput] = useState(timeWindow || 15);
  const [checkWhois, setCheckWhois] = useState(true);
  const [checkAbuse, setCheckAbuse] = useState(true);
  const [modeALoading, setModeALoading] = useState(false);
  const [modeAError, setModeAError] = useState(null);
  const [modeAResult, setModeAResult] = useState(null);
  const [copiedAction, setCopiedAction] = useState(false);

  // --- MODE B STATE ---
  const [bSrcIp, setBSrcIp] = useState('198.51.100.77');
  const [bDstIp, setBDstIp] = useState('10.0.0.50');
  const [bSrcPort, setBSrcPort] = useState(48210);
  const [bDstPort, setBDstPort] = useState(443);
  const [bProtocol, setBProtocol] = useState('TCP');
  const [bLabel, setBLabel] = useState('PortScan');
  const [bSeverity, setBSeverity] = useState('MEDIUM');
  const [bConfidence, setBConfidence] = useState(0.85);
  const [bSynthetic, setBSynthetic] = useState(false);
  const [modeBLoading, setModeBLoading] = useState(false);
  const [modeBError, setModeBError] = useState(null);
  const [modeBSuccess, setModeBSuccess] = useState(null);

  // --- MODE C STATE ---
  const [rawLog, setRawLog] = useState(
    'Failed password for invalid user admin from 203.0.113.11 port 48212 ssh2\n' +
    'Oct 26 00:15:30 soc-gw sshd[1245]: Received disconnect from 203.0.113.11 port 48212:11: Bye Bye [preauth]'
  );
  const [modeCLoading, setModeCLoading] = useState(false);
  const [modeCError, setModeCError] = useState(null);
  const [modeCResult, setModeCResult] = useState(null);
  const [ingestLogLoading, setIngestLogLoading] = useState(false);
  const [ingestLogSuccess, setIngestLogSuccess] = useState(null);

  // Handler: Mode A Execute
  const handleAnalyzeIP = async (ipToAnalyze, targetFilter) => {
    const ip = ipToAnalyze || ipInput;
    const filter = targetFilter !== undefined ? targetFilter : targetFilterInput;
    if (!ip) return;

    try {
      setModeALoading(true);
      setModeAError(null);
      const res = await api.analyzeIP({
        src_ip: ip.trim(),
        target_filter_ip: filter.trim() || null,
        time_window_minutes: windowInput,
        check_whois: checkWhois,
        check_abuse: checkAbuse,
      });
      setModeAResult(res);
    } catch (err) {
      console.error('Mode A error:', err);
      setModeAError(err.response?.data?.detail || err.message || 'Failed to analyze IP address');
    } finally {
      setModeALoading(false);
    }
  };

  // Handler: Mode B Submit Alert
  const handleManualIngest = async (e) => {
    e.preventDefault();
    try {
      setModeBLoading(true);
      setModeBError(null);
      setModeBSuccess(null);

      const payload = {
        src_ip: bSrcIp.trim(),
        dst_ip: bDstIp.trim(),
        src_port: parseInt(bSrcPort, 10),
        dst_port: parseInt(bDstPort, 10),
        protocol: bProtocol.trim().toUpperCase(),
        label: bLabel.trim(),
        severity: bSeverity.trim().toUpperCase(),
        confidence: parseFloat(bConfidence),
        timestamp: new Date().toISOString(),
        is_synthetic: Boolean(bSynthetic),
        source: 'SecurityCheck-Manual',
      };

      const res = await api.postAlert(payload);
      setModeBSuccess(res);
      if (onAlertIngested) onAlertIngested();
    } catch (err) {
      console.error('Mode B error:', err);
      setModeBError(err.response?.data?.detail || err.message || 'Failed to ingest manual alert');
    } finally {
      setModeBLoading(false);
    }
  };

  // Handler: Mode C Parse Log
  const handleParseLog = async () => {
    if (!rawLog.trim()) return;
    try {
      setModeCLoading(true);
      setModeCError(null);
      setModeCResult(null);
      setIngestLogSuccess(null);

      const res = await api.parseLog(rawLog);
      setModeCResult(res);
    } catch (err) {
      console.error('Mode C error:', err);
      setModeCError(err.response?.data?.detail || err.message || 'Failed to parse log');
    } finally {
      setModeCLoading(false);
    }
  };

  // Ingest Mode C Parsed alert
  const handleIngestParsedAlert = async () => {
    if (!modeCResult?.extracted_src_ip) return;
    try {
      setIngestLogLoading(true);
      const payload = {
        src_ip: modeCResult.extracted_src_ip,
        dst_ip: modeCResult.extracted_dst_ip || '10.0.0.1',
        src_port: modeCResult.extracted_src_port || 50000,
        dst_port: modeCResult.extracted_dst_port || 22,
        protocol: 'TCP',
        label: modeCResult.inferred_label || 'SSH-BruteForce',
        severity: 'HIGH',
        confidence: 0.9,
        timestamp: new Date().toISOString(),
        is_synthetic: false,
        source: 'LogParser-Syslog',
      };
      const res = await api.postAlert(payload);
      setIngestLogSuccess(res);
      if (onAlertIngested) onAlertIngested();
    } catch (err) {
      console.error('Error ingesting parsed alert:', err);
      setModeCError('Failed to ingest parsed IOC: ' + (err.response?.data?.detail || err.message));
    } finally {
      setIngestLogLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedAction(true);
    setTimeout(() => setCopiedAction(false), 2000);
  };

  return (
    <div className="page-wrapper">
      {/* Mode Selector Tabs */}
      <div
        style={{
          display: 'flex',
          gap: '8px',
          borderBottom: '1px solid var(--border-subtle)',
          marginBottom: '24px',
          paddingBottom: '2px',
        }}
      >
        <button
          className="btn"
          style={{
            backgroundColor: activeTab === 'mode-a' ? 'rgba(0, 125, 184, 0.2)' : 'transparent',
            color: activeTab === 'mode-a' ? '#ffffff' : 'var(--text-muted)',
            borderBottom: activeTab === 'mode-a' ? '2px solid var(--dell-blue-light)' : '2px solid transparent',
            borderRadius: '6px 6px 0 0',
            fontWeight: 600,
          }}
          onClick={() => setActiveTab('mode-a')}
        >
          <Search size={16} />
          <span>Mode A: Threat Actor IP Investigation</span>
        </button>

        <button
          className="btn"
          style={{
            backgroundColor: activeTab === 'mode-b' ? 'rgba(0, 125, 184, 0.2)' : 'transparent',
            color: activeTab === 'mode-b' ? '#ffffff' : 'var(--text-muted)',
            borderBottom: activeTab === 'mode-b' ? '2px solid var(--dell-blue-light)' : '2px solid transparent',
            borderRadius: '6px 6px 0 0',
            fontWeight: 600,
          }}
          onClick={() => setActiveTab('mode-b')}
        >
          <PlusCircle size={16} />
          <span>Mode B: Live Alert Ingestion & Validation</span>
        </button>

        <button
          className="btn"
          style={{
            backgroundColor: activeTab === 'mode-c' ? 'rgba(0, 125, 184, 0.2)' : 'transparent',
            color: activeTab === 'mode-c' ? '#ffffff' : 'var(--text-muted)',
            borderBottom: activeTab === 'mode-c' ? '2px solid var(--dell-blue-light)' : '2px solid transparent',
            borderRadius: '6px 6px 0 0',
            fontWeight: 600,
          }}
          onClick={() => setActiveTab('mode-c')}
        >
          <FileCode size={16} />
          <span>Mode C: Raw Syslog / Flow Parser</span>
        </button>
      </div>

      {/* ======================================================== */}
      {/* MODE A: IP INVESTIGATION */}
      {/* ======================================================== */}
      {activeTab === 'mode-a' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Input Panel */}
          <div className="soc-card">
            <div className="soc-card-header">
              <div>
                <div className="soc-card-title">
                  <ShieldAlert size={18} color="var(--dell-blue-light)" />
                  <span>Deep Threat Actor & Host Telemetry Lookup</span>
                </div>
                <div className="soc-card-subtitle">
                  Inspect historical flows, RFC address classification, correlation clusters, and containment actions
                </div>
              </div>
            </div>

            <div className="soc-card-body">
              {/* Presets */}
              <div style={{ marginBottom: '18px' }}>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginRight: '10px' }}>
                  Quick Investigation Targets:
                </span>
                <div style={{ display: 'inline-flex', gap: '8px', flexWrap: 'wrap', marginTop: '6px' }}>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setIpInput('203.0.113.11');
                      setTargetFilterInput('');
                      handleAnalyzeIP('203.0.113.11', '');
                    }}
                  >
                    203.0.113.11 (Active Attacker, 112 Flows)
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setIpInput('10.0.0.99');
                      setTargetFilterInput('');
                      handleAnalyzeIP('10.0.0.99', '');
                    }}
                  >
                    10.0.0.99 (RFC 1918 Private Adversary, 37 Flows)
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setIpInput('198.51.100.25');
                      setTargetFilterInput('');
                      handleAnalyzeIP('198.51.100.25', '');
                    }}
                  >
                    198.51.100.25 (TEST-NET-2)
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setIpInput('192.168.1.1');
                      setTargetFilterInput('');
                      handleAnalyzeIP('192.168.1.1', '');
                    }}
                  >
                    192.168.1.1 (Clean Private IP)
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setIpInput('8.8.8.8');
                      setTargetFilterInput('');
                      handleAnalyzeIP('8.8.8.8', '');
                    }}
                  >
                    8.8.8.8 (Clean Public DNS)
                  </button>
                </div>
              </div>

              {/* Form Controls */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">Threat Actor / Source IP *</label>
                  <input
                    type="text"
                    className="form-input font-mono"
                    placeholder="e.g. 203.0.113.11"
                    value={ipInput}
                    onChange={(e) => setIpInput(e.target.value)}
                  />
                </div>

                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">Optional Target Filter IP</label>
                  <input
                    type="text"
                    className="form-input font-mono"
                    placeholder="e.g. 10.0.0.1 (leave blank for all)"
                    value={targetFilterInput}
                    onChange={(e) => setTargetFilterInput(e.target.value)}
                  />
                </div>

                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">Correlation Window (min)</label>
                  <input
                    type="number"
                    min="1"
                    max="1440"
                    className="form-input"
                    value={windowInput}
                    onChange={(e) => setWindowInput(Number(e.target.value))}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '18px' }}>
                <div style={{ display: 'flex', gap: '18px' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={checkWhois}
                      onChange={(e) => setCheckWhois(e.target.checked)}
                    />
                    <span>Local Heuristic WHOIS</span>
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={checkAbuse}
                      onChange={(e) => setCheckAbuse(e.target.checked)}
                    />
                    <span>Abuse Score Reconciliation</span>
                  </label>
                </div>

                <button
                  className="btn btn-primary"
                  onClick={() => handleAnalyzeIP()}
                  disabled={modeALoading || !ipInput.trim()}
                >
                  <Search size={16} />
                  <span>{modeALoading ? 'Analyzing Telemetry...' : 'Execute Security Check'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Mode A Results */}
          {modeALoading && <LoadingState message="Querying telemetry database and running correlation heuristics..." />}
          {modeAError && <ErrorState title="Investigation Error" error={modeAError} onRetry={() => handleAnalyzeIP()} />}

          {modeAResult && !modeALoading && (() => {
            const destBreakdown = modeAResult.destination_breakdown || modeAResult.target_breakdown || {};
            const portBreakdown = modeAResult.port_breakdown || {};
            const totalSourced = modeAResult.total_alerts_for_ip ?? modeAResult.total_alerts_found ?? 0;
            const targetHits = modeAResult.target_filter_matches ?? modeAResult.target_hits ?? modeAResult.target_hit_count ?? totalSourced;
            const isFilterApplied = modeAResult.filter_applied ?? modeAResult.target_filter_applied ?? false;
            const correlatedIncId = modeAResult.correlated_incident_id || modeAResult.correlated_incident?.incident_id;
            const correlatedSev = modeAResult.correlated_severity || modeAResult.correlated_incident?.severity;
            const correlatedRisk = modeAResult.correlated_risk_score ?? modeAResult.correlated_incident?.risk_score;
            const recommendationText = Array.isArray(modeAResult.recommendations)
              ? modeAResult.recommendations.join(' ')
              : (modeAResult.recommendations || modeAResult.action_recommendation || modeAResult.soc_finding || 'Continuous passive monitoring recommended.');

            const destSum = Object.values(destBreakdown).reduce((a, b) => a + b, 0);
            const portSum = Object.values(portBreakdown).reduce((a, b) => a + b, 0);

            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                {/* Classification & Summary Metrics */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                    gap: '16px',
                  }}
                >
                  {/* Network Type Card */}
                  <div className="soc-card" style={{ padding: '20px' }}>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Address Classification
                    </span>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', marginTop: '6px' }}>
                      {modeAResult.network_info?.category || modeAResult.network_info?.category_description || 'Standard IP Address'}
                    </div>
                    <div style={{ marginTop: '8px', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                      {modeAResult.network_info?.classification_note || modeAResult.network_info?.soc_classification_note || 'RFC compliance verified.'}
                    </div>
                  </div>

                  {/* Sourced Flows in DB */}
                  <div className="soc-card" style={{ padding: '20px', borderLeft: '3px solid var(--dell-blue-light)' }}>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Total Sourced Flows
                    </span>
                    <div style={{ fontSize: '2rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--dell-blue-light)', marginTop: '4px' }}>
                      {totalSourced}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      Telemetry records originating from this IP
                    </div>
                  </div>

                  {/* Optional Target Matches */}
                  <div className="soc-card" style={{ padding: '20px', borderLeft: '3px solid #f97316' }}>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Optional Target Filter Matches
                    </span>
                    <div style={{ fontSize: '2rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#f97316', marginTop: '4px' }}>
                      {targetHits}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      {isFilterApplied
                        ? `Filter active on target: ${targetFilterInput}`
                        : 'No filter active (100% of sourced alerts represented)'}
                    </div>
                  </div>

                  {/* Correlated Incident Status */}
                  <div className="soc-card" style={{ padding: '20px', borderLeft: '3px solid #ef4444' }}>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      Correlated Incident Link
                    </span>
                    <div style={{ fontSize: '1.25rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: correlatedIncId ? '#ef4444' : '#22c55e', marginTop: '6px' }}>
                      {correlatedIncId || 'NO ACTIVE INCIDENT'}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      {correlatedIncId
                        ? `Assessed Severity: ${correlatedSev} (Score: ${Number(correlatedRisk || 0).toFixed(1)}/10.0)`
                        : 'Hostile grouping threshold not triggered'}
                    </div>
                  </div>
                </div>

                {/* Infrastructure Breakdowns (Target Hosts & Ports) */}
                <div className="charts-grid-2">
                  {/* Target Hosts */}
                  <div className="soc-card">
                    <div className="soc-card-header">
                      <div className="soc-card-title">Target Host Breakdown</div>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        Sum: {destSum} flows
                      </span>
                    </div>
                    <div className="soc-card-body">
                      {Object.keys(destBreakdown).length === 0 ? (
                        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No destination records found.</p>
                      ) : (
                        <table className="soc-table">
                          <thead>
                            <tr>
                              <th>Target Host IP</th>
                              <th>Flow Count</th>
                              <th>% Share</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(destBreakdown).map(([dst, cnt]) => (
                              <tr key={dst}>
                                <td className="font-mono">{dst}</td>
                                <td className="font-mono" style={{ fontWeight: 600 }}>{cnt}</td>
                                <td style={{ color: 'var(--text-accent)' }}>
                                  {((cnt / (totalSourced || 1)) * 100).toFixed(1)}%
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  </div>

                  {/* Target Ports */}
                  <div className="soc-card">
                    <div className="soc-card-header">
                      <div className="soc-card-title">Destination Port Breakdown</div>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        Sum: {portSum} flows
                      </span>
                    </div>
                    <div className="soc-card-body">
                      {Object.keys(portBreakdown).length === 0 ? (
                        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No destination port records found.</p>
                      ) : (
                        <table className="soc-table">
                          <thead>
                            <tr>
                              <th>Port / Service</th>
                              <th>Flow Count</th>
                              <th>% Share</th>
                            </tr>
                          </thead>
                          <tbody>
                            {Object.entries(portBreakdown).map(([port, cnt]) => (
                              <tr key={port}>
                                <td className="font-mono">Port {port}</td>
                                <td className="font-mono" style={{ fontWeight: 600 }}>{cnt}</td>
                                <td style={{ color: 'var(--text-accent)' }}>
                                  {((cnt / (totalSourced || 1)) * 100).toFixed(1)}%
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  </div>
                </div>

                {/* Tactical Containment Action Plan */}
                <div className="soc-card">
                  <div className="soc-card-header">
                    <div className="soc-card-title">
                      <Shield size={18} color="#22c55e" />
                      <span>Tactical Incident Containment & Mitigation</span>
                    </div>
                    {correlatedIncId && (
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => navigate('/reports', { state: { incidentId: correlatedIncId } })}
                      >
                        <ExternalLink size={14} />
                        <span>Generate Full Incident Report</span>
                      </button>
                    )}
                  </div>
                  <div className="soc-card-body">
                    <div style={{ marginBottom: '16px' }}>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                        Primary Remediation Recommendation:
                      </div>
                      <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                        {recommendationText}
                      </p>
                    </div>

                    <div style={{ background: 'var(--bg-input)', padding: '14px 18px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                          Linux Netfilter / iptables Perimeter Drop Rule
                        </span>
                        <button
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '3px 8px', fontSize: '0.72rem' }}
                          onClick={() => copyToClipboard(`iptables -A INPUT -s ${modeAResult.src_ip} -j DROP`)}
                        >
                          <Copy size={12} />
                          <span>{copiedAction ? 'Copied Rule!' : 'Copy Command'}</span>
                        </button>
                      </div>
                      <code style={{ fontSize: '0.85rem', color: '#38bdf8' }}>
                        iptables -A INPUT -s {modeAResult.src_ip} -j DROP
                      </code>
                    </div>
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* ======================================================== */}
      {/* MODE B: LIVE ALERT INGESTION */}
      {/* ======================================================== */}
      {activeTab === 'mode-b' && (
        <div className="soc-card">
          <div className="soc-card-header">
            <div>
              <div className="soc-card-title">
                <PlusCircle size={18} color="var(--dell-blue-light)" />
                <span>Live Alert Ingestion & Pipeline Validation</span>
              </div>
              <div className="soc-card-subtitle">
                Submit raw structured intrusion alerts with schema validation and deduplication checking
              </div>
            </div>
          </div>

          <div className="soc-card-body">
            {modeBSuccess && (
              <div
                style={{
                  padding: '14px 18px',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: modeBSuccess.status === 'deduplicated' ? 'rgba(234, 179, 8, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                  border: `1px solid ${modeBSuccess.status === 'deduplicated' ? 'rgba(234, 179, 8, 0.4)' : 'rgba(34, 197, 94, 0.4)'}`,
                  color: '#ffffff',
                  marginBottom: '20px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                }}
              >
                {modeBSuccess.status === 'deduplicated' ? (
                  <AlertTriangle size={20} color="#facc15" />
                ) : (
                  <CheckCircle size={20} color="#4ade80" />
                )}
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                    {modeBSuccess.status === 'deduplicated' ? 'Alert Deduplicated' : 'Alert Successfully Ingested'}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {modeBSuccess.detail || `Alert ID: ${modeBSuccess.id || 'N/A'}`}
                  </div>
                </div>
              </div>
            )}

            {modeBError && <ErrorState title="Validation / Ingestion Error" error={modeBError} />}

            <form onSubmit={handleManualIngest}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label">Source IP (Attacker) *</label>
                  <input
                    type="text"
                    required
                    className="form-input font-mono"
                    value={bSrcIp}
                    onChange={(e) => setBSrcIp(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Destination IP (Target) *</label>
                  <input
                    type="text"
                    required
                    className="form-input font-mono"
                    value={bDstIp}
                    onChange={(e) => setBDstIp(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Source Port (1-65535) *</label>
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    required
                    className="form-input font-mono"
                    value={bSrcPort}
                    onChange={(e) => setBSrcPort(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Destination Port (1-65535) *</label>
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    required
                    className="form-input font-mono"
                    value={bDstPort}
                    onChange={(e) => setBDstPort(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Protocol *</label>
                  <select
                    className="form-select"
                    value={bProtocol}
                    onChange={(e) => setBProtocol(e.target.value)}
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Attack Vector / Classification Label *</label>
                  <select
                    className="form-select"
                    value={bLabel}
                    onChange={(e) => setBLabel(e.target.value)}
                  >
                    <option value="PortScan">PortScan</option>
                    <option value="DDoS">DDoS</option>
                    <option value="DoS-Hulk">DoS-Hulk</option>
                    <option value="DoS-Slowloris">DoS-Slowloris</option>
                    <option value="SSH-BruteForce">SSH-BruteForce</option>
                    <option value="FTP-BruteForce">FTP-BruteForce</option>
                    <option value="Botnet">Botnet</option>
                    <option value="Web-XSS">Web-XSS</option>
                    <option value="BENIGN">BENIGN</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Severity Level *</label>
                  <select
                    className="form-select"
                    value={bSeverity}
                    onChange={(e) => setBSeverity(e.target.value)}
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">ML Confidence Score (0.00 - 1.00) *</label>
                  <input
                    type="number"
                    step="0.01"
                    min="0"
                    max="1"
                    required
                    className="form-input font-mono"
                    value={bConfidence}
                    onChange={(e) => setBConfidence(e.target.value)}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '0.85rem' }}>
                  <input
                    type="checkbox"
                    checked={bSynthetic}
                    onChange={(e) => setBSynthetic(e.target.checked)}
                  />
                  <span>Tag as Synthetic Test Seed (Adversary Emulation)</span>
                </label>

                <button type="submit" className="btn btn-primary" disabled={modeBLoading}>
                  <CheckCircle size={16} />
                  <span>{modeBLoading ? 'Validating...' : 'Ingest Alert into SOC'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* MODE C: LOG PARSER */}
      {/* ======================================================== */}
      {activeTab === 'mode-c' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="soc-card">
            <div className="soc-card-header">
              <div>
                <div className="soc-card-title">
                  <FileCode size={18} color="var(--dell-blue-light)" />
                  <span>Unstructured Syslog & Network Telemetry Parser</span>
                </div>
                <div className="soc-card-subtitle">
                  Extract source/target IP addresses, ports, and intrusion signatures automatically
                </div>
              </div>
            </div>

            <div className="soc-card-body">
              {/* Presets */}
              <div style={{ marginBottom: '16px' }}>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginRight: '10px' }}>
                  Sample Security Logs:
                </span>
                <div style={{ display: 'inline-flex', gap: '8px', flexWrap: 'wrap', marginTop: '6px' }}>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setRawLog('Failed password for invalid user admin from 203.0.113.11 port 48212 ssh2');
                      setModeCResult(null);
                    }}
                  >
                    SSH Brute-Force Log
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setRawLog('%ASA-4-106023: Deny tcp src outside:10.0.0.99/54321 dst inside:192.168.1.50/443 by access-group "outside_in"');
                      setModeCResult(null);
                    }}
                  >
                    Cisco ASA Firewall Drop
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => {
                      setRawLog('198.51.100.25 - - [26/Oct/2026:00:15:32 +0000] "GET /admin.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 403 289');
                      setModeCResult(null);
                    }}
                  >
                    Nginx / Apache WAF Log
                  </button>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Raw Security Log Text *</label>
                <textarea
                  className="form-textarea font-mono"
                  style={{ minHeight: '120px', fontSize: '0.85rem' }}
                  value={rawLog}
                  onChange={(e) => setRawLog(e.target.value)}
                  placeholder="Paste multi-line syslog, firewall, or web server access log..."
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '12px' }}>
                <button
                  className="btn btn-primary"
                  onClick={handleParseLog}
                  disabled={modeCLoading || !rawLog.trim()}
                >
                  <Search size={16} />
                  <span>{modeCLoading ? 'Parsing Log IOCs...' : 'Parse Log Text'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Mode C Results */}
          {modeCLoading && <LoadingState message="Extracting IP addresses and classifying intrusion signature..." />}
          {modeCError && <ErrorState title="Log Parsing Error" error={modeCError} />}

          {modeCResult && !modeCLoading && (
            <div className="soc-card">
              <div className="soc-card-header">
                <div className="soc-card-title">
                  <CheckCircle size={18} color="#22c55e" />
                  <span>Extracted Indicators of Compromise (IOCs)</span>
                </div>
                {modeCResult.extracted_src_ip && (
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={handleIngestParsedAlert}
                    disabled={ingestLogLoading || !!ingestLogSuccess}
                  >
                    <PlusCircle size={14} />
                    <span>{ingestLogSuccess ? 'Ingested into Database!' : 'Ingest Parsed IOC into SOC Telemetry'}</span>
                  </button>
                )}
              </div>

              <div className="soc-card-body">
                {ingestLogSuccess && (
                  <div
                    style={{
                      padding: '12px 16px',
                      borderRadius: 'var(--radius-md)',
                      backgroundColor: 'rgba(34, 197, 94, 0.15)',
                      border: '1px solid rgba(34, 197, 94, 0.4)',
                      color: '#4ade80',
                      marginBottom: '16px',
                      fontSize: '0.875rem',
                    }}
                  >
                    Successfully ingested alert flow into database (ID: {ingestLogSuccess.id || 'Saved'}).
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
                  <div style={{ background: 'var(--bg-input)', padding: '14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Extracted Source IP</span>
                    <div className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', marginTop: '4px' }}>
                      {modeCResult.extracted_src_ip || 'Not Found'}
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-input)', padding: '14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Destination IP</span>
                    <div className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', marginTop: '4px' }}>
                      {modeCResult.extracted_dst_ip || 'Internal Asset (10.0.0.1)'}
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-input)', padding: '14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Port</span>
                    <div className="font-mono" style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', marginTop: '4px' }}>
                      {modeCResult.extracted_dst_port ? `Port ${modeCResult.extracted_dst_port}` : 'Port 22 (Default)'}
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-input)', padding: '14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Inferred Threat Vector</span>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--dell-blue-light)', marginTop: '4px' }}>
                      {modeCResult.inferred_label || 'SSH-BruteForce'}
                    </div>
                  </div>
                </div>

                {modeCResult.extracted_src_ip && (
                  <div style={{ marginTop: '18px', display: 'flex', gap: '10px' }}>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => {
                        setIpInput(modeCResult.extracted_src_ip);
                        setActiveTab('mode-a');
                        handleAnalyzeIP(modeCResult.extracted_src_ip, '');
                      }}
                    >
                      <Search size={14} />
                      <span>Investigate Extracted IP in Mode A</span>
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SecurityCheck;
