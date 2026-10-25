import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Flame,
  Search,
  Sliders,
  ChevronRight,
  X,
  FileText,
  Download,
  AlertTriangle,
  Clock,
  Layers,
  Shield,
  Activity,
} from 'lucide-react';
import api from '../api/api';
import SeverityBadge from '../components/SeverityBadge';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export const Incidents = ({ timeWindow, setTimeWindow }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [pdfDownloading, setPdfDownloading] = useState(false);

  const loadIncidents = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getIncidents(timeWindow);
      setIncidents(res);
      // If selected incident is open, update its reference if it still exists
      if (selectedIncident) {
        const updated = res.find((i) => i.incident_id === selectedIncident.incident_id);
        if (updated) setSelectedIncident(updated);
      }
    } catch (err) {
      console.error('Failed to load incidents:', err);
      setError(err.response?.data?.detail || err.message || 'Error correlating incidents');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [timeWindow]);

  const handleDownloadPdf = async (incidentId) => {
    try {
      setPdfDownloading(true);
      const blob = await api.downloadPdfBlob(incidentId, timeWindow);
      const url = window.URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${incidentId}_SOC_Report.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error('Failed to download PDF:', err);
      alert('Could not download PDF report: ' + (err.response?.data?.detail || err.message));
    } finally {
      setPdfDownloading(false);
    }
  };

  // Filter incidents
  const filteredIncidents = incidents.filter((inc) => {
    const q = searchTerm.toLowerCase();
    const incIdMatch = (inc.incident_id || '').toLowerCase().includes(q);
    const ipMatch = (inc.src_ip || '').toLowerCase().includes(q);
    const labelMatch = (inc.labels || []).some((l) => l.toLowerCase().includes(q));
    const sevMatch = (inc.severity || '').toLowerCase().includes(q);
    return incIdMatch || ipMatch || labelMatch || sevMatch;
  });

  const criticalCount = incidents.filter((i) => i.severity === 'CRITICAL').length;
  const highCount = incidents.filter((i) => i.severity === 'HIGH').length;
  const maxRisk = incidents.length > 0 ? Math.max(...incidents.map((i) => i.risk_score || 0)) : 0;

  return (
    <div className="page-wrapper">
      {/* Top Controls & Correlation Window Selector */}
      <div
        className="soc-card"
        style={{
          padding: '18px 24px',
          marginBottom: '24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sliders size={18} color="var(--dell-blue-light)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Temporal Window:
            </span>
          </div>
          <div style={{ display: 'flex', gap: '6px' }}>
            {[5, 15, 30, 60].map((win) => (
              <button
                key={win}
                className="btn btn-sm"
                style={{
                  backgroundColor: timeWindow === win ? 'var(--dell-blue)' : 'var(--bg-input)',
                  color: timeWindow === win ? '#ffffff' : 'var(--text-secondary)',
                  border: `1px solid ${timeWindow === win ? 'var(--dell-blue-light)' : 'var(--border-subtle)'}`,
                  fontWeight: timeWindow === win ? 600 : 400,
                }}
                onClick={() => setTimeWindow(win)}
              >
                {win}m {win === 15 ? '(Standard)' : ''}
              </button>
            ))}
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            Grouping alerts occurring within {timeWindow} minutes of each other
          </span>
        </div>

        {/* Search */}
        <div style={{ position: 'relative', width: '280px' }}>
          <Search size={15} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="form-input"
            style={{ paddingLeft: '36px', height: '38px', fontSize: '0.825rem' }}
            placeholder="Filter by ID, IP, or Vector..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      {/* KPI Stats Ribbon */}
      <div className="metrics-grid" style={{ marginBottom: '24px' }}>
        <div className="soc-card" style={{ padding: '16px 20px', borderLeft: '3px solid var(--dell-blue)' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Clusters</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#ffffff', marginTop: '4px' }}>
            {incidents.length}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Correlated in {timeWindow}m window</div>
        </div>

        <div className="soc-card" style={{ padding: '16px 20px', borderLeft: '3px solid #ef4444' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Critical Severity</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#ef4444', marginTop: '4px' }}>
            {criticalCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Multi-stage / weaponized breaches</div>
        </div>

        <div className="soc-card" style={{ padding: '16px 20px', borderLeft: '3px solid #f97316' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>High Severity</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#f97316', marginTop: '4px' }}>
            {highCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Active exploit attempts</div>
        </div>

        <div className="soc-card" style={{ padding: '16px 20px', borderLeft: '3px solid #a855f7' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Peak Risk Score</span>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#c084fc', marginTop: '4px' }}>
            {Number(maxRisk).toFixed(1)} <span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>/ 10.0</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Deterministic threat weight</div>
        </div>
      </div>

      {/* Main Table */}
      {loading && !incidents.length ? (
        <LoadingState message="Correlating alert telemetry and building chronological attack progressions..." />
      ) : error ? (
        <ErrorState title="Correlation Error" error={error} onRetry={loadIncidents} />
      ) : (
        <div className="soc-card">
          <div className="soc-card-header">
            <div>
              <div className="soc-card-title">
                <Flame size={18} color="#f97316" />
                <span>Correlated Security Incidents</span>
              </div>
              <div className="soc-card-subtitle">
                Displaying {filteredIncidents.length} of {incidents.length} incidents
              </div>
            </div>
          </div>

          <div className="soc-table-wrapper">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Threat Actor IP</th>
                  <th>Flow Count</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Attack Vectors</th>
                  <th>Attack Progression</th>
                  <th>Time Span</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.length === 0 ? (
                  <tr>
                    <td colSpan="9" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      No matching incidents found for the search query.
                    </td>
                  </tr>
                ) : (
                  filteredIncidents.map((inc) => {
                    const score = Number(inc.risk_score || 0);
                    const isCritical = score >= 8.0;
                    const isHigh = score >= 6.0 && score < 8.0;
                    const isMedium = score >= 3.5 && score < 6.0;
                    const scoreColor = isCritical ? '#ef4444' : isHigh ? '#f97316' : isMedium ? '#eab308' : '#22c55e';
                    const progression = inc.threat_pattern || inc.sequence_description || 'Single-phase activity';

                    return (
                      <tr
                        key={inc.incident_id}
                        style={{
                          backgroundColor: selectedIncident?.incident_id === inc.incident_id ? 'rgba(0, 125, 184, 0.12)' : 'transparent',
                          cursor: 'pointer',
                        }}
                        onClick={() => setSelectedIncident(inc)}
                      >
                        <td>
                          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--dell-blue-light)' }}>
                            {inc.incident_id}
                          </span>
                        </td>
                        <td>
                          <span className="font-mono" style={{ color: '#ffffff', fontWeight: 600 }}>{inc.src_ip}</span>
                        </td>
                        <td>
                          <span style={{ fontWeight: 600 }}>{inc.alert_count}</span>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: '3px' }}>flows</span>
                        </td>
                        <td>
                          <SeverityBadge severity={inc.severity} isSynthetic={inc.is_synthetic} />
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span
                              style={{
                                fontFamily: 'var(--font-mono)',
                                fontWeight: 700,
                                color: scoreColor,
                              }}
                            >
                              {score.toFixed(1)}
                            </span>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>/ 10.0</span>
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                            {(inc.labels || []).map((lbl, idx) => (
                              <span
                                key={idx}
                                style={{
                                  fontSize: '0.7rem',
                                  padding: '2px 6px',
                                  background: 'rgba(255, 255, 255, 0.06)',
                                  borderRadius: '4px',
                                  color: '#e2e8f0',
                                }}
                              >
                                {lbl}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td style={{ maxWidth: '280px', whiteSpace: 'normal' }}>
                          <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.3, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                            {progression}
                          </span>
                        </td>
                        <td>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            {inc.first_seen && inc.last_seen
                              ? `${new Date(inc.first_seen).toLocaleTimeString()} - ${new Date(inc.last_seen).toLocaleTimeString()}`
                              : inc.window_start && inc.window_end
                              ? `${new Date(inc.window_start).toLocaleTimeString()} - ${new Date(inc.window_end).toLocaleTimeString()}`
                              : 'N/A'}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '6px' }}>
                            <button
                              className="btn btn-secondary btn-sm"
                              style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedIncident(inc);
                              }}
                            >
                              Evidence
                            </button>
                            <button
                              className="btn btn-primary btn-sm"
                              style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate('/reports', { state: { incidentId: inc.incident_id } });
                              }}
                            >
                              Report
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Slide-in Evidence Drawer */}
      {selectedIncident && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            right: 0,
            width: '600px',
            maxWidth: '90vw',
            height: '100vh',
            backgroundColor: 'var(--bg-secondary)',
            borderLeft: '1px solid var(--border-medium)',
            boxShadow: '-10px 0 40px rgba(0, 0, 0, 0.7)',
            zIndex: 100,
            display: 'flex',
            flexDirection: 'column',
            animation: 'slideIn 0.25s ease-out',
          }}
        >
          {/* Drawer Header */}
          <div
            style={{
              padding: '20px 24px',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: 'rgba(0, 0, 0, 0.2)',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '1.2rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--dell-blue-light)' }}>
                  {selectedIncident.incident_id}
                </span>
                <SeverityBadge severity={selectedIncident.severity} isSynthetic={selectedIncident.is_synthetic} />
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                Threat Actor: <span className="font-mono" style={{ color: '#ffffff' }}>{selectedIncident.src_ip}</span>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => handleDownloadPdf(selectedIncident.incident_id)}
                disabled={pdfDownloading}
                title="Download Forensic PDF Report"
              >
                <Download size={14} />
                <span>{pdfDownloading ? 'Exporting PDF...' : 'PDF Report'}</span>
              </button>
              <button
                className="btn btn-secondary btn-sm"
                style={{ padding: '6px' }}
                onClick={() => setSelectedIncident(null)}
              >
                <X size={18} />
              </button>
            </div>
          </div>

          {/* Drawer Body */}
          <div style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>
            {/* Meta Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '20px' }}>
              <div style={{ background: 'var(--bg-input)', padding: '12px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Risk Score</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: Number(selectedIncident.risk_score || 0) >= 8.0 ? '#ef4444' : Number(selectedIncident.risk_score || 0) >= 6.0 ? '#f97316' : '#38bdf8' }}>
                  {Number(selectedIncident.risk_score || 0).toFixed(1)} <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>/ 10.0</span>
                </div>
              </div>

              <div style={{ background: 'var(--bg-input)', padding: '12px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Correlated Flows</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#ffffff' }}>
                  {selectedIncident.alert_count}
                </div>
              </div>
            </div>

            {/* Sequence Analysis */}
            <div style={{ marginBottom: '24px' }}>
              <h4 style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Activity size={15} color="var(--dell-blue-light)" />
                <span>Attack Progression Analysis</span>
              </h4>
              <div style={{ background: 'var(--bg-input)', padding: '14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {selectedIncident.threat_pattern || selectedIncident.sequence_description || 'Telemetry indicates homogeneous single-stage attack pattern.'}
              </div>
            </div>

            {/* Ingested Alerts Table */}
            <div>
              <h4 style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Layers size={15} color="var(--dell-blue-light)" />
                <span>Correlated Alert Flows ({selectedIncident.alerts?.length || selectedIncident.alert_count})</span>
              </h4>

              <div className="soc-table-wrapper" style={{ maxHeight: '350px', overflowY: 'auto' }}>
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Target</th>
                      <th>Port</th>
                      <th>Vector</th>
                      <th>Conf</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(selectedIncident.alerts || []).map((alt, idx) => (
                      <tr key={idx}>
                        <td className="font-mono" style={{ fontSize: '0.72rem' }}>
                          {alt.timestamp ? new Date(alt.timestamp).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td className="font-mono" style={{ fontSize: '0.75rem' }}>
                          {alt.dst_ip}
                        </td>
                        <td className="font-mono" style={{ fontSize: '0.75rem' }}>
                          {alt.dst_port}
                        </td>
                        <td>
                          <span style={{ fontSize: '0.7rem', padding: '1px 5px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '3px' }}>
                            {alt.label}
                          </span>
                        </td>
                        <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-accent)' }}>
                          {(alt.confidence * 100).toFixed(0)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Jump to Report button */}
            <div style={{ marginTop: '24px' }}>
              <button
                className="btn btn-primary"
                style={{ width: '100%' }}
                onClick={() => navigate('/reports', { state: { incidentId: selectedIncident.incident_id } })}
              >
                <FileText size={16} />
                <span>View Full Executive Incident Report</span>
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes slideIn {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
      `}</style>
    </div>
  );
};

export default Incidents;
