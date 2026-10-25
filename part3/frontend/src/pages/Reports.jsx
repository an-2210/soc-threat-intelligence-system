import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  FileText,
  Download,
  Flame,
  Shield,
  Activity,
  CheckCircle,
  Copy,
  Printer,
  Sparkles,
  Layers,
} from 'lucide-react';
import api from '../api/api';
import SeverityBadge from '../components/SeverityBadge';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export const Reports = ({ timeWindow }) => {
  const location = useLocation();
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(
    location.state?.incidentId || ''
  );
  const [loadingIncidents, setLoadingIncidents] = useState(true);

  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [reportError, setReportError] = useState(null);

  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [copiedSection, setCopiedSection] = useState(null);

  // Load available incidents
  useEffect(() => {
    const loadIncidents = async () => {
      try {
        setLoadingIncidents(true);
        const res = await api.getIncidents(timeWindow);
        setIncidents(res);
        if (!selectedIncidentId && res.length > 0) {
          setSelectedIncidentId(res[0].incident_id);
        }
      } catch (err) {
        console.error('Failed to load incidents for reports:', err);
      } finally {
        setLoadingIncidents(false);
      }
    };
    loadIncidents();
  }, [timeWindow]);

  // When selectedIncidentId changes, trigger report generation
  useEffect(() => {
    if (selectedIncidentId) {
      handleGenerateReport(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const handleGenerateReport = async (incId) => {
    const id = incId || selectedIncidentId;
    if (!id) return;
    try {
      setGeneratingReport(true);
      setReportError(null);
      const res = await api.generateReport(id, timeWindow);
      setReportData(res);
    } catch (err) {
      console.error('Failed to generate report:', err);
      setReportError(err.response?.data?.detail || err.message || 'Error generating report');
    } finally {
      setGeneratingReport(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!selectedIncidentId) return;
    try {
      setDownloadingPdf(true);
      const blob = await api.downloadPdfBlob(selectedIncidentId, timeWindow);
      const url = window.URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${selectedIncidentId}_SOC_Report.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error('Failed to download PDF:', err);
      alert('Could not download PDF report: ' + (err.response?.data?.detail || err.message));
    } finally {
      setDownloadingPdf(false);
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(key);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const currentIncident = incidents.find((i) => i.incident_id === selectedIncidentId);

  return (
    <div className="page-wrapper">
      {/* Top Selector Panel */}
      <div
        className="soc-card"
        style={{
          padding: '20px 24px',
          marginBottom: '24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div>
            <div className="soc-card-title">
              <FileText size={18} color="var(--dell-blue-light)" />
              <span>Incident Forensic & Executive Reporting</span>
            </div>
            <div className="soc-card-subtitle">
              Generates executive summaries, forensic timelines, and PDF deliverables
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Target Incident:</span>
            <select
              className="form-select font-mono"
              style={{ width: '220px', padding: '7px 12px', fontSize: '0.85rem', fontWeight: 600 }}
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              disabled={loadingIncidents || incidents.length === 0}
            >
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.incident_id} — {inc.src_ip} ({inc.severity})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            className="btn btn-secondary"
            onClick={() => handleGenerateReport()}
            disabled={generatingReport || !selectedIncidentId}
          >
            <Sparkles size={15} color="var(--dell-blue-light)" />
            <span>{generatingReport ? 'Analyzing...' : 'Regenerate Analysis'}</span>
          </button>

          <button
            className="btn btn-primary"
            onClick={handleDownloadPdf}
            disabled={downloadingPdf || !selectedIncidentId || !reportData}
          >
            <Download size={15} />
            <span>{downloadingPdf ? 'Generating PDF...' : 'Download PDF Report'}</span>
          </button>
        </div>
      </div>

      {/* Main Report View */}
      {generatingReport ? (
        <LoadingState message="Synthesizing multi-vector telemetry into executive incident report..." />
      ) : reportError ? (
        <ErrorState title="Report Generation Error" error={reportError} onRetry={() => handleGenerateReport()} />
      ) : !reportData ? (
        <div className="soc-card" style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
          Please select an incident above to generate its report.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Metadata Card */}
          <div
            className="soc-card"
            style={{
              padding: '20px 24px',
              backgroundColor: 'var(--bg-card-subtle)',
              borderLeft: '4px solid var(--dell-blue)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '1.3rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#ffffff' }}>
                    {reportData.metadata?.incident_id || reportData.incident_id || selectedIncidentId}
                  </span>
                  <SeverityBadge severity={currentIncident?.severity || 'HIGH'} isSynthetic={currentIncident?.is_synthetic} />
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Source IP: <span className="font-mono" style={{ color: 'var(--text-accent)' }}>{currentIncident?.src_ip || 'N/A'}</span> | 
                  Risk Score: <span className="font-mono" style={{ color: '#ffffff', fontWeight: 600 }}>{Number(currentIncident?.risk_score || 0).toFixed(1)}/10.0</span> | 
                  Flow Volume: <span className="font-mono" style={{ color: '#ffffff' }}>{currentIncident?.alert_count || 0} alerts</span>
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>
                  Local Deterministic SOC Heuristic Engine
                </span>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Report Generated: {new Date().toLocaleTimeString()}
                </div>
              </div>
            </div>
          </div>

          {/* Section 1: What Happened */}
          <div className="soc-card">
            <div className="soc-card-header">
              <div className="soc-card-title">
                <Flame size={18} color="#f97316" />
                <span>1. Executive Summary & Attack Nature</span>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => copyToClipboard(reportData.what, 'what')}
              >
                <Copy size={13} />
                <span>{copiedSection === 'what' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="soc-card-body" style={{ fontSize: '0.9rem', lineHeight: 1.6, color: 'var(--text-primary)', whiteSpace: 'pre-line' }}>
              {reportData.what}
            </div>
          </div>

          {/* Section 2: Evidence */}
          <div className="soc-card">
            <div className="soc-card-header">
              <div className="soc-card-title">
                <Layers size={18} color="var(--dell-blue-light)" />
                <span>2. Observed Forensic Telemetry & Evidence</span>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => copyToClipboard(reportData.evidence, 'evidence')}
              >
                <Copy size={13} />
                <span>{copiedSection === 'evidence' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="soc-card-body" style={{ fontSize: '0.9rem', lineHeight: 1.6, color: 'var(--text-primary)', whiteSpace: 'pre-line' }}>
              {reportData.evidence}
            </div>
          </div>

          {/* Section 3: Severity */}
          <div className="soc-card">
            <div className="soc-card-header">
              <div className="soc-card-title">
                <Shield size={18} color="#ef4444" />
                <span>3. Threat Severity & Impact Assessment</span>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => copyToClipboard(reportData.severity, 'severity')}
              >
                <Copy size={13} />
                <span>{copiedSection === 'severity' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="soc-card-body" style={{ fontSize: '0.9rem', lineHeight: 1.6, color: 'var(--text-primary)', whiteSpace: 'pre-line' }}>
              {reportData.severity}
            </div>
          </div>

          {/* Section 4: Action Plan */}
          <div className="soc-card">
            <div className="soc-card-header">
              <div className="soc-card-title">
                <CheckCircle size={18} color="#22c55e" />
                <span>4. Prescribed Containment & Remediation Roadmap</span>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => copyToClipboard(reportData.action, 'action')}
              >
                <Copy size={13} />
                <span>{copiedSection === 'action' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="soc-card-body" style={{ fontSize: '0.9rem', lineHeight: 1.6, color: 'var(--text-primary)', whiteSpace: 'pre-line' }}>
              {reportData.action}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
