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
  Cpu,
  Server,
  Terminal,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  AlertTriangle,
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

  // LLM Engine selection & status
  const [llmStatus, setLlmStatus] = useState(null);
  const [selectedEngine, setSelectedEngine] = useState('auto'); // auto, ollama, gemini, heuristic
  const [selectedModel, setSelectedModel] = useState('');
  const [showOllamaGuide, setShowOllamaGuide] = useState(false);

  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [reportError, setReportError] = useState(null);

  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [copiedSection, setCopiedSection] = useState(null);

  // Load LLM status
  const loadLlmStatus = async () => {
    try {
      const status = await api.getLLMStatus();
      setLlmStatus(status);
      if (status.ollama?.default_model && !selectedModel) {
        setSelectedModel(status.ollama.default_model);
      }
    } catch (err) {
      console.warn('Failed to load LLM status:', err);
    }
  };

  useEffect(() => {
    loadLlmStatus();
  }, []);

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
      handleGenerateReport(selectedIncidentId, selectedEngine, selectedModel);
    }
  }, [selectedIncidentId]);

  const handleGenerateReport = async (incId, engine = selectedEngine, model = selectedModel) => {
    const id = incId || selectedIncidentId;
    if (!id) return;
    try {
      setGeneratingReport(true);
      setReportError(null);
      const res = await api.generateReport(id, timeWindow, engine, model || undefined);
      setReportData(res);
      // Refresh LLM status in background
      loadLlmStatus();
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
      const blob = await api.downloadPdfBlob(selectedIncidentId, timeWindow, selectedEngine, selectedModel || undefined);
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

  // Render generator badge
  const renderGeneratorBadge = () => {
    const gen = reportData?.metadata?.generator || '';
    const fallback = reportData?.metadata?.fallback_used;

    if (gen.toLowerCase().includes('ollama')) {
      const modelName = reportData?.metadata?.model || gen.replace('ollama/', '');
      return (
        <span
          className="badge"
          style={{
            backgroundColor: 'rgba(6, 182, 212, 0.15)',
            color: '#06b6d4',
            border: '1px solid rgba(6, 182, 212, 0.4)',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.75rem',
            padding: '4px 8px',
          }}
        >
          <Cpu size={13} />
          <span>Local Ollama ({modelName})</span>
        </span>
      );
    }

    if (gen.toLowerCase().includes('gemini')) {
      return (
        <span
          className="badge"
          style={{
            backgroundColor: 'rgba(59, 130, 246, 0.15)',
            color: '#60a5fa',
            border: '1px solid rgba(59, 130, 246, 0.4)',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.75rem',
            padding: '4px 8px',
          }}
        >
          <Sparkles size={13} />
          <span>Google Gemini (1.5-flash)</span>
        </span>
      );
    }

    return (
      <span
        className="badge"
        style={{
          backgroundColor: 'rgba(100, 116, 139, 0.15)',
          color: '#94a3b8',
          border: '1px solid rgba(100, 116, 139, 0.4)',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '0.75rem',
          padding: '4px 8px',
        }}
      >
        <Shield size={13} />
        <span>Deterministic SOC Heuristic Engine</span>
        {fallback && (
          <span
            style={{
              marginLeft: '4px',
              fontSize: '0.65rem',
              color: '#f59e0b',
              backgroundColor: 'rgba(245, 158, 11, 0.15)',
              padding: '1px 5px',
              borderRadius: '3px',
            }}
          >
            (Fallback)
          </span>
        )}
      </span>
    );
  };

  return (
    <div className="page-wrapper">
      {/* Top Selector Panel */}
      <div
        className="soc-card"
        style={{
          padding: '20px 24px',
          marginBottom: '16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
          <div>
            <div className="soc-card-title">
              <FileText size={18} color="var(--dell-blue-light)" />
              <span>Incident Forensic & Executive Reporting</span>
            </div>
            <div className="soc-card-subtitle">
              Generates executive summaries, forensic timelines, and PDF deliverables
            </div>
          </div>

          {/* Incident Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Target:</span>
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

          {/* LLM Engine Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Engine:</span>
            <select
              className="form-select"
              style={{ width: '210px', padding: '7px 12px', fontSize: '0.85rem' }}
              value={selectedEngine}
              onChange={(e) => {
                const newEng = e.target.value;
                setSelectedEngine(newEng);
                handleGenerateReport(selectedIncidentId, newEng, selectedModel);
              }}
            >
              <option value="auto">
                Auto (Best Available)
              </option>
              <option value="ollama">
                Ollama Local LLM {llmStatus?.ollama?.available ? '✓' : '(Offline)'}
              </option>
              <option value="gemini">
                Google Gemini {llmStatus?.gemini?.available ? '✓' : '(No Key)'}
              </option>
              <option value="heuristic">Deterministic Offline Engine</option>
            </select>
          </div>

          {/* Ollama Model Selector if available */}
          {llmStatus?.ollama?.available && llmStatus?.ollama?.models?.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Model:</span>
              <select
                className="form-select font-mono"
                style={{ width: '160px', padding: '7px 12px', fontSize: '0.82rem' }}
                value={selectedModel}
                onChange={(e) => {
                  const m = e.target.value;
                  setSelectedModel(m);
                  if (selectedEngine === 'ollama') {
                    handleGenerateReport(selectedIncidentId, 'ollama', m);
                  }
                }}
              >
                {llmStatus.ollama.models.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            className="btn btn-secondary"
            onClick={() => handleGenerateReport()}
            disabled={generatingReport || !selectedIncidentId}
            title="Re-run synthesis with chosen engine"
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

      {/* Ollama Setup / Status Callout */}
      {!llmStatus?.ollama?.available && (
        <div
          className="soc-card"
          style={{
            padding: '12px 18px',
            marginBottom: '20px',
            backgroundColor: 'rgba(15, 23, 42, 0.6)',
            border: '1px dashed var(--border-color)',
            borderRadius: '6px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Cpu size={16} color="#06b6d4" />
              <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                <strong>Want to use local private AI?</strong> Run{' '}
                <code style={{ color: '#38bdf8', backgroundColor: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                  ollama run llama3
                </code>{' '}
                on your system — the dashboard will auto-detect it without restarts.
              </span>
            </div>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setShowOllamaGuide(!showOllamaGuide)}
              style={{ fontSize: '0.72rem', padding: '3px 10px', display: 'flex', alignItems: 'center', gap: '4px' }}
            >
              <Terminal size={12} />
              <span>{showOllamaGuide ? 'Hide Guide' : 'Ollama Quickstart'}</span>
              {showOllamaGuide ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </button>
          </div>

          {showOllamaGuide && (
            <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid rgba(255,255,255,0.08)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <ol style={{ paddingLeft: '20px', lineHeight: 1.8, margin: 0 }}>
                <li>
                  Download and install Ollama from{' '}
                  <a href="https://ollama.com" target="_blank" rel="noreferrer" style={{ color: 'var(--dell-blue-light)', textDecoration: 'underline' }}>
                    ollama.com
                  </a>
                  .
                </li>
                <li>
                  Open your terminal / PowerShell and pull any model:
                  <div style={{ backgroundColor: 'rgba(0,0,0,0.4)', padding: '6px 12px', borderRadius: '4px', fontFamily: 'var(--font-mono)', color: '#38bdf8', margin: '6px 0' }}>
                    ollama run llama3
                    <span style={{ color: 'var(--text-muted)', marginLeft: '12px' }}># or: ollama run llama3.2 / mistral / phi3</span>
                  </div>
                </li>
                <li>
                  Click <strong>Regenerate Analysis</strong> above. The dashboard will automatically route report synthesis to your local Ollama engine with zero cloud leakage.
                </li>
              </ol>
            </div>
          )}
        </div>
      )}

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
                <div>{renderGeneratorBadge()}</div>
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
