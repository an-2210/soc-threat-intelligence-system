import React, { useState, useEffect } from 'react';
import {
  Radio,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Database,
  Cpu,
  Layers,
  ArrowUpDown,
} from 'lucide-react';
import api from '../api/api';
import SeverityBadge from '../components/SeverityBadge';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export const Telemetry = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [totalCount, setTotalCount] = useState(0);

  // Filters
  const [srcIpFilter, setSrcIpFilter] = useState('');
  const [labelFilter, setLabelFilter] = useState('');
  const [originFilter, setOriginFilter] = useState(''); // '', 'live', 'synthetic'
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      setError(null);

      const params = {
        limit,
        offset,
      };

      if (srcIpFilter.trim()) params.src_ip = srcIpFilter.trim();
      if (labelFilter) params.label = labelFilter;
      if (originFilter === 'synthetic') params.is_synthetic = true;
      if (originFilter === 'live') params.is_synthetic = false;

      const res = await api.getAlerts(params);
      setAlerts(res.alerts);
      setTotalCount(res.totalCount);
    } catch (err) {
      console.error('Failed to load telemetry alerts:', err);
      setError(err.response?.data?.detail || err.message || 'Error querying telemetry alerts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [offset, limit, labelFilter, originFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setOffset(0);
    loadAlerts();
  };

  const totalPages = Math.ceil(totalCount / limit) || 1;
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <div className="page-wrapper">
      {/* Top Filter Bar */}
      <div
        className="soc-card"
        style={{
          padding: '20px 24px',
          marginBottom: '24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div className="soc-card-title">
              <Radio size={18} color="var(--dell-blue-light)" />
              <span>Network Intrusion Telemetry Feed</span>
            </div>
            <div className="soc-card-subtitle">
              Inspect raw flow events, ML model inference confidences, and adversary seeds
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Page Size:</span>
            <select
              className="form-select"
              style={{ width: '80px', padding: '6px 8px', fontSize: '0.8rem' }}
              value={limit}
              onChange={(e) => {
                setLimit(Number(e.target.value));
                setOffset(0);
              }}
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>

        {/* Filter Inputs Grid */}
        <form onSubmit={handleSearchSubmit}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
            {/* Source IP */}
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Filter Source IP</label>
              <div style={{ position: 'relative' }}>
                <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  className="form-input font-mono"
                  style={{ paddingLeft: '32px' }}
                  placeholder="e.g. 203.0.113.11"
                  value={srcIpFilter}
                  onChange={(e) => setSrcIpFilter(e.target.value)}
                />
              </div>
            </div>

            {/* Attack Vector */}
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Attack Vector / Label</label>
              <select
                className="form-select"
                value={labelFilter}
                onChange={(e) => {
                  setLabelFilter(e.target.value);
                  setOffset(0);
                }}
              >
                <option value="">All Vectors</option>
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

            {/* Telemetry Origin */}
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Detection Origin</label>
              <select
                className="form-select"
                value={originFilter}
                onChange={(e) => {
                  setOriginFilter(e.target.value);
                  setOffset(0);
                }}
              >
                <option value="">All Origins (Live ML + Synthetic)</option>
                <option value="live">Live ML Detections Only</option>
                <option value="synthetic">Synthetic Test Seeds Only</option>
              </select>
            </div>

            {/* Submit Filter Button */}
            <div style={{ display: 'flex', alignItems: 'flex-end' }}>
              <button type="submit" className="btn btn-primary" style={{ width: '100%', height: '40px' }}>
                <Filter size={15} />
                <span>Apply Filters</span>
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Main Alert Feed Table */}
      {loading && !alerts.length ? (
        <LoadingState message="Fetching network telemetry records from SQLite database..." />
      ) : error ? (
        <ErrorState title="Telemetry Error" error={error} onRetry={loadAlerts} />
      ) : (
        <div className="soc-card">
          <div className="soc-card-header">
            <div>
              <div className="soc-card-title">Ingested Security Flows</div>
              <div className="soc-card-subtitle">
                Displaying flows {offset + 1} - {Math.min(offset + limit, totalCount)} of {totalCount} total records
              </div>
            </div>

            {/* Pagination buttons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Page {currentPage} of {totalPages}
              </span>
              <button
                className="btn btn-secondary btn-sm"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - limit))}
              >
                <ChevronLeft size={14} />
              </button>
              <button
                className="btn btn-secondary btn-sm"
                disabled={offset + limit >= totalCount}
                onClick={() => setOffset(offset + limit)}
              >
                <ChevronRight size={14} />
              </button>
            </div>
          </div>

          <div className="soc-table-wrapper">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source (Origin)</th>
                  <th>Destination (Target)</th>
                  <th>Proto</th>
                  <th>Classification Vector</th>
                  <th>ML Confidence</th>
                  <th>Severity</th>
                  <th>Origin Type</th>
                  <th>Source Pipeline</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan="9" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                      No telemetry alerts match the selected criteria.
                    </td>
                  </tr>
                ) : (
                  alerts.map((alt) => (
                    <tr key={alt.id || alt.timestamp + alt.src_ip + alt.src_port}>
                      <td>
                        <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                          {alt.timestamp ? new Date(alt.timestamp).toLocaleString() : 'N/A'}
                        </span>
                      </td>
                      <td>
                        <span className="font-mono" style={{ color: '#ffffff', fontWeight: 600 }}>
                          {alt.src_ip}
                        </span>
                        <span className="font-mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                          :{alt.src_port}
                        </span>
                      </td>
                      <td>
                        <span className="font-mono" style={{ color: '#ffffff' }}>
                          {alt.dst_ip}
                        </span>
                        <span className="font-mono" style={{ color: 'var(--text-accent)', fontSize: '0.75rem' }}>
                          :{alt.dst_port}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                          {alt.protocol}
                        </span>
                      </td>
                      <td>
                        <span
                          style={{
                            fontSize: '0.75rem',
                            padding: '3px 7px',
                            borderRadius: '4px',
                            background: 'rgba(255, 255, 255, 0.08)',
                            color: '#ffffff',
                            fontWeight: 500,
                          }}
                        >
                          {alt.label}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span className="font-mono" style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-accent)' }}>
                            {(alt.confidence * 100).toFixed(1)}%
                          </span>
                        </div>
                      </td>
                      <td>
                        <SeverityBadge severity={alt.severity} />
                      </td>
                      <td>
                        {alt.is_synthetic ? (
                          <span className="badge badge-synthetic">SYNTHETIC</span>
                        ) : (
                          <span className="badge badge-live">LIVE ML</span>
                        )}
                      </td>
                      <td>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {alt.source || 'NIDS-Pipeline'}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default Telemetry;
