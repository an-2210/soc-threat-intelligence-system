import React from 'react';
import { RefreshCw, Clock, Sliders } from 'lucide-react';

export const Topbar = ({
  title,
  subtitle,
  timeWindow,
  setTimeWindow,
  onRefresh,
  isRefreshing,
  lastUpdated,
  showTimeControls = true,
}) => {
  const windowOptions = [
    { label: '5 min', value: 5 },
    { label: '15 min (Standard)', value: 15 },
    { label: '30 min', value: 30 },
    { label: '60 min', value: 60 },
  ];

  return (
    <header
      style={{
        height: '70px',
        backgroundColor: 'rgba(13, 19, 34, 0.85)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 32px',
        position: 'sticky',
        top: 0,
        zIndex: 40,
      }}
    >
      <div>
        <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '2px' }}>
            {subtitle}
          </p>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {showTimeControls && setTimeWindow && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-card-subtle)', padding: '5px 10px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <Sliders size={14} color="var(--text-muted)" />
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Correlation Window:</span>
            <select
              value={timeWindow}
              onChange={(e) => setTimeWindow(Number(e.target.value))}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--dell-blue-light)',
                fontSize: '0.8rem',
                fontWeight: 600,
                outline: 'none',
                cursor: 'pointer',
              }}
            >
              {windowOptions.map((opt) => (
                <option key={opt.value} value={opt.value} style={{ background: '#0d1322', color: '#ffffff' }}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        )}

        {lastUpdated && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <Clock size={13} />
            <span>Updated: {lastUpdated.toLocaleTimeString()}</span>
          </div>
        )}

        {onRefresh && (
          <button
            className="btn btn-secondary btn-sm"
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh Security Telemetry"
          >
            <RefreshCw
              size={14}
              style={{
                animation: isRefreshing ? 'spin 1s linear infinite' : 'none',
              }}
            />
            <span>Refresh</span>
          </button>
        )}
      </div>
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </header>
  );
};

export default Topbar;
