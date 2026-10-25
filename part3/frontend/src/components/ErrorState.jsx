import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export const ErrorState = ({ title = 'Failed to load data', error, onRetry }) => {
  return (
    <div
      className="soc-card"
      style={{
        padding: '30px',
        border: '1px solid rgba(239, 68, 68, 0.4)',
        backgroundColor: 'rgba(239, 68, 68, 0.05)',
        textAlign: 'center',
        margin: '20px 0',
      }}
    >
      <div style={{ display: 'inline-flex', padding: '12px', borderRadius: '50%', background: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', marginBottom: '16px' }}>
        <AlertTriangle size={32} />
      </div>
      <h3 style={{ fontSize: '1.1rem', color: '#f87171', marginBottom: '8px' }}>{title}</h3>
      <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', maxWidth: '500px', margin: '0 auto 20px', fontFamily: 'var(--font-mono)' }}>
        {typeof error === 'string' ? error : error?.message || 'An unexpected communication error occurred with the SOC backend.'}
      </p>
      {onRetry && (
        <button className="btn btn-secondary" onClick={onRetry}>
          <RefreshCw size={15} />
          <span>Retry Operation</span>
        </button>
      )}
    </div>
  );
};

export default ErrorState;
