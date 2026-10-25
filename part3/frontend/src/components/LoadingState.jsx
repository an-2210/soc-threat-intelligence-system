import React from 'react';
import { Loader2 } from 'lucide-react';

export const LoadingState = ({ message = 'Loading security telemetry...' }) => {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '60px 20px',
        color: 'var(--text-secondary)',
      }}
    >
      <Loader2
        size={36}
        style={{
          animation: 'spin 1.2s linear infinite',
          color: 'var(--dell-blue-light)',
          marginBottom: '16px',
        }}
      />
      <span style={{ fontSize: '0.9rem', letterSpacing: '0.02em' }}>{message}</span>
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default LoadingState;
