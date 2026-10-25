import React from 'react';

export const MetricCard = ({ title, value, subtitle, icon: Icon, color = 'blue', trend }) => {
  const colorMap = {
    blue: {
      border: 'rgba(0, 153, 230, 0.3)',
      text: '#38bdf8',
      bgIcon: 'rgba(0, 125, 184, 0.15)',
    },
    red: {
      border: 'rgba(239, 68, 68, 0.35)',
      text: '#f87171',
      bgIcon: 'rgba(239, 68, 68, 0.15)',
    },
    orange: {
      border: 'rgba(249, 115, 22, 0.35)',
      text: '#fb923c',
      bgIcon: 'rgba(249, 115, 22, 0.15)',
    },
    yellow: {
      border: 'rgba(234, 179, 8, 0.35)',
      text: '#facc15',
      bgIcon: 'rgba(234, 179, 8, 0.15)',
    },
    green: {
      border: 'rgba(34, 197, 94, 0.35)',
      text: '#4ade80',
      bgIcon: 'rgba(34, 197, 94, 0.15)',
    },
    purple: {
      border: 'rgba(168, 85, 247, 0.35)',
      text: '#c084fc',
      bgIcon: 'rgba(168, 85, 247, 0.15)',
    },
  };

  const currentTheme = colorMap[color] || colorMap.blue;

  return (
    <div
      className="soc-card"
      style={{
        padding: '20px 22px',
        borderLeft: `3px solid ${currentTheme.text}`,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            {title}
          </span>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            {value}
          </div>
        </div>
        {Icon && (
          <div
            style={{
              padding: '10px',
              borderRadius: 'var(--radius-md)',
              backgroundColor: currentTheme.bgIcon,
              color: currentTheme.text,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Icon size={22} />
          </div>
        )}
      </div>

      {(subtitle || trend) && (
        <div style={{ marginTop: '12px', fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
          {trend && <span style={{ color: currentTheme.text, fontWeight: 600 }}>{trend}</span>}
          <span>{subtitle}</span>
        </div>
      )}
    </div>
  );
};

export default MetricCard;
