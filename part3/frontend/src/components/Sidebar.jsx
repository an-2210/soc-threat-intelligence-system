import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  Flame,
  Radio,
  FileText,
  Server,
  Activity,
  ShieldCheck,
} from 'lucide-react';

export const Sidebar = ({ isOnline, totalAlerts = 0, incidentCount = 0 }) => {
  const navItems = [
    { name: 'Overview', path: '/', icon: LayoutDashboard },
    { name: 'Security Check', path: '/security-check', icon: ShieldAlert },
    { name: 'Incidents', path: '/incidents', icon: Flame, badge: incidentCount > 0 ? incidentCount : null },
    { name: 'Telemetry', path: '/telemetry', icon: Radio, badge: totalAlerts > 0 ? totalAlerts : null },
    { name: 'Incident Reports', path: '/reports', icon: FileText },
  ];

  return (
    <aside
      style={{
        width: '260px',
        backgroundColor: 'var(--bg-secondary)',
        borderRight: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: '24px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        <div
          style={{
            width: '40px',
            height: '40px',
            borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, #007db8 0%, #0284c7 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(0, 125, 184, 0.4)',
            color: '#ffffff',
          }}
        >
          <ShieldCheck size={24} />
        </div>
        <div>
          <div style={{ fontSize: '1.05rem', fontWeight: 800, letterSpacing: '0.04em', color: '#ffffff' }}>
            DELL <span style={{ color: 'var(--dell-blue-light)' }}>SOC</span>
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Cyberthreat NIDS-CTI
          </div>
        </div>
      </div>

      {/* Navigation List */}
      <nav style={{ flex: 1, padding: '20px 12px', overflowY: 'auto' }}>
        <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '0 12px 10px' }}>
          Operations
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                style={({ isActive }) => ({
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '11px 14px',
                  borderRadius: 'var(--radius-md)',
                  textDecoration: 'none',
                  fontSize: '0.875rem',
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? '#ffffff' : 'var(--text-secondary)',
                  backgroundColor: isActive ? 'rgba(0, 125, 184, 0.18)' : 'transparent',
                  border: isActive ? '1px solid rgba(0, 153, 230, 0.35)' : '1px solid transparent',
                  transition: 'all 0.15s ease',
                })}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <Icon size={18} />
                  <span>{item.name}</span>
                </div>
                {item.badge !== null && item.badge !== undefined && (
                  <span
                    style={{
                      fontSize: '0.7rem',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600,
                      padding: '2px 7px',
                      borderRadius: '9999px',
                      background: 'rgba(255, 255, 255, 0.08)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </div>
      </nav>

      {/* Backend Status & System Info Panel */}
      <div
        style={{
          padding: '16px',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: 'rgba(0, 0, 0, 0.2)',
        }}
      >
        <div
          style={{
            backgroundColor: 'var(--bg-card-subtle)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            padding: '12px 14px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', fontWeight: 600 }}>
              <span className={`pulse-dot ${isOnline ? 'online' : 'offline'}`} />
              <span style={{ color: isOnline ? '#22c55e' : '#ef4444' }}>
                {isOnline ? 'Core API Online' : 'Core API Disconnected'}
              </span>
            </div>
            <Server size={14} color="var(--text-muted)" />
          </div>

          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
            <span>Backend Port</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>:8000</span>
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
            <span>Telemetry Records</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-accent)' }}>{totalAlerts}</span>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
