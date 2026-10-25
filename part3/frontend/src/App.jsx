import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import api from './api/api';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Overview from './pages/Overview';
import SecurityCheck from './pages/SecurityCheck';
import Incidents from './pages/Incidents';
import Telemetry from './pages/Telemetry';
import Reports from './pages/Reports';

function AppLayout() {
  const location = useLocation();
  const [timeWindow, setTimeWindow] = useState(15);
  const [isOnline, setIsOnline] = useState(false);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [incidentCount, setIncidentCount] = useState(0);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Health and System Overview heartbeat
  const refreshSystemData = useCallback(async () => {
    try {
      setIsRefreshing(true);
      const [health, stats] = await Promise.all([
        api.checkHealth().catch(() => ({ status: 'down' })),
        api.getStats().catch(() => ({ total_alerts: 0 })),
      ]);

      const online = health.status === 'ok' || health.status === 'healthy';
      setIsOnline(online);
      setTotalAlerts(stats.total_alerts || health.alerts_in_db || 0);

      // Also get incident count in current window
      try {
        const incidents = await api.getIncidents(timeWindow);
        setIncidentCount(incidents.length);
      } catch (e) {
        // Fallback
      }

      setLastUpdated(new Date());
    } catch (err) {
      console.warn('System status heartbeat failed:', err);
      setIsOnline(false);
    } finally {
      setIsRefreshing(false);
    }
  }, [timeWindow]);

  useEffect(() => {
    refreshSystemData();
    const interval = setInterval(refreshSystemData, 15000);
    return () => clearInterval(interval);
  }, [refreshSystemData]);

  // Page titles and subtitles
  const getPageMeta = () => {
    switch (location.pathname) {
      case '/':
        return {
          title: 'SOC Executive Overview',
          subtitle: 'Live NIDS-CTI Threat Telemetry & Attack Surface Monitoring',
        };
      case '/security-check':
        return {
          title: 'Interactive Security Check',
          subtitle: 'Deep Threat Actor Analysis, Alert Ingestion & Syslog Parsing',
        };
      case '/incidents':
        return {
          title: 'Correlated Incidents',
          subtitle: 'Temporal Clustering & Multi-Stage Attack Progressions',
        };
      case '/telemetry':
        return {
          title: 'Telemetry Feed',
          subtitle: 'Raw Intrusion Alert Records, ML Classifications & Threat Seeds',
        };
      case '/reports':
        return {
          title: 'Incident Forensic Reports',
          subtitle: 'Automated Executive Briefings & ReportLab PDF Deliverables',
        };
      default:
        return {
          title: 'Dell SOC Platform',
          subtitle: 'Cyberthreat NIDS-CTI Defense Operations',
        };
    }
  };

  const { title, subtitle } = getPageMeta();

  return (
    <div className="app-container">
      {/* Navigation Sidebar */}
      <Sidebar
        isOnline={isOnline}
        totalAlerts={totalAlerts}
        incidentCount={incidentCount}
      />

      {/* Main Content Area */}
      <main className="main-content">
        <Topbar
          title={title}
          subtitle={subtitle}
          timeWindow={timeWindow}
          setTimeWindow={setTimeWindow}
          onRefresh={refreshSystemData}
          isRefreshing={isRefreshing}
          lastUpdated={lastUpdated}
          showTimeControls={location.pathname === '/' || location.pathname === '/incidents'}
        />

        <Routes>
          <Route path="/" element={<Overview timeWindow={timeWindow} />} />
          <Route
            path="/security-check"
            element={
              <SecurityCheck
                timeWindow={timeWindow}
                onAlertIngested={refreshSystemData}
              />
            }
          />
          <Route
            path="/incidents"
            element={
              <Incidents
                timeWindow={timeWindow}
                setTimeWindow={setTimeWindow}
              />
            }
          />
          <Route path="/telemetry" element={<Telemetry />} />
          <Route path="/reports" element={<Reports timeWindow={timeWindow} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout />
    </BrowserRouter>
  );
}
