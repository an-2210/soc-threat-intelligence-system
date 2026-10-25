import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Flame,
  Radio,
  Cpu,
  Layers,
  Crosshair,
  ArrowRight,
  TrendingUp,
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend,
} from 'recharts';
import api from '../api/api';
import MetricCard from '../components/MetricCard';
import SeverityBadge from '../components/SeverityBadge';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

const CHART_COLORS = ['#007db8', '#0ea5e9', '#06b6d4', '#f97316', '#ef4444', '#a855f7', '#eab308', '#22c55e'];

export const Overview = ({ timeWindow }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getOverviewStats(timeWindow);
      setData(res);
    } catch (err) {
      console.error('Failed to load overview data:', err);
      setError(err.response?.data?.detail || err.message || 'Error loading dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [timeWindow]);

  if (loading && !data) {
    return <LoadingState message="Aggregating SOC security metrics and incident telemetry..." />;
  }

  if (error && !data) {
    return <ErrorState title="Failed to Load SOC Overview" error={error} onRetry={loadData} />;
  }

  // Resilient data extractions supporting both canonical backend names and aliases
  const totalAlerts = data?.total_alerts ?? 0;
  const liveMlAlerts = data?.live_count ?? data?.live_ml_alerts ?? 0;
  const syntheticAlerts = data?.synthetic_count ?? data?.synthetic_alerts ?? 0;
  const correlatedIncidents = data?.correlated_incidents ?? 0;

  // Severity distributions
  const sevDist = data?.severity_distribution || data?.incident_severity_distribution || {};
  const criticalCount = data?.critical_incidents ?? sevDist.CRITICAL ?? 0;
  const highCount = data?.high_incidents ?? sevDist.HIGH ?? 0;
  const mediumCount = data?.medium_incidents ?? sevDist.MEDIUM ?? 0;
  const lowCount = data?.low_incidents ?? sevDist.LOW ?? 0;
  const criticalHighIncidents = criticalCount + highCount;

  // Threat Vector Distribution (Anomaly, BruteForce, DoS, PortScan, etc.)
  const labelObj = data?.label_counts || data?.label_distribution || {};
  const vectorChartData = Object.entries(labelObj).map(([name, value]) => ({
    name,
    value,
  }));

  // Top Attacking Source IPs
  const rawTopIps = data?.top_ips || data?.top_sources || [];
  const topSourcesData = rawTopIps.map((item) => ({
    ip: item.src_ip || 'Unknown',
    alerts: item.count || 0,
  }));

  // Top Targeted Destination Hosts
  const rawTopDests = data?.top_destinations || [];
  const topDestsData = rawTopDests.map((item) => ({
    ip: item.dst_ip || 'Unknown',
    alerts: item.count || 0,
  }));

  // Incident Threat Classification data
  const severityChartData = [
    { level: 'CRITICAL', count: criticalCount, fill: '#ef4444' },
    { level: 'HIGH', count: highCount, fill: '#f97316' },
    { level: 'MEDIUM', count: mediumCount, fill: '#eab308' },
    { level: 'LOW', count: lowCount, fill: '#22c55e' },
  ];

  const recentIncidentsList = data?.recent_incidents || [];

  return (
    <div className="page-wrapper">
      {/* 6 Metric KPI Cards */}
      <div className="metrics-grid">
        <MetricCard
          title="Total Ingested Alerts"
          value={totalAlerts}
          subtitle="Validated flows in DB"
          icon={Radio}
          color="blue"
        />
        <MetricCard
          title="Correlated Incidents"
          value={correlatedIncidents}
          subtitle={`Grouped in ${timeWindow}m window`}
          icon={Flame}
          color="red"
        />
        <MetricCard
          title="Critical / High Incidents"
          value={criticalHighIncidents}
          subtitle="Immediate containment required"
          icon={ShieldAlert}
          color="orange"
        />
        <MetricCard
          title="Live ML Detections"
          value={liveMlAlerts}
          subtitle="RandomForest + XGBoost"
          icon={Cpu}
          color="purple"
        />
        <MetricCard
          title="Synthetic Threat Seeds"
          value={syntheticAlerts}
          subtitle="Simulated adversary alerts"
          icon={Layers}
          color="yellow"
        />
        <MetricCard
          title="Attacking Threat Actors"
          value={topSourcesData.length}
          subtitle="Unique hostile source IPs"
          icon={Crosshair}
          color="green"
        />
      </div>

      {/* 4 Interactive Recharts */}
      <div className="charts-grid-2">
        {/* 1. Vector Distribution */}
        <div className="soc-card">
          <div className="soc-card-header">
            <div>
              <div className="soc-card-title">Threat Vector Distribution</div>
              <div className="soc-card-subtitle">Breakdown by intrusion classification label</div>
            </div>
          </div>
          <div className="soc-card-body" style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {vectorChartData.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>No threat vectors recorded</div>
            ) : (
              <ResponsiveContainer width="100%" height={260} minWidth={100}>
                <PieChart>
                  <Pie
                    data={vectorChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={4}
                    dataKey="value"
                    label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                    labelLine={false}
                  >
                    {vectorChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#11192e',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                      color: '#f1f5f9',
                    }}
                    itemStyle={{ color: '#38bdf8' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* 2. Top Attacker IPs */}
        <div className="soc-card">
          <div className="soc-card-header">
            <div>
              <div className="soc-card-title">Top Hostile Source IPs</div>
              <div className="soc-card-subtitle">Highest volume attacking origins</div>
            </div>
          </div>
          <div className="soc-card-body" style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {topSourcesData.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>No source IP telemetry found</div>
            ) : (
              <ResponsiveContainer width="100%" height={260} minWidth={100}>
                <BarChart data={topSourcesData} margin={{ top: 10, right: 20, left: 0, bottom: 25 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" />
                  <XAxis dataKey="ip" stroke="#64748b" tick={{ fontSize: 11 }} interval={0} angle={-15} textAnchor="end" />
                  <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#11192e',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="alerts" fill="#0ea5e9" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* 3. Top Target Hosts */}
        <div className="soc-card">
          <div className="soc-card-header">
            <div>
              <div className="soc-card-title">Top Targeted Destination Hosts</div>
              <div className="soc-card-subtitle">Internal enterprise assets under attack</div>
            </div>
          </div>
          <div className="soc-card-body" style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {topDestsData.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>No destination host telemetry found</div>
            ) : (
              <ResponsiveContainer width="100%" height={260} minWidth={100}>
                <BarChart data={topDestsData} margin={{ top: 10, right: 20, left: 0, bottom: 25 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" />
                  <XAxis dataKey="ip" stroke="#64748b" tick={{ fontSize: 11 }} interval={0} angle={-15} textAnchor="end" />
                  <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#11192e',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="alerts" fill="#a855f7" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* 4. Incident Severity Breakdown */}
        <div className="soc-card">
          <div className="soc-card-header">
            <div>
              <div className="soc-card-title">Incident Threat Classification</div>
              <div className="soc-card-subtitle">Correlated incidents by assessed severity level</div>
            </div>
          </div>
          <div className="soc-card-body" style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {severityChartData.every((item) => item.count === 0) ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>No active incident classifications</div>
            ) : (
              <ResponsiveContainer width="100%" height={260} minWidth={100}>
                <BarChart data={severityChartData} margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" />
                  <XAxis dataKey="level" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#11192e',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Correlated Incidents Summary Table */}
      <div className="soc-card">
        <div className="soc-card-header">
          <div>
            <div className="soc-card-title">
              <Flame size={20} color="#f97316" />
              <span>Recent Correlated Security Incidents</span>
            </div>
            <div className="soc-card-subtitle">
              Showing top correlated clusters in the current {timeWindow}-minute temporal correlation window
            </div>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={() => navigate('/incidents')}>
            <span>View All Incidents</span>
            <ArrowRight size={14} />
          </button>
        </div>

        <div className="soc-table-wrapper">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Threat Actor IP</th>
                <th>Alert Volume</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Attack Vectors</th>
                <th>Target Scope</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {recentIncidentsList.length === 0 ? (
                <tr>
                  <td colSpan="8" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                    No security incidents correlated in the current window.
                  </td>
                </tr>
              ) : (
                recentIncidentsList.map((inc) => {
                  const score = Number(inc.risk_score || 0);
                  const isCritical = score >= 8.0;
                  const isHigh = score >= 6.0 && score < 8.0;
                  const isMedium = score >= 3.5 && score < 6.0;
                  const scoreColor = isCritical ? '#ef4444' : isHigh ? '#f97316' : isMedium ? '#eab308' : '#22c55e';
                  const incidentLabels = inc.labels && inc.labels.length > 0
                    ? inc.labels
                    : inc.threat_pattern
                    ? [inc.threat_pattern.slice(0, 25)]
                    : ['Security Alert'];

                  return (
                    <tr key={inc.incident_id}>
                      <td>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--dell-blue-light)' }}>
                          {inc.incident_id}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontFamily: 'var(--font-mono)', color: '#ffffff' }}>{inc.src_ip}</span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 600 }}>{inc.alert_count}</span>
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginLeft: '4px' }}>alerts</span>
                      </td>
                      <td>
                        <SeverityBadge severity={inc.severity} isSynthetic={inc.is_synthetic} />
                      </td>
                      <td>
                        <span
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontWeight: 700,
                            color: scoreColor,
                          }}
                        >
                          {score.toFixed(1)}
                        </span>
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}> / 10.0</span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {incidentLabels.slice(0, 3).map((lbl, idx) => (
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
                      <td>
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                          {inc.target_count || 1} target{(inc.target_count || 1) > 1 ? 's' : ''}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                          onClick={() => navigate('/incidents')}
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Overview;
