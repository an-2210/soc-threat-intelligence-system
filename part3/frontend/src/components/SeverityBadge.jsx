import React from 'react';

export const SeverityBadge = ({ severity, isSynthetic = false }) => {
  const sev = (severity || 'INFO').toUpperCase();

  let badgeClass = 'badge-info';
  if (sev === 'CRITICAL') badgeClass = 'badge-critical';
  else if (sev === 'HIGH') badgeClass = 'badge-high';
  else if (sev === 'MEDIUM') badgeClass = 'badge-medium';
  else if (sev === 'LOW' || sev === 'BENIGN') badgeClass = 'badge-low';

  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
      <span className={`badge ${badgeClass}`}>{sev}</span>
      {isSynthetic && <span className="badge badge-synthetic">SYNTHETIC</span>}
    </div>
  );
};

export default SeverityBadge;
