import React, { useState } from 'react';

interface PendingEscalation {
  id: string;
  agentId: string;
  command: string;
  riskReason: string;
  timestamp: string;
}

export const HitlApprovals: React.FC = () => {
  const [escalations, setEscalations] = useState<PendingEscalation[]>([
    {
      id: 'req-8841',
      agentId: 'agent-dev-01',
      command: 'rm -rf /var/db/backup',
      riskReason: 'P0 Dangerous command execution (Destructive file path operation)',
      timestamp: 'Just now',
    },
  ]);

  const handleAction = (id: string, decision: 'ALLOW_ONCE' | 'PERMANENT_ALLOW' | 'DENY') => {
    setEscalations((prev) => prev.filter((item) => item.id !== id));
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <h2>Human-in-the-Loop (HITL) Approvals</h2>
        <p className="subtitle">
          FR-304: Asynchronous authorization queue for intercepted dangerous commands across agent fleets.
        </p>
      </div>

      {escalations.length === 0 ? (
        <div className="card empty-state">
          <span className="icon">✓</span>
          <h3>No Pending Escalations</h3>
          <p>All dangerous agent actions have been resolved or authorized.</p>
        </div>
      ) : (
        <div className="card-list">
          {escalations.map((item) => (
            <div key={item.id} className="card escalation-card">
              <div className="escalation-header">
                <span className="badge warning">P0 Escalation</span>
                <span className="timestamp">{item.timestamp}</span>
              </div>
              <div className="escalation-details">
                <p><strong>Agent ID:</strong> <code>{item.agentId}</code></p>
                <p><strong>Attempted Command:</strong> <code>{item.command}</code></p>
                <p><strong>Risk Trigger:</strong> {item.riskReason}</p>
              </div>
              <div className="escalation-actions">
                <button
                  className="btn btn-success"
                  onClick={() => handleAction(item.id, 'ALLOW_ONCE')}
                >
                  Allow Once (Signed HMAC)
                </button>
                <button
                  className="btn btn-primary"
                  onClick={() => handleAction(item.id, 'PERMANENT_ALLOW')}
                >
                  Permanently Authorize
                </button>
                <button
                  className="btn btn-danger"
                  onClick={() => handleAction(item.id, 'DENY')}
                >
                  Deny & Block
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default HitlApprovals;
