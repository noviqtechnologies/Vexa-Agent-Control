import React from 'react';

interface ContainerNode {
  podId: string;
  environment: string;
  imageSize: string;
  status: string;
  policySync: string;
  p95Latency: string;
}

export const HarFleetTelemetry: React.FC = () => {
  const nodes: ContainerNode[] = [
    {
      podId: 'agentcontrol-har-pod-88a',
      environment: 'Kubernetes Cluster / EKS',
      imageSize: '84.2 MB (Alpine)',
      status: 'Healthy',
      policySync: 'Synced (v2.0)',
      p95Latency: '1.8 ms',
    },
    {
      podId: 'agentcontrol-har-obot-02',
      environment: 'Obot Agent Platform',
      imageSize: '91.0 MB (Distroless)',
      status: 'Healthy',
      policySync: 'Synced (v2.0)',
      p95Latency: '2.4 ms',
    },
  ];

  return (
    <div className="view-container">
      <div className="view-header">
        <h2>Hardened Agent Container Runtime (HAR) Telemetry</h2>
        <p className="subtitle">
          FR-401 / NFR-302: Monitoring pre-configured OCI container sidecars running Agent Control entrypoints.
        </p>
      </div>

      <div className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Pod / Container ID</th>
              <th>Environment</th>
              <th>OCI Image Size</th>
              <th>Status</th>
              <th>Policy Sync</th>
              <th>P95 Latency</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((node) => (
              <tr key={node.podId}>
                <td><code>{node.podId}</code></td>
                <td>{node.environment}</td>
                <td><span className="badge info">{node.imageSize}</span></td>
                <td><span className="badge success">{node.status}</span></td>
                <td>{node.policySync}</td>
                <td><strong>{node.p95Latency}</strong></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default HarFleetTelemetry;
